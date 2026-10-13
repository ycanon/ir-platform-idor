"""Proveedores de LLM para los agentes: Ollama (local/LAN) y APIs en la nube.

Mejora opcional [SPECS O9]: además de Ollama (local o en la red), el analista puede elegir una API
comercial si no quiere procesar el LLM localmente.

Diseño:
- Sin SDKs de terceros: `httpx` directo. Menos dependencias y control total de TLS, timeouts,
  redirecciones y mensajes de error (para que la API key nunca termine en un log o en la UI).
- Dos familias de API cubren el mercado: **compatible con OpenAI** (`/chat/completions`, `/models`:
  OpenAI, Gemini, DeepSeek, Mistral, Groq, xAI, OpenRouter y servidores propios como LM Studio/vLLM)
  y **Anthropic Messages** (Claude). Ollama conserva su cliente (`llm.OllamaLLM`).
- Salida estructurada: OpenAI y Gemini → `response_format: json_schema`; el resto → `json_object`;
  Anthropic → *tool use* forzado con el esquema como `input_schema`. Siempre se valida con Pydantic,
  se repara (solo recortes) y, si falla, el agente usa su lógica determinista (igual que con Ollama).
- Si el proveedor rechaza un parámetro opcional (HTTP 400), se reintenta UNA vez sin `temperature` ni
  `response_format` (los modelos de razonamiento rechazan `temperature`; no todos aceptan JSON mode).

Seguridad (OWASP Secrets Management, Logging, Error Handling CS):
- La API key llega como `SecretStr`, vive solo en memoria del proceso y solo sale en la cabecera
  de autenticación hacia la URL fija del proveedor (HTTPS, verificación TLS, sin seguir redirecciones).
- Los errores del proveedor se resumen (código HTTP + tipo + mensaje corto) y se limpian de la clave.
- URLs editables (Ollama, compatible personalizado): solo http/https, sin credenciales embebidas ni
  query; `http` solo hacia hosts locales/privados (con API key nunca se envía en claro a Internet).
"""

from __future__ import annotations

import ipaddress
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, TypeVar
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, Field, SecretStr, ValidationError

from idor_ir.agents.llm import LLMError, OllamaLLM, _inline, _validation_summary, ollama_schema, repair
from idor_ir.redaction import redact_text

T = TypeVar("T", bound=BaseModel)
Kind = Literal["ollama", "openai", "anthropic"]

CONNECT_TIMEOUT_S = 10.0
READ_TIMEOUT_S = 240.0
# Presupuesto de salida para la nube: los modelos de razonamiento gastan tokens "pensando" antes de
# responder. La longitud real la acotan los límites del esquema (LLM_LIMITS), no este tope.
CLOUD_MIN_TOKENS = 4096
MAX_MODELS = 300
ANTHROPIC_VERSION = "2023-06-01"
_NON_CHAT = re.compile(r"embed|tts|whisper|dall-e|moderation|transcribe|realtime|image|audio|rerank", re.I)


@dataclass(frozen=True)
class ProviderSpec:
    id: str
    label: str
    kind: Kind
    base_url: str | None  # None = la escribe el usuario
    needs_key: bool
    cloud: bool  # True = los datos salen de la red local hacia un tercero
    json_mode: Literal["json_schema", "json_object", "tool"] = "json_object"
    limit_param: Literal["max_tokens", "max_completion_tokens"] = "max_tokens"
    send_temperature: bool = True
    default_url: str = ""
    help: str = ""


PROVIDERS: dict[str, ProviderSpec] = {
    p.id: p
    for p in (
        ProviderSpec(
            "ollama",
            "Ollama (local / LAN)",
            "ollama",
            None,
            needs_key=False,
            cloud=False,
            default_url="http://localhost:11434",
            help="Servidor Ollama propio. Modelos desde /api/tags.",
        ),
        ProviderSpec(
            "openai_compatible",
            "Compatible con OpenAI (URL propia)",
            "openai",
            None,
            needs_key=False,
            cloud=False,
            default_url="http://localhost:1234/v1",
            help="LM Studio, vLLM, LocalAI u otro endpoint /v1 compatible. La API key es opcional.",
        ),
        ProviderSpec(
            "anthropic",
            "Anthropic Claude",
            "anthropic",
            "https://api.anthropic.com/v1",
            needs_key=True,
            cloud=True,
            json_mode="tool",
            help="Clave en console.anthropic.com.",
        ),
        ProviderSpec(
            "openai",
            "OpenAI",
            "openai",
            "https://api.openai.com/v1",
            needs_key=True,
            cloud=True,
            json_mode="json_schema",
            limit_param="max_completion_tokens",
            send_temperature=False,
            help="Clave en platform.openai.com.",
        ),
        ProviderSpec(
            "gemini",
            "Google Gemini",
            "openai",
            "https://generativelanguage.googleapis.com/v1beta/openai",
            needs_key=True,
            cloud=True,
            json_mode="json_schema",
            help="Clave en Google AI Studio.",
        ),
        ProviderSpec(
            "deepseek",
            "DeepSeek",
            "openai",
            "https://api.deepseek.com",
            needs_key=True,
            cloud=True,
            help="Clave en platform.deepseek.com.",
        ),
        ProviderSpec(
            "mistral",
            "Mistral AI",
            "openai",
            "https://api.mistral.ai/v1",
            needs_key=True,
            cloud=True,
            help="Clave en console.mistral.ai.",
        ),
        ProviderSpec(
            "groq",
            "Groq",
            "openai",
            "https://api.groq.com/openai/v1",
            needs_key=True,
            cloud=True,
            help="Clave en console.groq.com.",
        ),
        ProviderSpec(
            "xai",
            "xAI Grok",
            "openai",
            "https://api.x.ai/v1",
            needs_key=True,
            cloud=True,
            help="Clave en console.x.ai.",
        ),
        ProviderSpec(
            "openrouter",
            "OpenRouter (multi-modelo)",
            "openai",
            "https://openrouter.ai/api/v1",
            needs_key=True,
            cloud=True,
            help="Una clave para modelos de varios proveedores. Clave en openrouter.ai.",
        ),
    )
}


# --------------------------------------------------------------------------- validación de entradas
_KEY_RE = re.compile(r"^[\x21-\x7e]{8,512}$")  # ASCII imprimible sin espacios (evita inyección de cabeceras)


def validate_api_key(key: str) -> str:
    key = key.strip()
    if not _KEY_RE.fullmatch(key):
        raise ValueError("La API key tiene un formato inválido (8-512 caracteres imprimibles, sin espacios)")
    return key


def is_local_host(host: str) -> bool:
    """localhost, nombres de una sola etiqueta (LAN) o IPs privadas/loopback/link-local."""
    host = host.strip("[]").lower()
    if host == "localhost" or host.endswith(".localhost") or "." not in host and ":" not in host:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host.endswith((".local", ".lan", ".internal"))
    return ip.is_private or ip.is_loopback or ip.is_link_local


# --------------------------------------------------------------------------- control de salida (anti-SSRF)
_EGRESS: Any = None


def configure_egress(settings: Any) -> Any:
    """Fija la política de salida de los clientes LLM (llamado al crear la app web y en la CLI)."""
    from egress_guard import DEFAULT_LOCAL_HOSTS, EgressPolicy, parse_hosts

    global _EGRESS
    fixed = frozenset(urlsplit(s.base_url).hostname or "" for s in PROVIDERS.values() if s.base_url) - {""}
    _EGRESS = EgressPolicy(
        allowed_hosts=DEFAULT_LOCAL_HOSTS + parse_hosts(getattr(settings, "llm_allowed_hosts", "")),
        fixed_hosts=fixed,
        env_var="IRP_LLM_ALLOWED_HOSTS",
    ).with_hosts(urlsplit(str(settings.ollama_base_url)).hostname)
    return _EGRESS


def egress_policy() -> Any:
    if _EGRESS is None:
        from idor_ir.config import get_settings

        return configure_egress(get_settings())
    return _EGRESS


def guarded_transport() -> httpx.BaseTransport:
    from egress_guard import GuardedTransport

    return GuardedTransport(egress_policy())


def validate_base_url(url: str) -> str:
    """URL editable por el usuario: http(s), con host, sin credenciales, query ni fragmento."""
    url = url.strip()
    if len(url) > 300:
        raise ValueError("URL demasiado larga")
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("La URL debe empezar por http:// o https:// e incluir el host")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("La URL no puede incluir credenciales, parámetros (?) ni fragmentos (#)")
    try:
        _ = parts.port
    except ValueError as exc:
        raise ValueError("Puerto inválido") from exc
    if parts.scheme == "http" and not is_local_host(parts.hostname):
        raise ValueError("Use https:// para hosts fuera de la red local (http solo para localhost/IP privada)")
    egress_policy().check_url(url)  # EgressError es ValueError: host fuera de la lista blanca del administrador
    return url.rstrip("/")


def sends_off_lan(spec: ProviderSpec, base_url: str) -> bool:
    """¿El contexto del incidente sale de la red local? Determina si se exige consentimiento."""
    if spec.cloud:
        return True
    host = urlsplit(base_url).hostname or ""
    return not is_local_host(host)


# --------------------------------------------------------------------------- utilidades HTTP
def _client(transport: httpx.BaseTransport | None) -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(READ_TIMEOUT_S, connect=CONNECT_TIMEOUT_S),
        follow_redirects=False,  # una redirección podría reenviar la API key a otro host
        transport=transport or guarded_transport(),  # anti-SSRF: lista blanca + IP verificada y fijada
    )


def scrub(text: str, secret: str | None) -> str:
    """Elimina la clave (completa o casi) y patrones de credenciales de un texto antes de mostrarlo."""
    if secret:
        text = text.replace(secret, "***")
        if len(secret) > 12:
            text = text.replace(secret[:12], "***")
    return redact_text(text)


def _error_detail(response: httpx.Response, secret: str | None) -> str:
    try:
        body = response.json()
    except ValueError:
        body = None
    detail = ""
    if isinstance(body, dict):
        err = body.get("error", body)
        if isinstance(err, dict):
            kind = err.get("type") or err.get("code") or err.get("status") or ""
            detail = f"{kind}: {err.get('message', '')}".strip(": ")
        elif isinstance(err, str):
            detail = err
    return scrub(f"HTTP {response.status_code} {detail}"[:220], secret)


def _parse_json_text(content: str) -> Any:
    """JSON del modelo; tolera bloques ```json y texto alrededor (proveedores sin JSON mode)."""
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            return json.loads(text[start : end + 1])
        raise


def _schema_instruction(schema: type[BaseModel]) -> str:
    return (
        "\n\nFORMATO DE SALIDA: responde ÚNICAMENTE con un objeto JSON válido (sin texto adicional ni "
        "bloques de código) que cumpla este JSON Schema; respeta maxLength y maxItems:\n"
        + json.dumps(ollama_schema(schema), ensure_ascii=False, separators=(",", ":"))
    )


def _validate[M: BaseModel](schema: type[M], data: Any) -> M:
    try:
        return schema.model_validate(repair(data, _inline(schema)))
    except ValidationError as exc:
        raise LLMError(f"Salida del modelo no cumple el esquema: {_validation_summary(exc)}") from exc


# --------------------------------------------------------------------------- clientes
class _CloudBase:
    def __init__(
        self,
        spec: ProviderSpec,
        base_url: str,
        model: str,
        api_key: SecretStr | None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.spec = spec
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._key = api_key
        self._transport = transport
        self.name = f"{spec.id}:{model}"
        self.last_latency_s: float | None = None
        self.last_stats: dict[str, Any] = {}

    @property
    def _secret(self) -> str | None:
        return self._key.get_secret_value() if self._key else None

    def _headers(self) -> dict[str, str]:
        raise NotImplementedError

    def _post(self, path: str, build: Callable[[bool], dict[str, Any]]) -> dict[str, Any]:
        """POST con un reintento 'mínimo' (sin parámetros opcionales) si el proveedor responde 400."""
        started = time.perf_counter()
        label = self.spec.label
        try:
            with _client(self._transport) as http:
                response = http.post(f"{self.base_url}{path}", json=build(False), headers=self._headers())
                if response.status_code == 400:
                    response = http.post(f"{self.base_url}{path}", json=build(True), headers=self._headers())
        except httpx.HTTPError as exc:
            raise LLMError(f"{label} no disponible ({type(exc).__name__})") from exc
        finally:
            self.last_latency_s = round(time.perf_counter() - started, 1)
        if response.status_code != 200:
            raise LLMError(f"{label} rechazó la petición ({_error_detail(response, self._secret)})")
        try:
            data: dict[str, Any] = response.json()
        except ValueError as exc:
            raise LLMError(f"{label} devolvió una respuesta que no es JSON") from exc
        return data

    def _stream(
        self,
        path: str,
        build: Callable[[bool], dict[str, Any]],
        extract: Callable[[dict[str, Any]], str | None],
        on_delta: Callable[[str], None],
        usage: Callable[[dict[str, Any], dict[str, Any]], None] | None = None,
    ) -> str:
        """POST con `stream: true` (Server-Sent Events). Un reintento 'mínimo' si el proveedor responde 400."""
        started = time.perf_counter()
        label, parts = self.spec.label, []
        first: float | None = None
        stats: dict[str, Any] = {}
        try:
            with _client(self._transport) as http:
                for minimal in (False, True):
                    with http.stream(
                        "POST", f"{self.base_url}{path}", json=build(minimal), headers=self._headers()
                    ) as r:
                        if r.status_code == 400 and not minimal:
                            r.read()
                            continue
                        if r.status_code != 200:
                            r.read()
                            raise LLMError(f"{label} rechazó la petición ({_error_detail(r, self._secret)})")
                        for line in r.iter_lines():
                            if not line.startswith("data:"):
                                continue
                            payload = line[5:].strip()
                            if payload == "[DONE]":
                                break
                            try:
                                event = json.loads(payload)
                            except ValueError:
                                continue
                            if event.get("type") == "error" or "error" in event and "choices" not in event:
                                raise LLMError(f"{label} interrumpió la respuesta")
                            if usage is not None:
                                usage(event, stats)
                            delta = extract(event)
                            if delta:
                                first = first if first is not None else time.perf_counter()
                                parts.append(delta)
                                on_delta(delta)
                    break
        except httpx.HTTPError as exc:
            raise LLMError(f"{label} no disponible ({type(exc).__name__})") from exc
        finally:
            self.last_latency_s = round(time.perf_counter() - started, 1)
            self.last_stats = {
                "ttft_s": round(first - started, 1) if first is not None else None,
                "total_s": self.last_latency_s,
                **stats,
            }
        return "".join(parts)

    def list_models(self) -> list[str]:
        try:
            with _client(self._transport) as http:
                response = http.get(f"{self.base_url}/models", headers=self._headers(), params=self._list_params())
        except httpx.HTTPError as exc:
            raise LLMError(f"{self.spec.label} no disponible ({type(exc).__name__})") from exc
        if response.status_code != 200:
            raise LLMError(f"No se pudo listar modelos ({_error_detail(response, self._secret)})")
        try:
            items = response.json().get("data", [])
        except (ValueError, AttributeError) as exc:
            raise LLMError("Respuesta inesperada al listar modelos") from exc
        ids = {str(m["id"])[:120] for m in items if isinstance(m, dict) and m.get("id")}
        return sorted(i for i in ids if not _NON_CHAT.search(i))[:MAX_MODELS]

    def _list_params(self) -> dict[str, str]:
        return {}

    def health(self) -> bool:
        """Conectividad + clave válida, con una llamada gratuita (`GET /models`)."""
        try:
            self.list_models()
        except LLMError:
            return False
        return True


class OpenAICompatibleLLM(_CloudBase):
    """`/chat/completions` (OpenAI, Gemini, DeepSeek, Mistral, Groq, xAI, OpenRouter, LM Studio, vLLM...)."""

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._secret}"} if self._secret else {}

    def generate(self, system: str, user: str, schema: type[T], max_tokens: int) -> T:
        budget = max(CLOUD_MIN_TOKENS, max_tokens * 4) if self.spec.cloud else max_tokens * 2

        def build(minimal: bool) -> dict[str, Any]:
            body: dict[str, Any] = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system + _schema_instruction(schema)},
                    {"role": "user", "content": user},
                ],
                self.spec.limit_param: budget,
            }
            if minimal:
                return body
            if self.spec.send_temperature:
                body["temperature"] = 0
            if self.spec.json_mode == "json_schema":
                body["response_format"] = {
                    "type": "json_schema",
                    "json_schema": {"name": schema.__name__, "schema": ollama_schema(schema), "strict": False},
                }
            else:
                body["response_format"] = {"type": "json_object"}
            return body

        data = self._post("/chat/completions", build)
        try:
            choice = data["choices"][0]
            content = choice["message"].get("content") or ""
        except (KeyError, IndexError, TypeError, AttributeError) as exc:
            raise LLMError("Respuesta sin 'choices' (formato inesperado)") from exc
        if not content.strip():
            reason = choice.get("finish_reason", "?")
            raise LLMError(f"Respuesta vacía (finish_reason={reason}; ¿presupuesto de tokens agotado?)")
        try:
            parsed = _parse_json_text(content)
        except json.JSONDecodeError as exc:
            reason = choice.get("finish_reason", "?")
            raise LLMError(f"JSON inválido (finish_reason={reason}, {len(content)} caracteres)") from exc
        return _validate(schema, parsed)

    def stream_chat(
        self,
        system: str,
        messages: list[dict[str, str]],
        max_tokens: int,
        on_delta: Callable[[str], None],
    ) -> str:
        budget = max(CLOUD_MIN_TOKENS, max_tokens * 4) if self.spec.cloud else max_tokens * 2

        def build(minimal: bool) -> dict[str, Any]:
            body: dict[str, Any] = {
                "model": self.model,
                "messages": [{"role": "system", "content": system}, *messages],
                "stream": True,
                self.spec.limit_param: budget,
            }
            if not minimal:
                body["stream_options"] = {"include_usage": True}  # tokens al final (no todos lo aceptan)
                if self.spec.send_temperature:
                    body["temperature"] = 0.2
            return body

        return self._stream("/chat/completions", build, _openai_delta, on_delta, _openai_usage)


def _openai_usage(event: dict[str, Any], stats: dict[str, Any]) -> None:
    choices = event.get("choices") or []
    if choices and isinstance(choices[0], dict) and choices[0].get("finish_reason"):
        stats["done_reason"] = choices[0]["finish_reason"]  # "length" = cortada por el tope
    usage = event.get("usage")
    if isinstance(usage, dict):
        stats["prompt_tokens"] = usage.get("prompt_tokens")
        stats["output_tokens"] = usage.get("completion_tokens")
        details = usage.get("prompt_tokens_details") or {}
        if isinstance(details, dict) and details.get("cached_tokens") is not None:
            stats["cached_tokens"] = details["cached_tokens"]


def _openai_delta(event: dict[str, Any]) -> str | None:
    try:
        delta = event["choices"][0].get("delta") or {}
    except (KeyError, IndexError, TypeError, AttributeError):
        return None
    content = delta.get("content")
    return content if isinstance(content, str) else None


class AnthropicLLM(_CloudBase):
    """Anthropic Messages API: el esquema va como herramienta y se fuerza su uso (`tool_choice`)."""

    TOOL = "registrar_resultado"

    def _headers(self) -> dict[str, str]:
        return {"x-api-key": self._secret or "", "anthropic-version": ANTHROPIC_VERSION}

    def _list_params(self) -> dict[str, str]:
        return {"limit": "1000"}

    def generate(self, system: str, user: str, schema: type[T], max_tokens: int) -> T:
        def build(minimal: bool) -> dict[str, Any]:
            body: dict[str, Any] = {
                "model": self.model,
                "max_tokens": max(CLOUD_MIN_TOKENS, max_tokens * 4),
                "system": system,
                "messages": [{"role": "user", "content": user}],
                "tools": [
                    {
                        "name": self.TOOL,
                        "description": "Entrega el resultado estructurado del agente. Respeta maxLength/maxItems.",
                        "input_schema": ollama_schema(schema),
                    }
                ],
                "tool_choice": {"type": "tool", "name": self.TOOL},
            }
            if not minimal:
                body["temperature"] = 0
            return body

        data = self._post("/messages", build)
        blocks = data.get("content") if isinstance(data, dict) else None
        tool_input = next(
            (b.get("input") for b in blocks or [] if isinstance(b, dict) and b.get("type") == "tool_use"), None
        )
        if not isinstance(tool_input, dict):
            raise LLMError(f"Claude no devolvió el resultado estructurado (stop_reason={data.get('stop_reason')})")
        return _validate(schema, tool_input)

    def stream_chat(
        self, system: str, messages: list[dict[str, str]], max_tokens: int, on_delta: Callable[[str], None]
    ) -> str:
        def build(minimal: bool) -> dict[str, Any]:
            body: dict[str, Any] = {
                "model": self.model,
                "max_tokens": max(CLOUD_MIN_TOKENS, max_tokens * 4),
                "system": system,
                "messages": messages,
                "stream": True,
            }
            if not minimal:
                body["temperature"] = 0.2
            return body

        def extract(event: dict[str, Any]) -> str | None:
            delta = event.get("delta") or {}
            if event.get("type") == "content_block_delta" and delta.get("type") == "text_delta":
                text = delta.get("text")
                return text if isinstance(text, str) else None
            return None

        def usage(event: dict[str, Any], stats: dict[str, Any]) -> None:
            if event.get("type") == "message_start":
                u = (event.get("message") or {}).get("usage") or {}
                stats["prompt_tokens"] = u.get("input_tokens")
                if u.get("cache_read_input_tokens") is not None:
                    stats["cached_tokens"] = u["cache_read_input_tokens"]
            elif event.get("type") == "message_delta":
                stats["output_tokens"] = (event.get("usage") or {}).get("output_tokens")
                reason = (event.get("delta") or {}).get("stop_reason")
                if reason:
                    stats["done_reason"] = "length" if reason == "max_tokens" else reason

        return self._stream("/messages", build, extract, on_delta, usage)


# --------------------------------------------------------------------------- configuración y fábrica
class LLMConfig(BaseModel):
    """Configuración en memoria de un proveedor. La clave nunca se serializa en claro."""

    provider: str
    base_url: str
    model: str = Field(default="", max_length=120)
    api_key: SecretStr | None = None

    @property
    def spec(self) -> ProviderSpec:
        return PROVIDERS[self.provider]

    def off_lan(self) -> bool:
        return sends_off_lan(self.spec, self.base_url)


class Ping(BaseModel):
    """Esquema mínimo para la prueba de extremo a extremo (clave + modelo + salida estructurada)."""

    status: Literal["ok"]


def build_client(
    cfg: LLMConfig, transport: httpx.BaseTransport | None = None
) -> OllamaLLM | OpenAICompatibleLLM | AnthropicLLM:
    spec = cfg.spec
    if not cfg.model:
        raise LLMError("Seleccione un modelo")
    if spec.needs_key and not cfg.api_key:
        raise LLMError(f"Configure la API key de {spec.label}")
    if spec.kind == "ollama":
        return OllamaLLM(cfg.base_url, cfg.model)
    cls = AnthropicLLM if spec.kind == "anthropic" else OpenAICompatibleLLM
    return cls(spec, cfg.base_url, cfg.model, cfg.api_key, transport)


def list_models(cfg: LLMConfig, transport: httpx.BaseTransport | None = None) -> list[str]:
    spec = cfg.spec
    if spec.needs_key and not cfg.api_key:
        raise LLMError(f"Configure la API key de {spec.label}")
    if spec.kind == "ollama":
        try:
            with _client(transport) as http:
                response = http.get(f"{cfg.base_url}/api/tags", timeout=10.0)
        except httpx.HTTPError as exc:
            raise LLMError(f"Ollama no disponible en {cfg.base_url} ({type(exc).__name__})") from exc
        if response.status_code != 200:
            raise LLMError(f"Ollama respondió HTTP {response.status_code}")
        try:
            names = {str(m["name"])[:120] for m in response.json().get("models", []) if m.get("name")}
        except (ValueError, AttributeError, TypeError) as exc:
            raise LLMError("Respuesta inesperada de /api/tags") from exc
        return sorted(names)
    cls = AnthropicLLM if spec.kind == "anthropic" else OpenAICompatibleLLM
    return cls(spec, cfg.base_url, cfg.model or "-", cfg.api_key, transport).list_models()
