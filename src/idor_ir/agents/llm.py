"""Cliente LLM con salida estructurada (Ollama) y contrato inyectable para tests.

- `OllamaLLM` usa `langchain-ollama` con `format=<JSON Schema>`: Ollama restringe la generación al
  esquema y Pydantic valida el resultado. Si falla la conexión, el tiempo límite o la validación,
  se lanza `LLMError` y el agente usa su lógica determinista (fallback) — la demo nunca se bloquea.
- `temperature=0` para respuestas reproducibles; `num_predict` acota la longitud (y el tiempo).

Lecciones de la primera prueba real (03-oct-2026, decision log del run 20261003T170418Z-e72940):
- Triage y Forensic: "1 error de esquema" → salida cortada por `num_predict` o textos más largos que
  el máximo. Solución: límites por ítem en el esquema, más presupuesto de tokens y **reparación**
  (recortar textos/listas y acotar números) antes de validar. Recortar es seguro: nunca agrega datos.
- Response: HTTP 400 inmediato de Ollama → la gramática no aceptó alguna restricción del esquema o
  el contexto excedía `num_ctx`. Solución: esquema para Ollama sin `minimum/maximum/default`,
  `num_ctx` 8192 y entrada más compacta. Los errores ahora registran el detalle técnico (sin datos).
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any, Protocol, TypeVar

from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)

# Claves que la gramática de Ollama no necesita o que algunas versiones rechazan; Pydantic las valida igual.
# `maxLength`/`minLength` se quitan para que la gramática no corte frases (punto 5).
_STRIP_KEYS = {
    "maxLength",
    "minLength",
    "pattern",
    "title",
    "description",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "default",
}
# Campos que completa el código, nunca el modelo.
_CODE_ONLY_FIELDS = {"verified_in_catalog"}

# Límites para la gramática del LLM: SOLO cantidad de ítems por lista [mejora O13, punto 5].
# Antes también se enviaba `maxLength`: Ollama cortaba la frase al llegar al tope, en mitad de una palabra
# (y de una letra con tilde: "sesi�"). Ahora la longitud se controla con la instrucción (≤ 25 palabras por
# viñeta) y, si hace falta, `repair` recorta DESPUÉS en una palabra completa.
LLM_LIMITS: dict[str, dict[str, int]] = {
    "hypotheses": {"maxItems": 4},
    "investigation_plan": {"maxItems": 4},
    "priority_targets": {"maxItems": 4},
    "reasoning": {"maxItems": 4},
    "mitre": {"maxItems": 6},
    "mitre_attack": {"maxItems": 6},
    "open_questions": {"maxItems": 2},
    "actions": {"maxItems": 8},
    "ranking": {"maxItems": 12},
    "playbook": {"maxItems": 6},
}
DEFAULT_SEED = 42  # semilla fija: dos ejecuciones con el mismo modelo y contexto dan la misma salida


def trim_words(text: str, limit: int) -> str:
    """Recorta en una palabra completa (nunca a mitad de palabra) y agrega "…"."""
    if len(text) <= limit:
        return text
    cut = text[: limit - 1]
    space = cut.rfind(" ")
    if space > limit * 0.6:
        cut = cut[:space]
    return cut.rstrip(" ,;:-") + "…"


def _tighten(name: str, prop: dict[str, Any]) -> dict[str, Any]:
    limits = LLM_LIMITS.get(name)
    if not limits:
        return prop
    prop = dict(prop)
    if "maxItems" in limits:
        prop["maxItems"] = min(prop.get("maxItems", limits["maxItems"]), limits["maxItems"])
    return prop


def _inline(model: type[BaseModel]) -> dict[str, Any]:
    raw = model.model_json_schema()
    defs = raw.pop("$defs", {})

    def resolve(node: Any) -> Any:
        if isinstance(node, dict):
            if "$ref" in node:
                return resolve(defs[node["$ref"].split("/")[-1]])
            return {k: resolve(v) for k, v in node.items()}
        if isinstance(node, list):
            return [resolve(v) for v in node]
        return node

    result: dict[str, Any] = resolve(raw)
    return result


def ollama_schema(model: type[BaseModel]) -> dict[str, Any]:
    """JSON Schema simplificado para la gramática de Ollama (sin $ref ni restricciones problemáticas)."""

    def clean(node: Any) -> Any:
        if isinstance(node, dict):
            out = {k: clean(v) for k, v in node.items() if k not in _STRIP_KEYS}
            if "properties" in out:
                out["properties"] = {
                    k: _tighten(k, v) for k, v in out["properties"].items() if k not in _CODE_ONLY_FIELDS
                }
                out["required"] = [r for r in out.get("required", []) if r not in _CODE_ONLY_FIELDS]
            return out
        if isinstance(node, list):
            return [clean(v) for v in node]
        return node

    result: dict[str, Any] = clean(_inline(model))
    return result


def repair(data: Any, schema: dict[str, Any]) -> Any:
    """Ajusta la salida a los límites del esquema: recorta textos y listas, acota números.

    Solo REDUCE o acota valores existentes; no inventa contenido. Lo que siga siendo inválido
    (campos faltantes, tipos erróneos) lo rechaza Pydantic después.
    """
    if isinstance(data, dict) and "properties" in schema:
        props = schema["properties"]
        return {k: repair(v, props[k]) if k in props else v for k, v in data.items()}
    if isinstance(data, list) and schema.get("type") == "array":
        limit = schema.get("maxItems")
        items = data[:limit] if isinstance(limit, int) else data
        return [repair(v, schema.get("items", {})) for v in items]
    if isinstance(data, str):
        limit = schema.get("maxLength")
        return trim_words(data.strip(), limit) if isinstance(limit, int) else data
    if isinstance(data, int | float) and not isinstance(data, bool):
        low, high = schema.get("minimum"), schema.get("maximum")
        if isinstance(low, int | float):
            data = max(data, low)
        if isinstance(high, int | float):
            data = min(data, high)
        return data
    return data


def _validation_summary(exc: ValidationError) -> str:
    """Ubicación y tipo de los errores (sin valores, que podrían contener datos)."""
    parts = [f"{'.'.join(str(p) for p in e['loc']) or '<raíz>'}:{e['type']}" for e in exc.errors()[:3]]
    return f"{exc.error_count()} errores ({'; '.join(parts)})"


class LLMError(RuntimeError):
    """Fallo del LLM (conexión, timeout, salida inválida). El mensaje no incluye datos sensibles."""


class LLMClient(Protocol):
    name: str

    def generate(self, system: str, user: str, schema: type[T], max_tokens: int) -> T: ...


def _guarded() -> Any:
    """Transporte con la política de salida (anti-SSRF). Import diferido: providers importa este módulo."""
    from idor_ir.agents.providers import guarded_transport

    return guarded_transport()


class OllamaLLM:
    """Cliente para un servidor Ollama (local o en la red)."""

    def __init__(
        self,
        base_url: str,
        model: str,
        timeout_s: float = 420.0,
        num_ctx: int = 8192,
        seed: int | None = DEFAULT_SEED,
        temperature: float = 0.0,
        chat_temperature: float = 0.1,
    ) -> None:
        self.seed = seed
        self.temperature = temperature
        self.chat_temperature = chat_temperature
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_s = timeout_s
        self.num_ctx = num_ctx
        self.name = f"ollama:{model}"
        self.last_latency_s: float | None = None
        self.last_stats: dict[str, Any] = {}

    def _chat(self, schema: type[BaseModel], max_tokens: int) -> Any:
        from langchain_ollama import ChatOllama  # import diferido: la CLI de análisis no lo necesita

        return ChatOllama(
            model=self.model,
            base_url=self.base_url,
            temperature=self.temperature,
            seed=self.seed,
            num_predict=max_tokens,
            num_ctx=self.num_ctx,
            format=ollama_schema(schema),
            keep_alive="30m",
            client_kwargs={"timeout": self.timeout_s},
            sync_client_kwargs={"transport": _guarded()},
        )

    def generate(self, system: str, user: str, schema: type[T], max_tokens: int) -> T:
        started = time.perf_counter()
        try:
            message = self._chat(schema, max_tokens).invoke([("system", system), ("human", user)])
        except Exception as exc:  # conexión rechazada, timeout, 400 de Ollama...
            detail = str(getattr(exc, "error", "") or exc).replace("\n", " ")[:160]
            raise LLMError(f"Ollama no disponible o rechazó la petición ({type(exc).__name__}: {detail})") from exc
        finally:
            self.last_latency_s = round(time.perf_counter() - started, 1)
        content = message.content if isinstance(message.content, str) else str(message.content)
        meta = getattr(message, "response_metadata", {}) or {}
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            reason = meta.get("done_reason", "?")
            raise LLMError(f"JSON inválido o incompleto (done_reason={reason}, {len(content)} caracteres)") from exc
        try:
            return schema.model_validate(repair(data, _inline(schema)))
        except ValidationError as exc:
            raise LLMError(f"Salida del modelo no cumple el esquema: {_validation_summary(exc)}") from exc

    def stream_chat(
        self, system: str, messages: list[dict[str, str]], max_tokens: int, on_delta: Callable[[str], None]
    ) -> str:
        """Conversación en texto libre (sin esquema), token a token. Usado por la pestaña Conversación."""
        from langchain_ollama import ChatOllama

        chat = ChatOllama(
            model=self.model,
            base_url=self.base_url,
            temperature=self.chat_temperature,
            seed=self.seed,
            num_predict=max_tokens,
            num_ctx=self.num_ctx,
            keep_alive="30m",
            client_kwargs={"timeout": self.timeout_s},
            sync_client_kwargs={"transport": _guarded()},
        )
        history = [("system", system)] + [("human" if m["role"] == "user" else "ai", m["content"]) for m in messages]
        parts: list[str] = []
        started = time.perf_counter()
        first: float | None = None
        meta: dict[str, Any] = {}
        try:
            for chunk in chat.stream(history):
                text = chunk.content if isinstance(chunk.content, str) else ""
                if text:
                    first = first if first is not None else time.perf_counter()
                    parts.append(text)
                    on_delta(text)
                info = getattr(chunk, "response_metadata", None) or {}
                if info.get("done"):
                    meta = dict(info)
        except Exception as exc:
            detail = str(getattr(exc, "error", "") or exc).replace("\n", " ")[:160]
            raise LLMError(f"Ollama no disponible o rechazó la petición ({type(exc).__name__}: {detail})") from exc
        finally:
            self.last_latency_s = round(time.perf_counter() - started, 1)
        # Tiempos que reporta Ollama (ns). prompt_eval_count = tokens del prompt EVALUADOS: si el inicio del prompt
        # coincide con la petición anterior, Ollama reutiliza su caché y este número baja (solo lo nuevo).
        ns = 1e9
        self.last_stats = {
            "ttft_s": round(first - started, 1) if first is not None else None,
            "total_s": self.last_latency_s,
            "prompt_tokens": meta.get("prompt_eval_count"),
            "prompt_s": round(meta["prompt_eval_duration"] / ns, 1) if meta.get("prompt_eval_duration") else None,
            "output_tokens": meta.get("eval_count"),
            "gen_s": round(meta["eval_duration"] / ns, 1) if meta.get("eval_duration") else None,
            "load_s": round(meta["load_duration"] / ns, 1) if meta.get("load_duration") else None,
            "done_reason": meta.get("done_reason"),
            "prompt_tokens_are_processed": True,
        }
        return "".join(parts)

    def check_formats(self, schemas: list[type[BaseModel]]) -> dict[str, str]:
        """Verifica rápido que Ollama acepta cada esquema como gramática (genera 1 token)."""
        results = {}
        for schema in schemas:
            try:
                self._chat(schema, 1).invoke([("human", "ok")])
                results[schema.__name__] = "aceptado"
            except Exception as exc:
                detail = str(getattr(exc, "error", "") or exc).replace("\n", " ")[:160]
                results[schema.__name__] = f"RECHAZADO ({type(exc).__name__}: {detail})"
        return results

    def health(self) -> bool:
        """Comprueba conectividad con /api/tags (usado por la UI y la CLI)."""
        import httpx

        try:
            with httpx.Client(transport=_guarded(), follow_redirects=False, timeout=5.0) as http:
                return http.get(f"{self.base_url}/api/tags").status_code == 200
        except (httpx.HTTPError, ValueError):  # ValueError: destino bloqueado por la política de salida
            return False
