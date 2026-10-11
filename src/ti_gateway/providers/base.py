"""Contrato común de una fuente de inteligencia de amenazas.

Agregar una fuente = una subclase de `Provider` con sus metadatos, `fetch()` y `validate()`, registrada en
`providers/__init__.py`. La web y los clientes MCP la descubren con `ti_list_sources` (no hay que tocar la UI).
"""

from __future__ import annotations

import ssl
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import UTC, datetime
from functools import partial
from typing import Any, ClassVar, Literal

import httpx
from pydantic import SecretStr

from ti_gateway.models import IndicatorType, Level, SourceResult
from ti_gateway.util import Pacer, describe_connection_error, scrub

TIMEOUT = httpx.Timeout(30.0, connect=10.0)
HttpFactory = Callable[[], httpx.Client]


def trust_context(ca_bundle: str | None = None, ca_pem: str | None = None) -> ssl.SSLContext:
    """Contexto TLS que confía en el almacén de certificados del SISTEMA (Windows/macOS/Linux) vía `truststore`.

    Así una instancia interna (MISP con certificado de la CA corporativa ya instalada en el equipo) o un proxy
    corporativo con inspección TLS funcionan sin desactivar la verificación. `ca_bundle` agrega una CA en PEM.
    """
    if ca_bundle or ca_pem:
        # Con un certificado propio se usa el contexto de OpenSSL (en Windows también carga el almacén del
        # sistema) + ese certificado: comportamiento idéntico en todos los sistemas operativos.
        ctx = ssl.create_default_context()
    else:
        try:
            import truststore

            ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        except ImportError:  # pragma: no cover - truststore es dependencia; respaldo: CAs de OpenSSL
            ctx = ssl.create_default_context()
    if ca_bundle:
        ctx.load_verify_locations(cafile=ca_bundle)
    if ca_pem:  # certificado pegado en la interfaz (instancia con certificado autofirmado o CA interna)
        ctx.load_verify_locations(cadata=ca_pem)
    return ctx


def default_http(verify: ssl.SSLContext | bool | None = None) -> httpx.Client:
    # TLS siempre verificado; sin seguir redirecciones: podrían reenviar la clave a otro host.
    # `verify` permite una CA propia (instancias autoalojadas con PKI interna), nunca desactivar la verificación.
    if verify is None:
        verify = trust_context()
    return httpx.Client(
        timeout=TIMEOUT, follow_redirects=False, headers={"User-Agent": "ti-gateway/0.1"}, verify=verify
    )


class ProviderError(RuntimeError):
    """Error de la fuente con mensaje ya limpio de secretos."""


class AuthError(ProviderError):
    pass


class QuotaExceeded(ProviderError):
    pass


class Provider(ABC):
    id: ClassVar[str]
    label: ClassVar[str]
    indicator_types: ClassVar[tuple[IndicatorType, ...]]
    key_required: ClassVar[bool] = True
    publishes_queries: ClassVar[bool] = False  # ¿lo consultado pasa a un dataset público?
    terms_note: ClassVar[str] = ""
    docs_url: ClassVar[str] = ""
    default_per_minute: ClassVar[int] = 30
    default_quota: ClassVar[int | None] = None
    quota_period: ClassVar[Literal["day", "week", "month"] | None] = None
    # Fuentes autoalojadas (MISP, OpenCTI...): necesitan la URL de la instancia además de la clave.
    needs_url: ClassVar[bool] = False
    url_placeholder: ClassVar[str] = ""

    def __init__(
        self,
        api_key: SecretStr | None = None,
        per_minute: int | None = None,
        quota_limit: int | None = None,
        enabled: bool = True,
        http_factory: HttpFactory = default_http,
        sleep: Callable[[float], None] | None = None,
        base_url: str | None = None,
        ca_bundle: str | None = None,
        ca_pem: str | None = None,
        tls_verify: bool = True,
    ) -> None:
        self._key = api_key
        self.base_url = base_url or None  # ya validada por la configuración
        # Excepción explícita del analista para una instancia INTERNA de laboratorio (validado en la configuración).
        self.tls_verify = tls_verify
        if not tls_verify and http_factory is default_http:
            http_factory = partial(default_http, verify=False)
        elif (ca_bundle or ca_pem) and http_factory is default_http:
            http_factory = partial(default_http, verify=trust_context(ca_bundle, ca_pem))
        self.enabled = enabled
        self.per_minute = per_minute or self.default_per_minute
        self._quota_override = quota_limit
        self._http_factory = http_factory
        self.pacer = Pacer(self.per_minute, sleep=sleep) if sleep else Pacer(self.per_minute)
        self.auth_failed: str | None = None  # tras un 401/403 no se insiste en este proceso

    # ---- metadatos dinámicos
    @classmethod
    def key_env(cls) -> str:
        return f"TI_{cls.id.upper()}_API_KEY"

    @classmethod
    def url_env(cls) -> str:
        return f"TI_{cls.id.upper()}_URL"

    @property
    def configured(self) -> bool:
        has_key = self._key is not None or not self.key_required
        return has_key and (self.base_url is not None or not self.needs_url)

    def missing_config(self) -> str:
        missing = [self.url_env()] if self.needs_url and not self.base_url else []
        if self.key_required and self._key is None:
            missing.append(self.key_env())
        return " y ".join(missing)

    @property
    def quota_limit(self) -> int | None:
        return self._quota_override if self._quota_override is not None else self.default_quota

    @property
    def period(self) -> str | None:
        """Periodo de la cuota (algunas fuentes lo cambian según haya clave, p. ej. GreyNoise)."""
        return self.quota_period

    @property
    def secret(self) -> str:
        return self._key.get_secret_value() if self._key else ""

    # ---- HTTP con errores limpios
    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        try:
            with self._http_factory() as http:
                return http.request(method, url, **kwargs)
        except httpx.HTTPError as exc:  # el texto se limpia: podría incluir la URL con ?key=
            reason = scrub(describe_connection_error(exc), [self.secret])
            raise ProviderError(f"{self.label}: sin conexión — {reason}") from exc

    def error_text(self, response: httpx.Response) -> str:
        detail = ""
        try:
            body = response.json()
            if isinstance(body, dict):
                err = body.get("error") or body.get("errors") or body.get("message") or body.get("query_status")
                if isinstance(err, list) and err:
                    err = err[0]
                if isinstance(err, dict):
                    detail = " ".join(str(err.get(k, "")) for k in ("code", "detail", "message") if err.get(k))
                elif err:
                    detail = str(err)
        except ValueError:
            pass
        return scrub(f"{self.label}: HTTP {response.status_code} {detail}".strip()[:220], [self.secret])

    def check(self, response: httpx.Response, ok: tuple[int, ...] = (200,)) -> Any:
        if response.status_code in (401, 403):
            raise AuthError(self.error_text(response))
        if response.status_code == 429:
            raise QuotaExceeded(self.error_text(response))
        if response.status_code not in ok:
            raise ProviderError(self.error_text(response))
        try:
            return response.json()
        except ValueError as exc:
            raise ProviderError(f"{self.label}: respuesta no JSON") from exc

    # ---- resultado
    def result(
        self,
        level: Level,
        summary: str,
        *,
        status: Literal["ok", "not_found"] = "ok",
        reasons: list[str] | None = None,
        possible_false_positive: bool = False,
        context: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        permalink: str = "",
    ) -> SourceResult:
        return SourceResult(
            source=self.id,
            status=status,
            level=level,
            summary=summary[:200],
            reasons=(reasons or [])[:6],
            possible_false_positive=possible_false_positive,
            context={k: v for k, v in (context or {}).items() if v not in (None, "", [])},
            data=data or {},
            permalink=permalink,
            fetched_at=datetime.now(UTC).isoformat(timespec="seconds"),
        )

    @abstractmethod
    def fetch(self, indicator: str, indicator_type: IndicatorType) -> SourceResult:
        """Consulta la fuente (el motor ya validó el indicador, la caché, la cuota y el ritmo)."""

    @abstractmethod
    def validate(self) -> str:
        """Comprueba la clave configurada con una llamada real. Devuelve un mensaje sin secretos."""
