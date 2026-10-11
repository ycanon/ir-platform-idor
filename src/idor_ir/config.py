"""Configuración centralizada de la aplicación.

Decisión de seguridad (OWASP Secrets Management / Configuration):
- Ningún valor sensible se escribe en el código: todo llega por variables de entorno o `.env`.
- `.env` está excluido de Git; `.env.example` documenta las variables sin valores secretos.
- Cuando se agreguen API keys (fases posteriores) se tiparán como `SecretStr`, que evita
  que aparezcan en `repr()`, logs o trazas por accidente.
"""

from __future__ import annotations

from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, HttpUrl, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from idor_ir.profile import IncidentProfile

# Formato real de `timestamp` en three_months.csv, validado el 03-oct-2026 sobre el archivo completo:
# 92 fechas distintas, campo2 en [1, 31] (día) y campo3 en [10, 12] (mes) -> AAAA-DD-MMTHH:MM.
# La autodetección de Polars asumía AAAA-MM-DD: dejaba sin parsear 2.7 M filas (día > 12) y
# fechaba MAL el resto (día y mes intercambiados). Por eso el formato es explícito por defecto.
DEFAULT_TIMESTAMP_FORMAT = "%Y-%d-%mT%H:%M"


class Settings(BaseSettings):
    """Parámetros de ejecución. Prefijo de variables de entorno: `IRP_`."""

    model_config = SettingsConfigDict(
        env_prefix="IRP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # ignora variables desconocidas en lugar de fallar
    )

    data_dir: Path = Path("data")
    output_dir: Path = Path("output")

    # Formato del CSV validado con el archivo real [SPECS P1, P13].
    csv_separator: str = Field(default=",", min_length=1, max_length=1)
    # None = autodetección de Polars (solo con IRP_TIMESTAMP_FORMAT=auto; no recomendado).
    timestamp_format: str | None = DEFAULT_TIMESTAMP_FORMAT

    # Perfil del incidente [profile.py]. "auto" (por defecto): se DEDUCE del dataset en cada análisis
    # (ingestion/autoprofile.py); los valores de abajo solo se usan si no se detecta nada. "fixed": se usan siempre.
    profile_mode: Literal["auto", "fixed"] = "auto"
    # Campos del perfil fijados explícitamente para UNA ejecución (web/CLI); se aplican sobre lo detectado.
    profile_overrides: dict[str, str] = Field(default_factory=dict)
    # Valores por defecto / respaldo (los del reto [Reto §2]: GET /invoices/search?invoice_id&site_id&authtoken)
    target_endpoint: str = Field(default="/invoices/search", pattern=r"^/[A-Za-z0-9_\-/.]*$")
    object_param: str = Field(default="invoice_id", pattern=r"^[A-Za-z0-9_.\-]{1,40}$")
    scope_param: str = Field(default="site_id", pattern=r"^[A-Za-z0-9_.\-]{0,40}$")  # vacío = sin ámbito
    token_param: str = Field(default="authtoken", pattern=r"^[A-Za-z0-9_.\-]{1,40}$")
    object_label: str = Field(default="factura", max_length=30)
    object_label_plural: str = Field(default="facturas", max_length=30)
    scope_label: str = Field(default="sitio", max_length=30)

    ollama_base_url: HttpUrl = HttpUrl("http://localhost:11434")
    ollama_model: str = Field(default="qwen3:4b-instruct-2507-q4_K_M", max_length=100)
    # Conversación con los agentes: proveedor y modelo PROPIOS, iguales o distintos a los de los agentes.
    # Vacío = el mismo de los agentes. Ej.: agentes con qwen3:8b local y chat con qwen3:4b, o agentes en Ollama
    # y chat con una API en la nube (requiere su clave y autorización por pregunta).
    chat_provider: str = Field(default="", pattern=r"^[a-z0-9_-]{0,40}$")
    chat_model: str = Field(default="", max_length=120)
    ollama_chat_model: str = Field(default="", max_length=100)  # nombre anterior (v0.12.0) de chat_model

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # --- Web ---
    # Límite de carga de archivos por la web (MB). El dataset del reto pesa ~1.1 GB.
    max_upload_mb: int = Field(default=2048, ge=1, le=10240)
    # Token de acceso opcional a la UI/API. Si se define, se exige inicio de sesión (cookie HttpOnly).
    # La app escucha solo en 127.0.0.1 por defecto; el token es una segunda barrera si se expone en red.
    access_token: SecretStr | None = None
    # Token de solo lectura para que Prometheus lea /metrics cuando hay IRP_ACCESS_TOKEN (perfil observabilidad).
    metrics_token: SecretStr | None = None

    # --- Inteligencia de amenazas (opcional) ---
    # Lo normal es ingresarlas en la pestaña Configuración (solo memoria). Las variables de entorno existen
    # para la CLI/Docker; si se usan, el .env queda fuera de Git y con permisos restringidos.
    vt_api_key: SecretStr | None = None
    otx_api_key: SecretStr | None = None
    vt_requests_per_minute: int = Field(default=4, ge=1, le=1000)  # API pública: 4/min
    vt_daily_limit: int = Field(default=500, ge=1, le=1_000_000)  # API pública: 500/día
    ti_cache_ttl_hours: int = Field(default=24, ge=0, le=720)
    # Comando para lanzar el servidor MCP ti-gateway (JSON). Por defecto: este intérprete con `-m ti_gateway`.
    # Útil si el gateway vive en otro entorno o contenedor. Es configuración de administrador (solo entorno).
    ti_gateway_command: list[str] | None = None

    # Fecha de detección para el TTD: es un dato DEL INCIDENTE, no de la plataforma. Se indica por ejecución
    # (web: pestaña Dataset; CLI: --detection-date). Este valor es solo un predeterminado opcional (vacío = sin TTD).
    detection_date: datetime | None = None

    @field_validator("access_token", "metrics_token", "vt_api_key", "otx_api_key", "detection_date", mode="before")
    @classmethod
    def _blank_token_is_none(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator("timestamp_format", mode="before")
    @classmethod
    def _normalize_timestamp_format(cls, value: object) -> object:
        """Vacío -> formato validado por defecto; `auto` -> autodetección explícita."""
        if isinstance(value, str):
            if not value.strip():
                return DEFAULT_TIMESTAMP_FORMAT
            if value.strip().lower() == "auto":
                return None
        return value

    def profile(self) -> IncidentProfile:
        return IncidentProfile(
            endpoint=self.target_endpoint,
            object_param=self.object_param,
            scope_param=self.scope_param,
            token_param=self.token_param,
            object_label=self.object_label,
            object_label_plural=self.object_label_plural,
            scope_label=self.scope_label,
        )

    def for_run(self, overrides: dict[str, Any] | None = None) -> Settings:
        """Copia de la configuración con el perfil del incidente y la fecha de detección de UNA ejecución.

        Valida todo lo recibido (CLI/web) antes de usarlo: el perfil con `IncidentProfile` (patrones estrictos,
        ValueError si algo no cumple) y la fecha con ISO 8601. Claves no permitidas se ignoran. Valores vacíos
        conservan el valor configurado, salvo `scope_param` y `detection_date`, donde vacío significa "sin".
        """
        allowed = {"detection_date", *RUN_PROFILE_FIELDS}
        update: dict[str, Any] = {}
        for key, value in (overrides or {}).items():
            if key not in allowed or value is None:
                continue
            text = str(value).strip()
            if key == "detection_date":
                update[key] = _parse_detection_date(text)
            elif text or key == "scope_param":
                update[key] = text
        explicit = {k: v for k, v in update.items() if k in RUN_PROFILE_FIELDS}
        if explicit:
            update["profile_overrides"] = {**self.profile_overrides, **explicit}
        candidate = self.model_copy(update=update)
        candidate.profile()  # valida el perfil resultante
        return candidate


RUN_PROFILE_FIELDS = (
    "target_endpoint",
    "object_param",
    "scope_param",
    "token_param",
    "object_label",
    "object_label_plural",
    "scope_label",
)


def _parse_detection_date(text: str) -> datetime | None:
    if not text:
        return None
    if len(text) > 40:
        raise ValueError("Fecha de detección inválida")
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("Fecha de detección inválida (use AAAA-MM-DD o AAAA-MM-DDTHH:MM)") from exc


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Devuelve una única instancia de configuración (se lee una vez por proceso)."""
    return Settings()
