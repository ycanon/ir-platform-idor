"""Logging estructurado (JSON) con redacción de secretos.

Decisiones (OWASP Logging Cheat Sheet):
- Formato JSON, una línea por evento: fácil de filtrar y de ingerir en un SIEM/observabilidad.
- Filtro de redacción aplicado a TODOS los registros: aunque un desarrollador loguee un URI con
  `authtoken`, el valor no llega al archivo/consola.
- Se neutralizan saltos de línea (prevención de log injection: un user agent malicioso con `\n`
  no puede falsificar líneas de log).
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from idor_ir.redaction import redact_text

# Atributos estándar de LogRecord que no queremos repetir como campos "extra".
_STD_ATTRS = set(vars(logging.makeLogRecord({})).keys()) | {"message", "asctime"}


class RedactingFilter(logging.Filter):
    """Redacta secretos en el mensaje y en los campos extra de cada registro."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_text(str(record.getMessage()))
        record.args = None  # el mensaje ya quedó formateado y redactado
        for key, value in list(vars(record).items()):
            if key not in _STD_ATTRS and isinstance(value, str):
                setattr(record, key, redact_text(value))
        return True


class JsonFormatter(logging.Formatter):
    """Serializa cada registro como un objeto JSON en una sola línea."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Campos estructurados pasados con `extra={...}`.
        for key, value in vars(record).items():
            if key not in _STD_ATTRS:
                payload[key] = value
        if record.exc_info:
            # El tipo de excepción sí se registra; el traceback completo solo en DEBUG.
            payload["error_type"] = record.exc_info[0].__name__ if record.exc_info[0] else None
            if record.levelno <= logging.DEBUG:
                payload["traceback"] = redact_text(self.formatException(record.exc_info))
        # json.dumps escapa \n y \r, lo que impide inyectar líneas falsas.
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(level: str = "INFO") -> None:
    """Configura el logger raíz una sola vez."""
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
