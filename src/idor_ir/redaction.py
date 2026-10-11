"""Enmascarado de secretos y tokens.

Los logs del reto contienen `authtoken` de usuarios reales en `http_uri` [Reto §2].
Esos tokens son credenciales de terceros: si aparecen en evidencias, UI, logs de la app
o prompts al LLM, la propia herramienta de investigación se convierte en una fuga.

Estrategia:
- `fingerprint_token`: huella SHA-256 truncada. Permite correlacionar ("el mismo token aparece
  en 3 IPs") sin revelar el valor. Es determinista, por eso sirve como IOC interno.
- `redact_text`: reemplaza patrones sensibles en texto libre antes de loguearlo o mostrarlo.
"""

from __future__ import annotations

import hashlib
import re

# Parámetros de query cuyo valor nunca debe mostrarse. Se amplía en fases posteriores si hace falta.
_SENSITIVE_QUERY_PARAMS = ("authtoken", "token", "apikey", "api_key", "access_token", "password")

_QUERY_PARAM_RE = re.compile(
    r"(?P<key>(?:" + "|".join(_SENSITIVE_QUERY_PARAMS) + r"))=(?P<value>[^&\s\"']+)",
    re.IGNORECASE,
)
# Cabeceras típicas de credenciales (VirusTotal usa x-apikey, OTX usa X-OTX-API-KEY, Anthropic x-api-key).
_HEADER_RE = re.compile(
    r"(?P<key>authorization|x-apikey|x-api-key|api-key|x-otx-api-key)(?P<sep>\s*[:=]\s*)(?P<value>[^\s,;]+(?:\s+[^\s,;]+)?)",
    re.IGNORECASE,
)

# Formatos conocidos de API keys de proveedores de IA (OpenAI/DeepSeek/Anthropic/OpenRouter `sk-`,
# Google `AIza`, Groq `gsk_`, xAI `xai-`). Red de seguridad si una clave aparece en un mensaje de error.
_API_KEY_RE = re.compile(r"\b(?:sk-[A-Za-z0-9_\-]{8,}|AIza[0-9A-Za-z_\-]{20,}|gsk_[A-Za-z0-9]{8,}|xai-[A-Za-z0-9]{8,})")

REDACTED = "***"


def fingerprint_token(token: str, length: int = 12) -> str:
    """Huella no reversible de un token, p. ej. `tok_3f9a1c0b7e2d`."""
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return f"tok_{digest[:length]}"


def mask_secret(secret: str, visible: int = 4) -> str:
    """Muestra solo los últimos `visible` caracteres: `••••1234`. Para API keys en la UI."""
    if len(secret) <= visible:
        return "•" * len(secret)
    return "•" * 4 + secret[-visible:]


def redact_text(text: str) -> str:
    """Reemplaza valores de parámetros y cabeceras sensibles por `***`."""
    text = _QUERY_PARAM_RE.sub(lambda m: f"{m.group('key')}={REDACTED}", text)
    text = _API_KEY_RE.sub(REDACTED, text)
    return _HEADER_RE.sub(lambda m: f"{m.group('key')}{m.group('sep')}{REDACTED}", text)


def token_hint(token: str) -> str:
    """Pista legible y parcial de un token para la UI/reportes: `ATUSER-ID-pruebauser` -> `ATUSER-ID-pr…er`.

    Conserva el prefijo de esquema (útil para distinguir cuentas de prueba `TEST-ID-*` de usuarios
    `ATUSER-ID-*`) y oculta el identificador. El valor completo solo se guarda en el archivo restringido
    `sensitive/token_map.json`, necesario para ejecutar la revocación.
    """
    prefix, sep, rest = token.rpartition("-")
    if not sep:
        prefix, rest = "", token
    else:
        prefix += sep
    if len(rest) <= 4:
        return prefix + "…"
    return f"{prefix}{rest[:2]}…{rest[-2:]}"
