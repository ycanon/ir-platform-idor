"""Validación de indicadores, saneamiento de textos de terceros y limpieza de secretos en errores."""

from __future__ import annotations

import ipaddress
import re
import time
from collections.abc import Callable
from typing import Any

from ti_gateway.models import IndicatorType

_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.[a-z]{2,63}$")
_HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$")
_URL_RE = re.compile(r"^https?://[^\s/$.?#][^\s]{1,2000}$", re.IGNORECASE)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f‪-‮⁦-⁩]")  # control y bidi (ocultan texto)
# Formatos de claves conocidos + parámetros de query con credenciales (Shodan usa ?key=, IPinfo ?token=).
_SECRET_RES = [
    re.compile(r"(?i)\b(key|token|apikey|api_key|auth-key)=([^&\s\"']+)"),
    re.compile(r"\b(?:sk-[A-Za-z0-9_\-]{8,}|AIza[0-9A-Za-z_\-]{20,})"),
]


class BaseURLError(ValueError):
    """URL base de una fuente autoalojada (p. ej. MISP) inválida o insegura."""


def validate_base_url(raw: str) -> str:
    """URL base de una instancia autoalojada (interna o externa).

    - `https://` hacia cualquier servidor: instancia interna (misp.example.internal) o externa (comunidad/proveedor).
    - `http://` solo hacia la red interna: IP privada/loopback o un nombre que resuelve SOLO a IPs privadas. Por
      Internet la clave viajaría en claro.

    Sin credenciales embebidas, query ni fragmento (la clave va en cabecera; una URL con `user:pass@` o `?key=`
    acabaría en logs). Devuelve la URL sin `/` final.
    """
    from urllib.parse import urlsplit

    value = raw.strip()
    if not value or len(value) > 300 or _CONTROL_RE.search(value) or " " in value:
        raise BaseURLError("URL vacía, demasiado larga o con caracteres no permitidos")
    parts = urlsplit(value)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise BaseURLError("La URL debe ser https://servidor[:puerto][/ruta]")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise BaseURLError("La URL no puede incluir usuario/contraseña, parámetros (?) ni fragmento (#)")
    if parts.scheme == "http" and not _is_internal_host(parts.hostname):
        raise BaseURLError(
            "http:// solo se permite hacia la red interna (IP privada o nombre que resuelve a IP privada); "
            "use https:// para instancias externas"
        )
    try:
        _ = parts.port  # valida el puerto
    except ValueError as exc:
        raise BaseURLError("Puerto inválido") from exc
    return value.rstrip("/")


def is_internal_url(url: str) -> bool:
    """¿La URL apunta a la red interna (IP privada/loopback o nombre que resuelve SOLO a IPs privadas)?"""
    from urllib.parse import urlsplit

    host = urlsplit(url).hostname
    return bool(host) and _is_internal_host(host)  # type: ignore[arg-type]


def _is_internal_host(host: str) -> bool:
    import socket

    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False  # no resuelve: no se puede comprobar que sea interna
    addresses = {ipaddress.ip_address(str(i[4][0]).split("%")[0]) for i in infos}
    return bool(addresses) and all(a.is_private or a.is_loopback for a in addresses)


_PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----")


def validate_ca_pem(raw: str) -> str:
    """Certificado(s) PEM de una instancia autoalojada o de su CA interna (información pública, no secreta).

    Se acepta solo el bloque CERTIFICATE (nunca claves privadas) y se comprueba que OpenSSL lo carga.
    """
    import ssl

    text = raw.strip()
    if len(text) > 30_000 or "PRIVATE KEY" in text:  # Windows limita cada variable de entorno a 32 767 caracteres
        raise BaseURLError("Pegue solo el certificado (BEGIN CERTIFICATE), nunca una clave privada")
    blocks = _PEM_RE.findall(text)
    if not blocks:
        raise BaseURLError(
            "No se encontró un certificado PEM (-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----)"
        )
    pem = "\n".join(b.strip() for b in blocks) + "\n"
    try:
        ssl.create_default_context(cadata=pem)
    except (ssl.SSLError, ValueError) as exc:
        raise BaseURLError("El certificado PEM no es válido") from exc
    return pem


def pem_fingerprint(pem: str) -> str:
    """SHA-256 del primer certificado (para que el analista lo compare con el del servidor)."""
    import hashlib
    import ssl

    first = _PEM_RE.search(pem)
    if not first:
        return ""
    der = ssl.PEM_cert_to_DER_cert(first.group(0))
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, 16, 2)) + "…"


def describe_connection_error(exc: BaseException) -> str:
    """Motivo concreto de un fallo de conexión, sin secretos (las claves van en cabeceras; ?key= se limpia)."""
    text = f"{type(exc).__name__}: {exc}"
    low = text.lower()
    if "certificate" in low or "cert_" in low or "ssl" in low and "verify" in low:
        if "mismatch" in low or "doesn't match" in low or "does not match" in low or "cn_no_match" in low:
            reason = (
                "el certificado TLS no corresponde a esa dirección: use en la URL el nombre que figura en el "
                "certificado o regenere el certificado incluyendo esa IP/nombre"
            )
        elif "self-signed" in low or "self signed" in low:
            reason = (
                "certificado TLS autofirmado: pegue el certificado de la instancia (PEM) en el campo "
                "'Certificado' de esta fuente"
            )
        else:
            reason = (
                "certificado TLS emitido por una CA que este equipo no reconoce: pegue el certificado de la "
                "instancia o de su CA (PEM) en el campo 'Certificado' de esta fuente"
            )
    elif "wrong_version_number" in low or "wrong version number" in low or "record layer" in low:
        reason = "el servidor no responde HTTPS en ese puerto (¿usa http:// u otro puerto?)"
    elif "timeout" in low or "timed out" in low:
        reason = "tiempo de espera agotado (¿IP o puerto incorrectos, firewall o equipo apagado?)"
    elif "refused" in low or "10061" in low:
        reason = "conexión rechazada: nada escucha en ese puerto (¿servicio detenido, o http en vez de https?)"
    elif "proxy" in low:
        reason = "el proxy rechazó la conexión: agregue la dirección de la instancia a NO_PROXY"
    elif "getaddrinfo" in low or "name or service" in low or "11001" in low or "nodename" in low:
        reason = "no se pudo resolver el nombre del servidor"
    elif "unreachable" in low or "10051" in low or "10065" in low:
        reason = "red inalcanzable desde este equipo"
    else:
        reason = type(exc).__name__
    detail = scrub(str(exc).replace("\n", " "), [])[:140]
    return f"{reason}" + (f" — detalle: {detail}" if detail and detail not in reason else "")


class IndicatorError(ValueError):
    """Indicador inválido o no permitido (p. ej. IP privada)."""


def detect_type(indicator: str) -> IndicatorType:
    value = indicator.strip()
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if _URL_RE.match(value):
        return "url"
    if _HASH_RE.match(value.lower()):
        return "hash"
    if _DOMAIN_RE.match(value.lower()):
        return "domain"
    raise IndicatorError("No se reconoce el tipo de indicador (IP, dominio, hash MD5/SHA-1/SHA-256 o URL)")


def normalize_indicator(indicator: str, indicator_type: IndicatorType | None = None) -> tuple[str, IndicatorType]:
    value = indicator.strip()
    if not value or len(value) > 2048:
        raise IndicatorError("Indicador vacío o demasiado largo")
    detected = detect_type(value)
    if indicator_type and indicator_type != detected:
        raise IndicatorError(f"El indicador parece de tipo '{detected}', no '{indicator_type}'")
    if detected == "ip":
        ip = ipaddress.ip_address(value)
        if not ip.is_global:
            # Una IP privada/reservada no tiene reputación externa y revelaría direccionamiento interno.
            raise IndicatorError("IP privada o reservada: no se envía a fuentes externas")
        return str(ip), "ip"
    if detected in ("domain", "hash"):
        return value.lower(), detected
    return value, detected


def clean_text(value: Any, limit: int = 160) -> str:
    """Texto de terceros: sin caracteres de control/bidi y acotado. Sigue siendo DATO, no instrucción."""
    text = _CONTROL_RE.sub("", str(value)).strip()
    return text[: limit - 1] + "…" if len(text) > limit else text


def clean_list(values: Any, limit: int = 10, item_limit: int = 60) -> list[str]:
    if not isinstance(values, list):
        return []
    return [clean_text(v, item_limit) for v in values[:limit] if v not in (None, "")]


def scrub(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***")
    for pattern in _SECRET_RES:
        text = pattern.sub(lambda m: f"{m.group(1)}=***" if m.lastindex else "***", text)
    return text


class Pacer:
    """Espaciado mínimo entre peticiones a una fuente (límite por minuto) dentro de este proceso."""

    def __init__(
        self, per_minute: int, sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.interval = 60.0 / max(per_minute, 1)
        self._sleep, self._clock = sleep, clock
        self._last: float | None = None

    def wait(self) -> None:
        if self._last is not None:
            remaining = self.interval - (self._clock() - self._last)
            if remaining > 0:
                self._sleep(remaining)
        self._last = self._clock()
