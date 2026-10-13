"""Controles de seguridad de la aplicación web (OWASP Cheat Sheet Series).

- Cabeceras HTTP (HTTP Headers CS): CSP estricta sin `unsafe-inline` (todo JS/CSS en archivos propios,
  Chart.js servido localmente), anti-clickjacking, nosniff, sin Referer, sin caché en la API.
- CSRF (CSRF Prevention CS): "double submit" — cookie `irp_csrf` + cabecera `X-CSRF-Token` en todo
  POST, comparados en tiempo constante; además cookies `SameSite=Strict`.
- Autenticación y roles (Authentication / Session Management / Authorization CS):
  * `IRP_ACCESS_TOKEN` → rol **analista** (ver, analizar, ejecutar agentes, conversar).
  * `IRP_APPROVER_TOKEN` → rol **aprobador** (además: aprobar acciones, cambiar proveedores LLM/TI, autorizar la
    salida de datos a la nube). Sin token de aprobador, el titular del token de acceso es **operador único** (tiene
    ambos permisos y así queda registrado en la cadena de custodia).
  * Sin ningún token solo se permite escuchar en 127.0.0.1 (modo local de un solo usuario): `serve` se niega a
    escuchar en otra interfaz sin token (fail-closed).
  * La sesión es una cookie HttpOnly firmada con HMAC-SHA256 (clave aleatoria por proceso), con usuario, rol y
    vencimiento; `Secure` cuando la petición llega por HTTPS (directo o desde un proxy de confianza).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

CSRF_COOKIE = "irp_csrf"
CSRF_HEADER = "x-csrf-token"
SESSION_COOKIE = "irp_session"

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'"
)

# Rutas accesibles sin sesión aunque haya token configurado.
PUBLIC_PATHS = {"/login", "/api/health", "/static/app.css"}

ROLE_ANALYST = "analista"
ROLE_APPROVER = "aprobador"
ROLE_SINGLE = "operador_unico"  # sin IRP_APPROVER_TOKEN: un solo operador con ambos permisos
ROLE_LOCAL = "local"  # sin tokens: solo 127.0.0.1, un usuario
APPROVER_ROLES = frozenset({ROLE_APPROVER, ROLE_SINGLE, ROLE_LOCAL})
MIN_TOKEN_LENGTH = 16
_USER_RE = re.compile(r"^[\w .@'-]{2,60}$")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if is_https(request):
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        elif request.url.path.startswith("/static/") or request.url.path == "/":
            # Revalidar siempre (ETag): tras actualizar la plataforma el navegador no debe usar un app.js viejo.
            response.headers["Cache-Control"] = "no-cache"
        return response


@dataclass(frozen=True)
class Principal:
    user: str
    role: str

    @property
    def can_approve(self) -> bool:
        return self.role in APPROVER_ROLES

    def audit(self) -> dict[str, str]:
        return {"user": self.user, "role": self.role}


LOCAL_PRINCIPAL = Principal("local", ROLE_LOCAL)


def clean_user(value: str) -> str | None:
    """Nombre para auditoría (no es secreto): una línea, caracteres seguros."""
    value = " ".join(value.split())
    return value if _USER_RE.fullmatch(value) else None


class SessionSigner:
    """Cookie de sesión `payload.firma`: usuario, rol y vencimiento firmados con HMAC-SHA256.

    La clave es aleatoria por proceso: reiniciar la plataforma cierra todas las sesiones (no hay clave que robar
    del disco). El token nunca se guarda en la cookie."""

    def __init__(self, ttl_hours: int = 12, key: bytes | None = None) -> None:
        self.key = key or secrets.token_bytes(32)
        self.ttl = ttl_hours * 3600

    def _sign(self, payload: bytes) -> str:
        return base64.urlsafe_b64encode(hmac.new(self.key, payload, hashlib.sha256).digest()).decode().rstrip("=")

    def issue(self, principal: Principal) -> str:
        body = {"u": principal.user, "r": principal.role, "exp": int(time.time()) + self.ttl,
                "n": secrets.token_hex(8)}  # fmt: skip
        payload = base64.urlsafe_b64encode(json.dumps(body, separators=(",", ":")).encode()).decode().rstrip("=")
        return f"{payload}.{self._sign(payload.encode())}"

    def verify(self, cookie: str) -> Principal | None:
        try:
            payload, sig = cookie.split(".", 1)
            if not hmac.compare_digest(sig, self._sign(payload.encode())):
                return None
            body: dict[str, Any] = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        except (ValueError, TypeError):
            return None
        if int(body.get("exp", 0)) < time.time():
            return None
        return Principal(str(body.get("u", "")), str(body.get("r", "")))


def principal_of(request: Request) -> Principal:
    return getattr(request.state, "principal", None) or LOCAL_PRINCIPAL


def require_approver(request: Request) -> Principal:
    """Dependencia FastAPI: acciones reservadas al rol aprobador (decisiones y cambios de proveedores)."""
    principal = principal_of(request)
    if not principal.can_approve:
        raise HTTPException(status_code=403, detail="Requiere el rol aprobador")
    return principal


class AuthMiddleware(BaseHTTPMiddleware):
    """Si hay token configurado, exige una sesión firmada válida (salvo rutas públicas) y fija el principal."""

    def __init__(self, app: object, signer: SessionSigner | None, metrics_token: str | None = None) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self.signer = signer
        # Token de SOLO LECTURA para que Prometheus lea /metrics (cabecera Authorization: Bearer ...).
        self.metrics_token = metrics_token

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        is_metrics = request.url.path == "/metrics"
        if is_metrics and self.metrics_token:
            # Con IRP_METRICS_TOKEN definido, /metrics SIEMPRE exige el token (o una sesión válida), aunque la
            # app no tenga token de acceso: el contenedor publica el puerto y Prometheus llega por la red interna.
            auth = request.headers.get("authorization", "")
            if hmac.compare_digest(auth.encode(), f"Bearer {self.metrics_token}".encode()):
                return await call_next(request)
            if self.signer is None:
                return Response('{"detail":"No autenticado"}', status_code=401, media_type="application/json")
        if self.signer is None:
            request.state.principal = LOCAL_PRINCIPAL
            return await call_next(request)
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)
        principal = self.signer.verify(request.cookies.get(SESSION_COOKIE, ""))
        if principal is not None:
            request.state.principal = principal
            return await call_next(request)
        if request.url.path.startswith("/api/") or request.url.path == "/metrics":
            return Response('{"detail":"No autenticado"}', status_code=401, media_type="application/json")
        return Response(status_code=303, headers={"Location": "/login"})


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def require_csrf(request: Request) -> None:
    """Dependencia FastAPI para endpoints que cambian estado."""
    cookie = request.cookies.get(CSRF_COOKIE, "")
    header = request.headers.get(CSRF_HEADER, "")
    if not cookie or not header or not hmac.compare_digest(cookie, header):
        raise HTTPException(status_code=403, detail="Token CSRF inválido")


def is_https(request: Request) -> bool:
    """HTTPS directo o informado por un proxy de confianza.

    uvicorn solo acepta X-Forwarded-Proto de las IPs de IRP_TRUSTED_PROXIES (ver `serve`)."""
    return request.url.scheme == "https"


def set_cookie(
    response: Response, name: str, value: str, http_only: bool, secure: bool = False, max_age: int | None = None
) -> None:
    response.set_cookie(name, value, httponly=http_only, samesite="strict", secure=secure, path="/", max_age=max_age)
