"""Controles de seguridad de la aplicación web (OWASP Cheat Sheet Series).

- Cabeceras HTTP (HTTP Headers CS): CSP estricta sin `unsafe-inline` (todo JS/CSS en archivos propios,
  Chart.js servido localmente), anti-clickjacking, nosniff, sin Referer, sin caché en la API.
- CSRF (CSRF Prevention CS): "double submit" — cookie `irp_csrf` + cabecera `X-CSRF-Token` en todo
  POST, comparados en tiempo constante; además cookies `SameSite=Strict`.
- Autenticación opcional (`IRP_ACCESS_TOKEN`): sesión en cookie HttpOnly firmada con HMAC.
  Por defecto la app escucha solo en 127.0.0.1 (ver CLI `serve`); el token es la segunda barrera.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Awaitable, Callable

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


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        elif request.url.path.startswith("/static/") or request.url.path == "/":
            # Revalidar siempre (ETag): tras actualizar la plataforma el navegador no debe usar un app.js viejo.
            response.headers["Cache-Control"] = "no-cache"
        return response


def session_value(token: str) -> str:
    """Valor de sesión derivado del token (no se guarda el token en la cookie)."""
    return hmac.new(token.encode(), b"irp-session-v1", hashlib.sha256).hexdigest()


class AuthMiddleware(BaseHTTPMiddleware):
    """Si hay token configurado, exige la cookie de sesión válida (salvo rutas públicas)."""

    def __init__(self, app: object, token: str | None, metrics_token: str | None = None) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self.expected = session_value(token) if token else None
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
            if self.expected is None:
                return Response('{"detail":"No autenticado"}', status_code=401, media_type="application/json")
        if self.expected is None or request.url.path in PUBLIC_PATHS:
            return await call_next(request)
        cookie = request.cookies.get(SESSION_COOKIE, "")
        if hmac.compare_digest(cookie, self.expected):
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


def set_cookie(response: Response, name: str, value: str, http_only: bool) -> None:
    response.set_cookie(name, value, httponly=http_only, samesite="strict", secure=False, path="/")
