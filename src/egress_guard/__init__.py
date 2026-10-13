"""Control de salida de red (anti-SSRF) para las URLs que la plataforma consulta: LLM y fuentes de TI.

Problema (OWASP SSRF Prevention Cheat Sheet): la interfaz permite indicar la URL de un servidor (Ollama, una API
compatible con OpenAI, MISP). Sin control, un usuario de la UI podría apuntarla a la red interna o a los metadatos
de la nube (169.254.169.254) y usar la plataforma como proxy. Validar solo el texto de la URL no basta: un nombre
puede resolver a una IP permitida al validar y a otra al conectar (DNS rebinding).

Defensa en capas:
1. Lista blanca de hosts (configuración del administrador, por entorno; la UI no puede ampliarla):
   - `fixed_hosts`: los hosts que el código define (APIs públicas de proveedores). Deben resolver a IPs PÚBLICAS.
   - `allowed_hosts`: hosts propios autorizados (Ollama en el equipo o la LAN, MISP interno). Pueden ser privados.
   Entrada exacta (`ollama`, `10.0.0.5`) o sufijo con punto inicial (`.corp.example`).
2. Resolución DNS en CADA petición y verificación de TODAS las IPs: nunca link-local, metadatos de nube,
   multicast, reservadas ni 0.0.0.0.
3. La conexión se hace a la IP ya verificada (se fija la IP; el nombre se conserva en `Host` y en SNI/TLS):
   no hay segunda resolución que un atacante pueda cambiar.
4. Sin redirecciones (los clientes usan `follow_redirects=False`).
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

DEFAULT_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1", "host.docker.internal", "ollama")
# Metadatos de nube conocidos (AWS/GCP/Azure/OpenStack, AWS IPv6, ECS, Alibaba). Además se bloquea todo link-local.
METADATA_IPS = frozenset(
    ipaddress.ip_address(a) for a in ("169.254.169.254", "fd00:ec2::254", "169.254.170.2", "100.100.100.200")
)

Address = ipaddress.IPv4Address | ipaddress.IPv6Address


class EgressError(ValueError):
    """Destino de red no autorizado (mensaje sin secretos)."""


def parse_hosts(raw: str | Iterable[str] | None) -> tuple[str, ...]:
    items = raw.split(",") if isinstance(raw, str) else list(raw or [])
    return tuple(h.strip().strip("[]").lower().rstrip(".") for h in items if h and h.strip())


def _always_blocked(ip: Address) -> bool:
    return (
        ip in METADATA_IPS
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
        or (isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None and _always_blocked(ip.ipv4_mapped))
    )


@dataclass(frozen=True)
class EgressPolicy:
    allowed_hosts: tuple[str, ...] = DEFAULT_LOCAL_HOSTS
    fixed_hosts: frozenset[str] = field(default_factory=frozenset)
    env_var: str = "IRP_LLM_ALLOWED_HOSTS"  # solo para los mensajes de error

    def with_hosts(self, *hosts: str | None) -> EgressPolicy:
        extra = tuple(h for h in parse_hosts([h for h in hosts if h]) if h not in self.allowed_hosts)
        return EgressPolicy(self.allowed_hosts + extra, self.fixed_hosts, self.env_var)

    def _in_allowlist(self, host: str) -> bool:
        host = host.strip("[]").lower().rstrip(".")
        return any(host == h or (h.startswith(".") and host.endswith(h)) for h in self.allowed_hosts)

    def host_allowed(self, host: str) -> bool:
        return self._in_allowlist(host) or host.strip("[]").lower().rstrip(".") in self.fixed_hosts

    def check_url(self, url: str) -> None:
        """Validación al CONFIGURAR una URL (UI/entorno): el host debe estar en la lista blanca."""
        host = urlsplit(url).hostname or ""
        if not self.host_allowed(host):
            raise EgressError(
                f"Host no autorizado para conexiones salientes. El administrador debe agregarlo a {self.env_var}."
            )
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            return
        if _always_blocked(ip):
            raise EgressError("Dirección no permitida (link-local, metadatos de nube, multicast o reservada).")

    def resolve(self, host: str, port: int) -> list[Address]:
        """Resuelve y verifica TODAS las IPs del host (al CONECTAR). Devuelve las IPs permitidas."""
        if not self.host_allowed(host):
            raise EgressError(f"Host no autorizado para conexiones salientes ({self.env_var}).")
        bare = host.strip("[]")
        try:
            addresses: list[Address] = [ipaddress.ip_address(bare)]
        except ValueError:
            try:
                infos = socket.getaddrinfo(bare, port, type=socket.SOCK_STREAM)
            except OSError as exc:
                raise EgressError("No se pudo resolver el host de destino.") from exc
            addresses = list(dict.fromkeys(ipaddress.ip_address(str(i[4][0]).split("%")[0]) for i in infos))
        if not addresses:
            raise EgressError("El host de destino no tiene direcciones.")
        public_only = not self._in_allowlist(host)  # APIs públicas fijas: nunca hacia la red interna
        for ip in addresses:
            if _always_blocked(ip):
                raise EgressError("El destino resuelve a una dirección prohibida (link-local/metadatos/reservada).")
            if public_only and not ip.is_global:
                raise EgressError("Un proveedor público resolvió a una IP interna: conexión bloqueada (rebinding).")
        return addresses


class GuardedTransport(httpx.BaseTransport):
    """Transporte httpx que verifica el destino y conecta a la IP ya verificada (anti DNS rebinding)."""

    def __init__(self, policy: EgressPolicy, verify: Any = True) -> None:
        self.policy = policy
        self._direct = httpx.HTTPTransport(verify=verify)
        self._proxied: dict[str, httpx.HTTPTransport] = {}
        self._verify = verify

    def _transport_for(self, scheme: str, host: str) -> httpx.HTTPTransport:
        proxies = urllib.request.getproxies()
        proxy = proxies.get(scheme) or proxies.get("all")
        if not proxy or urllib.request.proxy_bypass(host):
            return self._direct
        if proxy not in self._proxied:
            self._proxied[proxy] = httpx.HTTPTransport(verify=self._verify, proxy=proxy)
        return self._proxied[proxy]

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        host = url.host
        port = url.port or (443 if url.scheme == "https" else 80)
        ip = self.policy.resolve(host, port)[0]
        pinned = url.copy_with(host=str(ip))
        extensions = dict(request.extensions)
        if url.scheme == "https":
            extensions["sni_hostname"] = host  # TLS valida el certificado contra el NOMBRE, no la IP
        guarded = httpx.Request(
            request.method, pinned, headers=request.headers, stream=request.stream, extensions=extensions
        )
        return self._transport_for(url.scheme, host).handle_request(guarded)

    def close(self) -> None:
        self._direct.close()
        for t in self._proxied.values():
            t.close()
