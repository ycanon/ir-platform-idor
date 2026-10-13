"""Cliente MCP del servidor `ti-gateway` (transporte stdio).

La plataforma ya no habla directamente con VirusTotal/OTX/...: lanza el gateway como subproceso, le pasa por
variables de entorno SOLO las claves de las fuentes que necesita esa operación (mínimo privilegio) y usa sus
herramientas MCP. Al terminar, el proceso se cierra y las claves desaparecen con él.

Entorno del subproceso: el SDK solo hereda variables seguras (PATH, HOME/USERPROFILE...); aquí se agregan las
`TI_*` y, si existen, las de proxy/CA corporativos para que el gateway pueda salir a Internet.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from pydantic import SecretStr

PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
              "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE")  # fmt: skip
CALL_TIMEOUT = timedelta(seconds=240)  # VirusTotal público: hasta 15 s de espera + reintentos


class GatewayError(RuntimeError):
    """Error del gateway o de la herramienta MCP (mensaje ya controlado por el servidor)."""


@dataclass
class GatewayLaunch:
    data_dir: Path
    client_name: str = "idor-ir"
    keys: dict[str, SecretStr] = field(default_factory=dict, repr=False)
    per_minute: dict[str, int] = field(default_factory=dict)
    quota: dict[str, int] = field(default_factory=dict)
    cache_ttl_hours: int = 24
    urls: dict[str, str] = field(default_factory=dict)  # fuentes autoalojadas (MISP): URL de la instancia
    ca_pems: dict[str, str] = field(default_factory=dict)  # certificado de la instancia/CA pegado en la web
    tls_insecure: set[str] = field(default_factory=set)  # fuentes internas sin verificación TLS (excepción)
    command: list[str] | None = None  # por defecto: el mismo intérprete, `-m ti_gateway`

    def params(self) -> StdioServerParameters:
        env = {k: os.environ[k] for k in PROXY_VARS if os.environ.get(k)}
        env |= {
            "TI_DATA_DIR": str(self.data_dir),
            "TI_CLIENT_NAME": self.client_name,
            "TI_CACHE_TTL_HOURS": str(self.cache_ttl_hours),
            "PYTHONUNBUFFERED": "1",
        }
        for source, key in self.keys.items():
            env[f"TI_{source.upper()}_API_KEY"] = key.get_secret_value()
        for source, value in self.per_minute.items():
            env[f"TI_{source.upper()}_PER_MINUTE"] = str(value)
        for source, value in self.quota.items():
            env[f"TI_{source.upper()}_QUOTA"] = str(value)
        for source, url in self.urls.items():
            env[f"TI_{source.upper()}_URL"] = url
        for source, pem in self.ca_pems.items():
            env[f"TI_{source.upper()}_CA_PEM"] = pem
        for source in self.tls_insecure:
            env[f"TI_{source.upper()}_TLS_VERIFY"] = "0"
        # CA interna de instancias autoalojadas (ruta a un PEM, no es secreta) definida por el administrador.
        env |= {k: v for k, v in os.environ.items() if k.startswith("TI_") and k.endswith("_CA_BUNDLE") and v}
        # Lista blanca de salida (anti-SSRF) definida por el administrador: el gateway la aplica en cada conexión.
        if os.environ.get("TI_ALLOWED_HOSTS"):
            env["TI_ALLOWED_HOSTS"] = os.environ["TI_ALLOWED_HOSTS"]
        command = self.command or [sys.executable, "-m", "ti_gateway"]
        return StdioServerParameters(command=command[0], args=command[1:], env=env)


class GatewaySession:
    """Envoltura de `ClientSession` con las herramientas del gateway y errores tipados."""

    def __init__(self, session: ClientSession) -> None:
        self._s = session

    async def _call(self, tool: str, args: dict[str, Any] | None = None) -> Any:
        result = await self._s.call_tool(tool, args or {}, read_timeout_seconds=CALL_TIMEOUT)
        if result.isError:
            text = " ".join(getattr(c, "text", "") for c in result.content)
            raise GatewayError(text.replace("Error executing tool ", "").strip()[:300])
        data = result.structuredContent
        if data is None:  # compatibilidad: algunos servidores solo devuelven texto JSON
            data = json.loads(getattr(result.content[0], "text", "null")) if result.content else None
        return data.get("result", data) if isinstance(data, dict) and set(data) == {"result"} else data

    async def list_sources(self) -> list[dict[str, Any]]:
        return list(await self._call("ti_list_sources"))

    async def lookup(
        self, indicator: str, indicator_type: str | None, sources: list[str], consent: dict[str, Any]
    ) -> dict[str, Any]:
        """`consent`: {granted, run_id, granted_by, purpose}; el gateway rechaza la consulta sin él."""
        args: dict[str, Any] = {"indicator": indicator, "sources": sources, "consent": consent}
        if indicator_type:
            args["indicator_type"] = indicator_type
        return dict(await self._call("ti_lookup", args))

    async def check_source(self, source: str) -> dict[str, Any]:
        return dict(await self._call("ti_check_source", {"source": source}))


async def _run[R](launch: GatewayLaunch, fn: Callable[[GatewaySession], Awaitable[R]]) -> R:
    try:
        async with stdio_client(launch.params()) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            return await fn(GatewaySession(session))
    except GatewayError:
        raise
    except Exception as exc:  # el gateway no arrancó o se cerró: mensaje genérico (el detalle va a stderr)
        if isinstance(exc, BaseExceptionGroup) and any(isinstance(e, GatewayError) for e in exc.exceptions):
            raise next(e for e in exc.exceptions if isinstance(e, GatewayError)) from None
        raise GatewayError(f"No se pudo usar ti-gateway ({type(exc).__name__})") from exc


def run_with_gateway[R](launch: GatewayLaunch, fn: Callable[[GatewaySession], Awaitable[R]]) -> R:
    """Ejecuta `fn` con una sesión MCP abierta. Pensado para hilos de trabajo (sin event loop propio)."""
    return asyncio.run(_run(launch, fn))
