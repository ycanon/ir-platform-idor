"""Configuración en memoria de las fuentes de inteligencia y lanzamiento del servidor MCP `ti-gateway`.

- El CATÁLOGO de fuentes lo define el gateway (`ti_list_sources`): agregar una fuente en ti-gateway la hace
  aparecer en la pestaña Configuración sin tocar la web.
- Las CLAVES las ingresa el analista en la web (solo memoria; también se aceptan `TI_<ID>_API_KEY` /
  `IRP_VT_API_KEY` / `IRP_OTX_API_KEY` del entorno para CLI/Docker). Nunca se devuelven al navegador.
- Cada operación lanza el gateway con SOLO las claves que necesita (mínimo privilegio).
"""

from __future__ import annotations

import os
import re
import threading
from typing import Any

from pydantic import SecretStr

from idor_ir.agents.providers import validate_api_key
from idor_ir.config import Settings
from idor_ir.enrichment.gateway_client import GatewayLaunch, GatewaySession, run_with_gateway
from idor_ir.redaction import mask_secret
from ti_gateway.util import is_internal_url, pem_fingerprint, validate_base_url, validate_ca_pem

SOURCE_ID_RE = re.compile(r"^[a-z0-9]{2,30}$")
ENV_KEY_RE = re.compile(r"^TI_([A-Z0-9]{2,30})_API_KEY$")
ENV_URL_RE = re.compile(r"^TI_([A-Z0-9]{2,30})_URL$")


class TIRuntime:
    def __init__(self, settings: Settings) -> None:
        self._lock = threading.Lock()
        self._settings = settings
        self._keys: dict[str, SecretStr] = {}
        self._origin: dict[str, str] = {}
        for name, value in os.environ.items():  # claves de entorno (CLI/Docker), genéricas por fuente
            if (m := ENV_KEY_RE.match(name)) and value.strip():
                self._keys[m.group(1).lower()], self._origin[m.group(1).lower()] = SecretStr(value.strip()), "entorno"
        for source, key in (("virustotal", settings.vt_api_key), ("otx", settings.otx_api_key)):  # compatibilidad 5b
            if key is not None:
                self._keys[source], self._origin[source] = key, "entorno"
        self._per_minute: dict[str, int] = {"virustotal": settings.vt_requests_per_minute}
        self._quota: dict[str, int] = {"virustotal": settings.vt_daily_limit}
        self._catalog: list[dict[str, Any]] = []
        # URL de instancias autoalojadas (MISP). No es secreta, pero se valida igual que en el gateway.
        self._urls: dict[str, str] = {}
        self._ca_pems: dict[str, str] = {}  # certificado de la instancia o de su CA (público; solo memoria)
        # Excepción explícita: no verificar TLS (solo instancias internas). Nunca por defecto; solo memoria.
        self._tls_insecure: set[str] = set()
        for name, value in os.environ.items():
            if (m := ENV_URL_RE.match(name)) and value.strip():
                try:
                    self._urls[m.group(1).lower()] = validate_base_url(value)
                except ValueError:
                    pass  # el gateway la rechazará igualmente; no se interrumpe el arranque de la web

    # ------------------------------------------------------------------ lanzamiento
    def launch(self, sources: list[str] | None = None, client: str = "idor-ir-web") -> GatewayLaunch:
        """Parámetros del subproceso con las claves de `sources` (`None` = todas, solo para el catálogo, que no
        contacta servicios externos pero necesita saber qué fuentes tienen clave para informar sus cupos)."""
        with self._lock:
            keys = dict(self._keys) if sources is None else {s: self._keys[s] for s in sources if s in self._keys}
            urls = dict(self._urls) if sources is None else {s: self._urls[s] for s in sources if s in self._urls}
            pems = (
                dict(self._ca_pems) if sources is None else {s: self._ca_pems[s] for s in sources if s in self._ca_pems}
            )
            insecure = {s for s in self._tls_insecure if sources is None or s in sources}
            return GatewayLaunch(
                data_dir=self._settings.output_dir / "ti_gateway",
                client_name=client,
                keys=keys,
                per_minute=dict(self._per_minute),
                quota=dict(self._quota),
                cache_ttl_hours=self._settings.ti_cache_ttl_hours,
                urls=urls,
                ca_pems=pems,
                tls_insecure=insecure,
                command=self._settings.ti_gateway_command,
            )

    def refresh_catalog(self) -> list[dict[str, Any]]:
        async def fetch(gw: GatewaySession) -> list[dict[str, Any]]:
            return await gw.list_sources()

        catalog = run_with_gateway(self.launch(None), fetch)
        with self._lock:
            self._catalog = catalog
        return catalog

    def known_sources(self) -> set[str]:
        with self._lock:
            return {s["id"] for s in self._catalog}

    def configured(self, source: str) -> bool:
        with self._lock:
            entry = next((s for s in self._catalog if s["id"] == source), None)
            has_key = source in self._keys or bool(entry and not entry["key_required"])
            needs_url = bool(entry and entry.get("needs_url"))
            return has_key and (source in self._urls or not needs_url)

    # ------------------------------------------------------------------ cambios desde la UI
    def update(
        self,
        *,
        keys: dict[str, str],
        clear: list[str],
        per_minute: dict[str, int],
        quota: dict[str, int],
        urls: dict[str, str] | None = None,
        ca_pems: dict[str, str] | None = None,
        tls_insecure: dict[str, bool] | None = None,
    ) -> None:
        urls, ca_pems, tls_insecure = urls or {}, ca_pems or {}, tls_insecure or {}
        known = self.known_sources()
        for source in [*keys, *clear, *per_minute, *quota, *urls, *ca_pems, *tls_insecure]:
            if not SOURCE_ID_RE.fullmatch(source) or (known and source not in known):
                raise ValueError(f"Fuente desconocida: {source[:30]}")
        validated = {s: SecretStr(validate_api_key(k)) for s, k in keys.items() if k}  # valida todo antes de cambiar
        # "" = olvidar la URL. Mensajes de error propios (no repiten la URL recibida).
        new_urls = {s: validate_base_url(u) if u.strip() else "" for s, u in urls.items()}
        new_pems = {s: validate_ca_pem(p) if p.strip() else "" for s, p in ca_pems.items()}  # "" = quitarlo
        with self._lock:
            final_urls = {**self._urls, **{s: u for s, u in new_urls.items() if u}}
            final_urls = {s: u for s, u in final_urls.items() if new_urls.get(s, u)}
        for source, on in tls_insecure.items():
            url = final_urls.get(source)
            if on and not (url and is_internal_url(url)):
                raise ValueError(
                    "Omitir la verificación TLS solo se permite con una URL de la red interna "
                    "(IP privada o nombre que resuelve a IP privada)"
                )
        with self._lock:
            for source in clear:
                self._keys.pop(source, None)
                self._origin.pop(source, None)
            for source, key in validated.items():
                self._keys[source], self._origin[source] = key, "ui"
            for source, url in new_urls.items():
                if url:
                    self._urls[source] = url
                else:
                    self._urls.pop(source, None)
            for source, on in tls_insecure.items():
                if on:
                    self._tls_insecure.add(source)
                else:
                    self._tls_insecure.discard(source)
            # Si la URL cambia a una externa (o se borra), la excepción se desactiva sola.
            self._tls_insecure = {s for s in self._tls_insecure if self._urls.get(s) and is_internal_url(self._urls[s])}
            for source, pem in new_pems.items():
                if pem:
                    self._ca_pems[source] = pem
                else:
                    self._ca_pems.pop(source, None)
            self._per_minute.update(per_minute)
            self._quota.update(quota)

    def public(self) -> dict[str, Any]:
        """Catálogo del gateway + estado de las claves (configurada, origen, últimos 4). Nunca la clave."""
        with self._lock:
            sources = []
            for entry in self._catalog:
                sid = entry["id"]
                value = self._keys[sid].get_secret_value() if sid in self._keys else ""
                sources.append(
                    {
                        **{
                            k: entry[k]
                            for k in (
                                "id",
                                "label",
                                "indicator_types",
                                "key_required",
                                "publishes_queries",
                                "terms_note",
                                "docs_url",
                                "per_minute",
                                "quota_limit",
                                "quota_period",
                                "quota_used",
                            )
                        },
                        "key_configured": bool(value),
                        "key_hint": (mask_secret(value) if len(value) >= 16 else "••••") if value else None,
                        "origin": self._origin.get(sid),
                        "needs_url": bool(entry.get("needs_url")),
                        "url_placeholder": entry.get("url_placeholder", ""),
                        "base_url": self._urls.get(sid),
                        "ca_fingerprint": pem_fingerprint(self._ca_pems[sid]) if sid in self._ca_pems else None,
                        "tls_verify": sid not in self._tls_insecure,
                        "usable": (bool(value) or not entry["key_required"])
                        and (sid in self._urls or not entry.get("needs_url")),
                    }
                )
            return {"sources": sources}
