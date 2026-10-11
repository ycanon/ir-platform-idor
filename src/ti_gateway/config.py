"""Configuración del gateway: SOLO desde variables de entorno (el cliente MCP las define al lanzarlo).

Por fuente (ID en mayúsculas: VIRUSTOTAL, OTX, ABUSEIPDB, GREYNOISE, IPINFO, SHODAN, ABUSECH, MISP):
  TI_<ID>_API_KEY      clave (nunca se registra ni se devuelve)
  TI_<ID>_PER_MINUTE   ritmo máximo (p. ej. plan premium)
  TI_<ID>_QUOTA        cupo del periodo de la fuente (día/semana)
  TI_<ID>_URL          URL de la instancia, solo fuentes autoalojadas (MISP). https, o http hacia IP privada
  TI_<ID>_CA_BUNDLE    ruta a un PEM con la CA interna de esa instancia (opcional; nunca se desactiva TLS)
  TI_<ID>_CA_PEM       el certificado PEM en sí (lo pasa la web cuando se pega en Configuración)
  TI_<ID>_TLS_VERIFY   "0" = NO verificar el certificado (solo instancias en la red interna; inseguro, auditado)
Generales:
  TI_DATA_DIR          directorio de estado compartido (caché, cuota, auditoría). Defecto: ~/.ti-gateway
  TI_CACHE_TTL_HOURS   vigencia de la caché (defecto 24; 0 = sin caché)
  TI_ENABLED_SOURCES   lista separada por comas (defecto: todas)
  TI_CLIENT_NAME       nombre del cliente para la auditoría (p. ej. idor-ir-web)
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import SecretStr

from ti_gateway.providers import PROVIDERS, Provider
from ti_gateway.providers.base import HttpFactory, default_http
from ti_gateway.util import BaseURLError, is_internal_url, validate_base_url, validate_ca_pem


def _int(env: Mapping[str, str], name: str, low: int, high: int) -> int | None:
    raw = env.get(name, "").strip()
    if not raw:
        return None
    value = int(raw)  # un valor no numérico debe fallar al arrancar, no en silencio
    if not low <= value <= high:
        raise ValueError(f"{name} fuera de rango [{low}, {high}]")
    return value


@dataclass
class GatewayConfig:
    data_dir: Path
    cache_ttl_hours: int = 24
    client_name: str = "desconocido"
    enabled: set[str] = field(default_factory=lambda: set(PROVIDERS))
    keys: dict[str, SecretStr] = field(default_factory=dict, repr=False)
    per_minute: dict[str, int] = field(default_factory=dict)
    quota: dict[str, int] = field(default_factory=dict)
    urls: dict[str, str] = field(default_factory=dict)
    ca_bundles: dict[str, str] = field(default_factory=dict)
    ca_pems: dict[str, str] = field(default_factory=dict)
    tls_insecure: set[str] = field(default_factory=set)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> GatewayConfig:
        env = os.environ if env is None else env
        keys, per_minute, quota, urls, cas, pems = {}, {}, {}, {}, {}, {}
        insecure: set[str] = set()
        for pid in PROVIDERS:
            prefix = f"TI_{pid.upper()}_"
            if env.get(prefix + "API_KEY", "").strip():
                keys[pid] = SecretStr(env[prefix + "API_KEY"].strip())
            if (pm := _int(env, prefix + "PER_MINUTE", 1, 10_000)) is not None:
                per_minute[pid] = pm
            if (q := _int(env, prefix + "QUOTA", 0, 10_000_000)) is not None:
                quota[pid] = q
            if PROVIDERS[pid].needs_url and env.get(prefix + "URL", "").strip():
                urls[pid] = validate_base_url(env[prefix + "URL"])  # URL inválida → falla al arrancar
            if (ca := env.get(prefix + "CA_BUNDLE", "").strip()) and PROVIDERS[pid].needs_url:
                if not Path(ca).is_file():
                    raise ValueError(f"{prefix}CA_BUNDLE no apunta a un archivo")
                cas[pid] = ca
            if (pem := env.get(prefix + "CA_PEM", "").strip()) and PROVIDERS[pid].needs_url:
                pems[pid] = validate_ca_pem(pem)
            if env.get(prefix + "TLS_VERIFY", "").strip().lower() in {"0", "false", "no"} and PROVIDERS[pid].needs_url:
                if pid not in urls or not is_internal_url(urls[pid]):
                    raise BaseURLError(f"{prefix}TLS_VERIFY=0 solo se permite con una URL de la red interna")
                insecure.add(pid)
        enabled_raw = env.get("TI_ENABLED_SOURCES", "").strip()
        enabled = (
            {s.strip() for s in enabled_raw.split(",") if s.strip()} & set(PROVIDERS) if enabled_raw else set(PROVIDERS)
        )
        return cls(
            data_dir=Path(env.get("TI_DATA_DIR") or Path.home() / ".ti-gateway"),
            cache_ttl_hours=24 if (ttl := _int(env, "TI_CACHE_TTL_HOURS", 0, 720)) is None else ttl,
            client_name="".join(c for c in env.get("TI_CLIENT_NAME", "desconocido") if c.isalnum() or c in "-_.")[:40],
            enabled=enabled,
            keys=keys,
            per_minute=per_minute,
            quota=quota,
            urls=urls,
            ca_bundles=cas,
            ca_pems=pems,
            tls_insecure=insecure,
        )

    def build_providers(self, http_factory: HttpFactory = default_http, sleep: object = None) -> dict[str, Provider]:
        return {
            pid: cls(
                api_key=self.keys.get(pid),
                per_minute=self.per_minute.get(pid),
                quota_limit=self.quota.get(pid),
                enabled=pid in self.enabled,
                http_factory=http_factory,
                sleep=sleep,  # type: ignore[arg-type]
                base_url=self.urls.get(pid),
                ca_bundle=self.ca_bundles.get(pid),
                ca_pem=self.ca_pems.get(pid),
                tls_verify=pid not in self.tls_insecure,
            )
            for pid, cls in PROVIDERS.items()
        }
