"""VirusTotal API v3 — https://docs.virustotal.com/reference/ip-info

IP: GET /api/v3/ip_addresses/{ip} · dominio: /domains/{d} · hash: /files/{h}; cabecera `x-apikey`.
API pública: 4 peticiones/min, 500/día, sin uso comercial. Todo indicador consultado se agrega al dataset
público de VirusTotal (por eso `publishes_queries`). Errores: {"error": {"code", "message"}}.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ti_gateway.models import IndicatorType, SourceResult
from ti_gateway.providers.base import Provider
from ti_gateway.util import clean_list, clean_text

BASE = "https://www.virustotal.com/api/v3"
MALICIOUS_THRESHOLD = 3  # >= 3 motores "malicious" → malicioso; 1-2 o "suspicious" → sospechoso
PATHS = {"ip": ("ip_addresses", "ip-address"), "domain": ("domains", "domain"), "hash": ("files", "file")}


class VirusTotal(Provider):
    id = "virustotal"
    label = "VirusTotal"
    indicator_types = ("ip", "domain", "hash")
    publishes_queries = True
    terms_note = (
        "API pública: 4 consultas/min y 500/día, sin uso comercial. Lo consultado se agrega al dataset "
        "público de VirusTotal."
    )
    docs_url = "https://docs.virustotal.com/reference/public-vs-premium-api"
    default_per_minute = 4
    default_quota = 500
    quota_period = "day"

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self.secret, "accept": "application/json"}

    def fetch(self, indicator: str, indicator_type: IndicatorType) -> SourceResult:
        api, gui = PATHS[indicator_type]
        link = f"https://www.virustotal.com/gui/{gui}/{indicator}"
        response = self.request("GET", f"{BASE}/{api}/{indicator}", headers=self._headers())
        if response.status_code == 404:
            return self.result("sin datos", "No existe en VirusTotal", status="not_found", permalink=link)
        attrs: dict[str, Any] = (self.check(response) or {}).get("data", {}).get("attributes", {}) or {}
        stats = attrs.get("last_analysis_stats") or {}
        mal, sus = int(stats.get("malicious", 0) or 0), int(stats.get("suspicious", 0) or 0)
        total = sum(int(v or 0) for v in stats.values() if isinstance(v, int))
        if mal >= MALICIOUS_THRESHOLD:
            level, reasons = "malicioso", [f"{mal} motores la marcan maliciosa"]
        elif mal or sus:
            level, reasons = "sospechoso", [f"{mal} maliciosa / {sus} sospechosa"]
        else:
            level, reasons = "sin reportes", []
        last = attrs.get("last_analysis_date")
        return self.result(
            level,  # type: ignore[arg-type]
            f"{mal}/{sus} motores (de {total})",
            reasons=reasons,
            context={
                "asn": attrs.get("asn") if isinstance(attrs.get("asn"), int) else None,
                "as_name": clean_text(attrs.get("as_owner", ""), 120),
                "country": clean_text(attrs.get("country", ""), 8),
            },
            data={
                "malicious": mal,
                "suspicious": sus,
                "harmless": int(stats.get("harmless", 0) or 0),
                "undetected": int(stats.get("undetected", 0) or 0),
                "reputation": attrs.get("reputation") if isinstance(attrs.get("reputation"), int) else None,
                "network": clean_text(attrs.get("network", ""), 64),
                "tags": clean_list(attrs.get("tags")),
                "last_analysis_date": datetime.fromtimestamp(last, tz=UTC).isoformat()
                if isinstance(last, int)
                else None,
            },
            permalink=link,
        )

    def validate(self) -> str:
        self.check(self.request("GET", f"{BASE}/ip_addresses/8.8.8.8", headers=self._headers()))
        return "Clave válida (se usó 1 consulta de la cuota diaria)"
