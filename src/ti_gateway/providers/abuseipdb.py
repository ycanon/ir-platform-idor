"""AbuseIPDB API v2 — https://docs.abuseipdb.com/

GET https://api.abuseipdb.com/api/v2/check?ipAddress=..&maxAgeInDays=90, cabeceras `Key` y `Accept`.
Plan gratuito: 1 000 consultas `check`/día. Errores: {"errors": [{"detail", "status"}]}.
"""

from __future__ import annotations

from typing import Any

from ti_gateway.models import IndicatorType, SourceResult
from ti_gateway.providers.base import Provider
from ti_gateway.util import clean_list, clean_text

URL = "https://api.abuseipdb.com/api/v2/check"
MALICIOUS_SCORE, SUSPICIOUS_SCORE = 75, 25  # umbrales [DEC] sobre abuseConfidenceScore (0-100)


class AbuseIPDB(Provider):
    id = "abuseipdb"
    label = "AbuseIPDB"
    indicator_types = ("ip",)
    terms_note = "Plan gratuito: 1.000 consultas/día. Reportes comunitarios de los últimos 90 días."
    docs_url = "https://docs.abuseipdb.com/"
    default_per_minute = 60
    default_quota = 1000
    quota_period = "day"

    def _get(self, ip: str) -> Any:
        headers = {"Key": self.secret, "Accept": "application/json"}
        return self.check(self.request("GET", URL, headers=headers, params={"ipAddress": ip, "maxAgeInDays": "90"}))

    def fetch(self, indicator: str, indicator_type: IndicatorType) -> SourceResult:
        d: dict[str, Any] = (self._get(indicator) or {}).get("data", {}) or {}
        score = int(d.get("abuseConfidenceScore", 0) or 0)
        reports = int(d.get("totalReports", 0) or 0)
        users = int(d.get("numDistinctUsers", 0) or 0)
        whitelisted = bool(d.get("isWhitelisted"))
        reasons = [f"Confianza de abuso {score}% · {reports} reportes de {users} usuarios"] if reports else []
        if whitelisted:
            level = "sin reportes"
            reasons.append("En la lista blanca de AbuseIPDB")
        elif score >= MALICIOUS_SCORE:
            level = "malicioso"
        elif score >= SUSPICIOUS_SCORE:
            level = "sospechoso"
        else:
            level = "sin reportes"
        if d.get("isTor"):
            reasons.append("Nodo de salida Tor")
        return self.result(
            level,  # type: ignore[arg-type]
            f"Confianza de abuso {score}% · {reports} reportes",
            reasons=reasons,
            possible_false_positive=whitelisted,
            context={
                "as_name": clean_text(d.get("isp", ""), 120),
                "usage_type": clean_text(d.get("usageType", ""), 60),
                "country": clean_text(d.get("countryCode", ""), 8),
                "tor": bool(d.get("isTor")) or None,
            },
            data={
                "abuse_confidence_score": score,
                "total_reports": reports,
                "distinct_users": users,
                "last_reported_at": clean_text(d.get("lastReportedAt", "") or "", 40) or None,
                "domain": clean_text(d.get("domain", "") or "", 100),
                "hostnames": clean_list(d.get("hostnames"), 5, 100),
                "is_whitelisted": whitelisted,
            },
            permalink=f"https://www.abuseipdb.com/check/{indicator}",
        )

    def validate(self) -> str:
        self._get("8.8.8.8")
        return "Clave válida (se usó 1 consulta de la cuota diaria)"
