"""abuse.ch: ThreatFox + URLhaus — https://threatfox.abuse.ch/api/

ThreatFox: POST https://threatfox-api.abuse.ch/api/v1/ {"query": "search_ioc", "search_term": ...}, cabecera
`Auth-Key` (clave gratuita del portal auth.abuse.ch). URLhaus: POST https://urlhaus-api.abuse.ch/v1/host/ (host=...).
Uso justo; uso comercial vía Spamhaus. Los IOCs de ThreatFox expiran a los 6 meses en la API.
En ThreatFox las IPs suelen registrarse como "ip:puerto": se busca sin coincidencia exacta y se filtra.
"""

from __future__ import annotations

from typing import Any

from ti_gateway.models import IndicatorType, SourceResult
from ti_gateway.providers.base import Provider
from ti_gateway.util import clean_list, clean_text

THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_HOST = "https://urlhaus-api.abuse.ch/v1/host/"
CONFIDENT = 50  # confidence_level de ThreatFox (0-100) a partir del cual una coincidencia es "malicioso"


class AbuseCh(Provider):
    id = "abusech"
    label = "abuse.ch (ThreatFox + URLhaus)"
    indicator_types = ("ip", "domain", "hash")
    terms_note = "Uso justo; uso comercial vía Spamhaus. IOCs de ThreatFox de hasta 6 meses."
    docs_url = "https://threatfox.abuse.ch/api/"
    default_per_minute = 30

    def _headers(self) -> dict[str, str]:
        return {"Auth-Key": self.secret, "Accept": "application/json"}

    def _threatfox(self, indicator: str, exact: bool) -> list[dict[str, Any]]:
        body = {"query": "search_ioc", "search_term": indicator, "exact_match": exact}
        data = self.check(self.request("POST", THREATFOX, json=body, headers=self._headers())) or {}
        rows = data.get("data") if data.get("query_status") == "ok" else []
        return [r for r in rows or [] if isinstance(r, dict)]

    def fetch(self, indicator: str, indicator_type: IndicatorType) -> SourceResult:
        hits = self._threatfox(indicator, exact=indicator_type != "ip")
        if indicator_type == "ip":
            hits = [
                h
                for h in hits
                if str(h.get("ioc", "")) in (indicator, f"[{indicator}]")
                or str(h.get("ioc", "")).startswith(f"{indicator}:")
            ]
        urls: list[dict[str, Any]] = []
        if indicator_type in ("ip", "domain"):
            uh = self.check(self.request("POST", URLHAUS_HOST, data={"host": indicator}, headers=self._headers())) or {}
            urls = [u for u in uh.get("urls") or [] if isinstance(u, dict)] if uh.get("query_status") == "ok" else []
        online = [u for u in urls if u.get("url_status") == "online"]
        best = max((int(h.get("confidence_level", 0) or 0) for h in hits), default=0)
        reasons = []
        if hits:
            families = sorted({clean_text(h.get("malware_printable", "") or "", 40) for h in hits} - {""})[:3]
            reasons.append(f"ThreatFox: {len(hits)} IOC ({', '.join(families) or 'sin familia'}; confianza {best}%)")
        if urls:
            reasons.append(f"URLhaus: {len(urls)} URL de malware ({len(online)} activas)")
        if (hits and best >= CONFIDENT) or online:
            level = "malicioso"
        elif hits or urls:
            level = "sospechoso"
        else:
            level = "sin reportes"
        return self.result(
            level,  # type: ignore[arg-type]
            f"{len(hits)} IOC en ThreatFox · {len(urls)} URL en URLhaus",
            reasons=reasons,
            data={
                "threatfox": [
                    {
                        "ioc": clean_text(h.get("ioc", ""), 80),
                        "threat_type": clean_text(h.get("threat_type", ""), 40),
                        "malware": clean_text(h.get("malware_printable", ""), 60),
                        "confidence": int(h.get("confidence_level", 0) or 0),
                        "first_seen": clean_text(h.get("first_seen", "") or "", 30),
                        "tags": clean_list(h.get("tags"), 5),
                    }
                    for h in hits[:5]
                ],
                "urlhaus": [
                    {
                        "url": clean_text(u.get("url", ""), 120),
                        "status": clean_text(u.get("url_status", ""), 20),
                        "threat": clean_text(u.get("threat", ""), 40),
                        "date_added": clean_text(u.get("date_added", ""), 30),
                    }
                    for u in urls[:5]
                ],
            },
            permalink=f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{indicator}",
        )

    def validate(self) -> str:
        self._threatfox("8.8.8.8", exact=True)  # 401/403 si la clave es inválida
        return "Clave válida"
