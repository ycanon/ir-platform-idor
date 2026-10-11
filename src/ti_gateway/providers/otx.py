"""AlienVault OTX API v1 — SDK oficial OTX-Python-SDK (OTXv2.py).

GET /api/v1/indicators/{IPv4|IPv6|domain|file}/{valor}/general, cabecera `X-OTX-API-KEY`.
Los indicadores son consultables sin clave; la validación usa /api/v1/pulses/subscribed, que sí la exige.
"""

from __future__ import annotations

from typing import Any

from ti_gateway.models import IndicatorType, SourceResult
from ti_gateway.providers.base import Provider
from ti_gateway.util import clean_list, clean_text

BASE = "https://otx.alienvault.com/api/v1"


class OTX(Provider):
    id = "otx"
    label = "AlienVault OTX"
    indicator_types = ("ip", "domain", "hash")
    terms_note = "Plataforma comunitaria: los pulsos los publican usuarios (posibles falsos positivos)."
    docs_url = "https://otx.alienvault.com/api"
    default_per_minute = 60

    def _headers(self) -> dict[str, str]:
        return {"X-OTX-API-KEY": self.secret, "accept": "application/json"}

    def fetch(self, indicator: str, indicator_type: IndicatorType) -> SourceResult:
        kind = {"ip": "IPv6" if ":" in indicator else "IPv4", "domain": "domain", "hash": "file"}[indicator_type]
        link = f"https://otx.alienvault.com/indicator/{'ip' if indicator_type == 'ip' else kind}/{indicator}"
        response = self.request("GET", f"{BASE}/indicators/{kind}/{indicator}/general", headers=self._headers())
        if response.status_code == 404:
            return self.result("sin reportes", "Sin registros en OTX", status="not_found", permalink=link)
        body: dict[str, Any] = self.check(response) or {}
        info = body.get("pulse_info") or {}
        pulses = [p for p in info.get("pulses") or [] if isinstance(p, dict)]
        count = int(info.get("count", len(pulses)) or 0)
        validation = [
            clean_text(v.get("message") or v.get("name") or v.get("source"), 120)
            for v in body.get("validation") or []
            if isinstance(v, dict)
        ]
        if validation:
            level, reasons = "sin reportes", [f"En lista de confianza ({validation[0]})"]
        elif count:
            level, reasons = "sospechoso", [f"Aparece en {count} pulso(s)"]
        else:
            level, reasons = "sin reportes", []
        return self.result(
            level,  # type: ignore[arg-type]
            f"{count} pulso{'s' if count != 1 else ''}"
            + (f": {clean_text(pulses[0].get('name', ''), 60)}" if pulses else ""),
            reasons=reasons,
            possible_false_positive=bool(validation),
            context={
                "country": clean_text(body.get("country_name", ""), 60),
                "as_name": clean_text(body.get("asn", ""), 120),
            },
            data={
                "pulse_count": count,
                "pulses": [
                    {
                        "name": clean_text(p.get("name", ""), 120),
                        "created": clean_text(p.get("created", ""), 30),
                        "tags": clean_list(p.get("tags"), 5),
                    }
                    for p in pulses[:5]
                ],
                "validation": validation[:5],
            },
            permalink=link,
        )

    def validate(self) -> str:
        self.check(self.request("GET", f"{BASE}/pulses/subscribed", headers=self._headers(), params={"limit": "1"}))
        return "Clave válida"
