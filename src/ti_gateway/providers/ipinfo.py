"""IPinfo Lite — https://ipinfo.io/developers/lite-api

GET https://api.ipinfo.io/lite/{ip}?token=... (el token va en la query, según la API). Gratuito y sin límite:
país y ASN. No incluye detección de VPN/proxy (planes pagos). Solo aporta CONTEXTO, no reputación.
"""

from __future__ import annotations

from typing import Any

from ti_gateway.models import IndicatorType, SourceResult
from ti_gateway.providers.base import Provider
from ti_gateway.util import clean_text

BASE = "https://api.ipinfo.io/lite"


class IPinfo(Provider):
    id = "ipinfo"
    label = "IPinfo"
    indicator_types = ("ip",)
    terms_note = "Lite gratuito y sin límite: país y ASN. Sin detección de VPN/proxy (planes pagos)."
    docs_url = "https://ipinfo.io/developers/lite-api"
    default_per_minute = 120

    def _get(self, ip: str) -> Any:
        return self.check(self.request("GET", f"{BASE}/{ip}", params={"token": self.secret}))

    def fetch(self, indicator: str, indicator_type: IndicatorType) -> SourceResult:
        d: dict[str, Any] = self._get(indicator) or {}
        asn = clean_text(d.get("asn", "") or "", 20)
        as_name = clean_text(d.get("as_name", "") or "", 120)
        country = clean_text(d.get("country_code", "") or "", 8)
        return self.result(
            "informativo",
            " · ".join(x for x in (asn, as_name, country) if x) or "Sin datos de red",
            context={
                "asn": asn,
                "as_name": as_name,
                "as_domain": clean_text(d.get("as_domain", "") or "", 100),
                "country": country,
            },
            data={
                "country_name": clean_text(d.get("country", "") or "", 60),
                "continent": clean_text(d.get("continent", "") or "", 30),
            },
            permalink=f"https://ipinfo.io/{indicator}",
        )

    def validate(self) -> str:
        self._get("8.8.8.8")
        return "Token válido"
