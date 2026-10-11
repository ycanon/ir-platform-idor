"""Shodan — https://developer.shodan.io/api

GET https://api.shodan.io/shodan/host/{ip}?key=...&minify=true (sin banners). No consume créditos de consulta.
La API exige la clave como parámetro de la URL: nunca se registra la URL y los errores se limpian (`scrub`).
Validación: GET /api-info. Aporta contexto (puertos, organización) y etiquetas como `compromised`.
"""

from __future__ import annotations

from typing import Any

from ti_gateway.models import IndicatorType, SourceResult
from ti_gateway.providers.base import Provider
from ti_gateway.util import clean_list, clean_text

BASE = "https://api.shodan.io"
RISK_TAGS = {"compromised", "malware", "c2"}


class Shodan(Provider):
    id = "shodan"
    label = "Shodan"
    indicator_types = ("ip",)
    terms_note = "La consulta de host no consume créditos. La API exige la clave en la URL (se protege en logs)."
    docs_url = "https://developer.shodan.io/api"
    default_per_minute = 60

    def fetch(self, indicator: str, indicator_type: IndicatorType) -> SourceResult:
        link = f"https://www.shodan.io/host/{indicator}"
        response = self.request("GET", f"{BASE}/shodan/host/{indicator}", params={"key": self.secret, "minify": "true"})
        if response.status_code == 404:
            return self.result("sin datos", "Sin información en Shodan", status="not_found", permalink=link)
        d: dict[str, Any] = self.check(response) or {}
        ports = sorted({int(p) for p in d.get("ports") or [] if isinstance(p, int)})[:30]
        tags = clean_list(d.get("tags"), 10, 40)
        vulns = d.get("vulns") or []
        vuln_ids = clean_list(sorted(vulns) if isinstance(vulns, list) else sorted(vulns.keys()), 10, 30)
        risky = sorted(RISK_TAGS & {t.lower() for t in tags})
        reasons = [f"Etiquetas de riesgo en Shodan: {', '.join(risky)}"] if risky else []
        if vuln_ids:
            reasons.append(f"{len(vulns)} vulnerabilidades conocidas expuestas")
        return self.result(
            "sospechoso" if risky else "informativo",
            f"{len(ports)} puertos abiertos" + (f" · {', '.join(map(str, ports[:5]))}" if ports else ""),
            reasons=reasons,
            context={
                "as_name": clean_text(d.get("org", "") or d.get("isp", "") or "", 120),
                "asn": clean_text(d.get("asn", "") or "", 20),
                "country": clean_text(d.get("country_code", "") or "", 8),
            },
            data={
                "ports": ports,
                "hostnames": clean_list(d.get("hostnames"), 5, 100),
                "os": clean_text(d.get("os", "") or "", 60),
                "tags": tags,
                "vulns": vuln_ids,
                "last_update": clean_text(d.get("last_update", "") or "", 30) or None,
            },
            permalink=link,
        )

    def validate(self) -> str:
        info = self.check(self.request("GET", f"{BASE}/api-info", params={"key": self.secret})) or {}
        return f"Clave válida (plan: {clean_text(info.get('plan', 'desconocido'), 30)})"
