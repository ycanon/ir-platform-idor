"""GreyNoise Community API v3 — https://docs.greynoise.io/docs/using-the-greynoise-community-api

GET https://api.greynoise.io/v3/community/{ip}, cabecera `key` (opcional). 404 = la IP no fue vista escaneando
Internet ni está en RIOT (servicios benignos conocidos). Límites: sin clave 10/día; con clave gratuita 50/semana.
Aporta lo que más ayuda a separar ruido de un ataque dirigido: ¿es un escáner masivo de Internet?
"""

from __future__ import annotations

from typing import Any

from ti_gateway.models import IndicatorType, SourceResult
from ti_gateway.providers.base import Provider
from ti_gateway.util import clean_text

BASE = "https://api.greynoise.io/v3/community"


class GreyNoise(Provider):
    id = "greynoise"
    label = "GreyNoise"
    indicator_types = ("ip",)
    key_required = False  # la API Community funciona sin clave, con un cupo menor
    terms_note = "Community: 10 consultas/día sin clave; 50/semana con clave gratuita."
    docs_url = "https://docs.greynoise.io/docs/using-the-greynoise-community-api"
    default_per_minute = 30

    @property
    def quota_limit(self) -> int | None:
        if self._quota_override is not None:
            return self._quota_override
        return 50 if self._key else 10

    @property
    def period(self) -> str | None:
        return "week" if self._key else "day"

    def _headers(self) -> dict[str, str]:
        return {"key": self.secret, "accept": "application/json"} if self._key else {"accept": "application/json"}

    def fetch(self, indicator: str, indicator_type: IndicatorType) -> SourceResult:
        link = f"https://viz.greynoise.io/ip/{indicator}"
        response = self.request("GET", f"{BASE}/{indicator}", headers=self._headers())
        if response.status_code == 404:
            return self.result(
                "sin reportes", "No observada escaneando Internet ni en RIOT", status="not_found", permalink=link
            )
        d: dict[str, Any] = self.check(response) or {}
        classification = clean_text(d.get("classification", "") or "", 30).lower()
        name = clean_text(d.get("name", "") or "", 80)
        name = "" if name.lower() == "unknown" else name
        noise, riot = bool(d.get("noise")), bool(d.get("riot"))
        fp = False
        if classification == "malicious":
            level, reasons = "malicioso", ["Escáner de Internet clasificado como malicioso"]
        elif riot or classification == "benign":
            level, reasons, fp = "sin reportes", [f"Servicio benigno conocido ({name or 'RIOT'})"], True
        elif noise:
            level, reasons = "sospechoso", ["Escanea Internet con intención desconocida"]
        else:
            level, reasons = "sin reportes", []
        return self.result(
            level,  # type: ignore[arg-type]
            f"{classification or 'sin clasificar'}" + (f" · {name}" if name else ""),
            reasons=reasons,
            possible_false_positive=fp,
            context={"as_name": name},
            data={
                "noise": noise,
                "riot": riot,
                "classification": classification,
                "last_seen": clean_text(d.get("last_seen", "") or "", 30) or None,
            },
            permalink=link,
        )

    def validate(self) -> str:
        if not self._key:
            return "Sin clave: se usa el cupo anónimo (10 consultas/día)"
        response = self.request("GET", f"{BASE}/8.8.8.8", headers=self._headers())
        self.check(response, ok=(200, 404))
        return "Clave válida (se usó 1 consulta del cupo semanal)"
