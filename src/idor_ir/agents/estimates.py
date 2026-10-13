"""Métricas de respuesta TTD / TTR / TTC y efecto de la automatización [R14].

- TTD (Time to Detect) se mide con los datos (evidencia).
- **Backtest de reglas**: se aplica sobre el Parquet la regla de detección propuesta y se calcula cuándo
  habría alertado. Responde con datos "¿cuánto se habría reducido el TTD?".
- TTR (Time to Respond) y TTC (Time to Contain) no están en los logs: se ESTIMAN con supuestos explícitos
  (editables) para un escenario manual y uno automatizado. En el automatizado se usan los tiempos
  MEDIDOS del pipeline y de los agentes.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import polars as pl

from idor_ir.profile import IncidentProfile

# Supuestos (horas) del escenario manual. Documentados en el reporte; no provienen del dataset.
MANUAL_ASSUMPTIONS_H = {
    "triage_inicial": 4.0,
    "analisis_forense_4_5M_logs": 16.0,
    "plan_de_contencion": 4.0,
    "aprobacion": 4.0,
    "implementacion_cambios": 8.0,
}
# Supuestos del escenario automatizado (lo humano que queda).
AUTOMATED_ASSUMPTIONS_H = {"revision_humana_del_plan": 0.5, "aprobacion": 1.0, "despliegue_reglas": 0.25}


def backtest_rules(
    lf: pl.LazyFrame, suspicious_tokens: list[str], threshold: int = 50, profile: IncidentProfile | None = None
) -> dict[str, Any]:
    """¿Cuándo habrían alertado las reglas propuestas y cuántos falsos positivos habrían generado?

    Las reglas se evalúan solo sobre el endpoint del perfil del incidente (igual que se desplegarían).
    """
    p = profile or IncidentProfile()
    lf = lf.filter(pl.col("path") == p.endpoint)
    flagged = (
        lf.group_by("authtoken", day=pl.col("ts").dt.date())
        .agg(invoices=pl.col("invoice_id_num").n_unique())
        .filter(pl.col("invoices") > threshold)
        .group_by("authtoken")
        .agg(first_day=pl.col("day").min())
        .collect(engine="streaming")
    )
    hits = flagged.filter(pl.col("authtoken").is_in(suspicious_tokens))
    other_tokens = flagged.filter(~pl.col("authtoken").is_in(suspicious_tokens)).height
    tool_ua = (
        lf.filter(pl.col("is_automation"))
        .group_by("authtoken")
        .agg(first=pl.col("ts").min())
        .collect(engine="streaming")
    )
    ua_hits = tool_ua.filter(pl.col("authtoken").is_in(suspicious_tokens))
    return {
        "rule_token_distinct_invoices_per_day": {
            "rule": f"{p.token_param} con > {threshold} {p.object_param} distintos en un día",
            "would_alert_on": str(hits["first_day"].min()) if hits.height else None,
            "other_tokens_alerted": other_tokens,
            "note": f"{other_tokens} credenciales fuera de las campañas priorizadas también superan el umbral: "
            "ajustar el umbral al comportamiento real por cliente antes de bloquear."
            if other_tokens
            else "Sin alertas sobre otros tokens.",
        },
        "rule_automation_user_agent": {
            "rule": f"UA de herramienta de automatización en {p.endpoint}",
            "would_alert_on": ua_hits["first"].min().isoformat() if ua_hits.height else None,  # type: ignore[union-attr]
            "other_tokens_alerted": tool_ua.height - ua_hits.height,
        },
    }


def estimate_response_times(measured_automation_s: float, response_metrics: dict[str, Any]) -> dict[str, Any]:
    manual_ttr = sum(
        MANUAL_ASSUMPTIONS_H[k] for k in ("triage_inicial", "analisis_forense_4_5M_logs", "plan_de_contencion")
    )
    manual_ttc = manual_ttr + MANUAL_ASSUMPTIONS_H["aprobacion"] + MANUAL_ASSUMPTIONS_H["implementacion_cambios"]
    auto_ttr = measured_automation_s / 3600 + AUTOMATED_ASSUMPTIONS_H["revision_humana_del_plan"]
    auto_ttc = auto_ttr + AUTOMATED_ASSUMPTIONS_H["aprobacion"] + AUTOMATED_ASSUMPTIONS_H["despliegue_reglas"]
    return {
        "ttd_days_measured": response_metrics.get("ttd_from_first_malicious_request_days"),
        "ttd_from_first_success_days_measured": response_metrics.get("ttd_from_first_successful_access_days"),
        # Sin fecha de detección del analista, el TTD se estima hasta el último registro del log.
        "ttd_is_estimate": bool(response_metrics.get("ttd_is_estimate")),
        "ttd_reference_source": response_metrics.get("ttd_reference_source"),
        "manual": {
            "ttr_hours": round(manual_ttr, 2),
            "ttc_hours": round(manual_ttc, 2),
            "assumptions_h": MANUAL_ASSUMPTIONS_H,
        },
        "automated": {
            "ttr_hours": round(auto_ttr, 2),
            "ttc_hours": round(auto_ttc, 2),
            "measured_pipeline_and_agents_s": round(measured_automation_s, 1),
            "assumptions_h": AUTOMATED_ASSUMPTIONS_H,
        },
        "reduction": {
            "ttr_percent": round(100 * (1 - auto_ttr / manual_ttr), 1),
            "ttc_percent": round(100 * (1 - auto_ttc / manual_ttc), 1),
        },
        "note": "TTR/TTC son estimaciones con supuestos explícitos; solo los tiempos de la automatización son medidos.",
        "computed_at": datetime.now().isoformat(timespec="seconds"),
    }
