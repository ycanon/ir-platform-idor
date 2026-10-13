"""Chat híbrido [mejora O13, fase 2 · punto 8]: las preguntas de DATO se responden desde la evidencia, sin modelo.

"¿Cuántas IPs tiene C1?", "lista las IPs", "¿cuándo ocurrió C2?", "¿cuántas facturas?", "¿qué sitios?",
"¿quién es el patient zero?", "¿cuál es el TTD?"... tienen una respuesta exacta en `evidence.json`. Responderlas
con el código es instantáneo y no puede inventar (en la prueba real el modelo dijo "febrero 2021" y omitió una
IP). El modelo queda para el "por qué" y el "qué harías".

Criterio conservador: si la pregunta pide criterio (por qué, cómo, recomienda, prioriza...) va al modelo.
"""

from __future__ import annotations

import re
from typing import Any

from idor_ir.forensics.assessment import is_priority, status_label
from idor_ir.profile import IncidentProfile

_JUDGEMENT = re.compile(
    r"por ?qu[eé]|c[oó]mo|explic|deber[ií]|recomiend|recomendar|prioriz|har[ií]as|riesgo|opin|eval[uú]|justific|"
    r"mejor|conviene|impacto|significa|interpreta|sugier|plan|analiza|compara|diferencia",
    re.I,
)
_ASK = r"(cu[aá]nt[oa]s|cu[aá]les|qu[eé]|lista|listar|enumera|dame|muestra|indica|nombra)"
SOURCE = "Fuente: evidencia del run (respuesta del código, sin modelo)."


def _campaigns(evidence: dict[str, Any], question: str) -> list[dict[str, Any]]:
    ids = {f"C{n}" for n in re.findall(r"\bC(\d{1,2})\b", question, re.I)}
    camps = evidence.get("campaigns", [])
    return [c for c in camps if c["campaign_id"] in ids] if ids else camps


def _status(c: dict[str, Any]) -> str:
    return status_label(c["status"])


def _ips(c: dict[str, Any]) -> str:
    pz = (c.get("patient_zero") or {}).get("source_ip")
    es = (c.get("exploitation_start") or {}).get("source_ip")
    parts = []
    for ip in c["ips"]:
        tags = [t for t, hit in (("primera actividad", ip == pz), ("primer acceso exitoso", ip == es)) if hit]
        parts.append(f"{ip} ({', '.join(tags)})" if tags else ip)
    return ", ".join(parts)


def is_data_question(question: str) -> bool:
    return answer_from_evidence(question, {"campaigns": [], "metadata": {}}) is not None


def answer_from_evidence(question: str, evidence: dict[str, Any]) -> str | None:  # noqa: C901 - tabla de intenciones
    """Respuesta exacta si la pregunta es de dato; None si requiere criterio (va al modelo)."""
    q = question.strip()
    if not q or _JUDGEMENT.search(q):
        return None
    prof = IncidentProfile.from_evidence(evidence)
    objs = prof.object_label_plural
    camps = _campaigns(evidence, q)
    lines: list[str] = []

    if re.search(rf"{_ASK}.*\bips?\b|\bips?\b.*\b(tiene|usa|usó|participa)", q, re.I):
        lines = [f"- {c['campaign_id']} ({_status(c)}): {len(c['ips'])} IPs — {_ips(c)}" for c in camps]
        if any(is_priority(c) for c in camps):
            lines.append("- Las IPs de una campaña comparten credenciales: se contienen como una unidad.")
    elif re.search(r"\bcu[aá]ndo\b|\bfechas?\b|\bperiodo\b|\bper[ií]odo\b", q, re.I):
        rng = (evidence.get("metadata") or {}).get("dataset_range") or [None, None]
        for c in camps:
            es = c.get("exploitation_start") or {}
            lines.append(
                f"- {c['campaign_id']} ({_status(c)}): del {str(c['first_seen'])[:16]} al {str(c['last_seen'])[:16]}"
                + (f"; primer acceso exitoso {str(es.get('ts'))[:16]} desde {es.get('source_ip')}" if es else "")
            )
            lines += [
                f"  · fase {p['phase']}: {p['start']} a {p['end']}, ~{p['median_per_day']:.0f}/día, éxito "
                f"{p['success_ratio']:.0%}"
                for p in c.get("phases", [])
            ]
        if rng[0]:
            lines.append(f"- El log cubre del {str(rng[0])[:16]} al {str(rng[1])[:16]}.")
    elif re.search(rf"{_ASK}.*\b(tokens?|credenciales?|cuentas?)\b", q, re.I):
        lines = [
            f"- {c['campaign_id']} ({_status(c)}): {len(c['tokens'])} credenciales — "
            + ", ".join(t["hint"] for t in c["tokens"])
            for c in camps
        ]
    elif re.search(rf"{_ASK}.*\b({re.escape(prof.scope_label)}|sitios?|tenants?|pa[ií]ses|clientes)\b", q, re.I):
        for c in camps:
            by = c["impact"].get("unique_invoices_2xx_by_site") or {}
            lines.append(
                f"- {c['campaign_id']} ({_status(c)}): {len(by)} {prof.scope_label}(s) — "
                + ", ".join(f"{k}: {v:,}" for k, v in by.items())
            )
    elif re.search(rf"cu[aá]nt[oa]s\b.*\b({re.escape(objs)}|{re.escape(prof.object_label)}|objetos|registros|"
                   r"expuest|accedid|alcance)", q, re.I):  # fmt: skip
        for c in camps:
            imp = c["impact"]
            lines.append(
                f"- {c['campaign_id']} ({_status(c)}): {imp['unique_invoices_2xx']:,} {objs} únicas con respuesta 2xx "
                f"(TOTAL de la campaña); {imp['unique_invoices_2xx_outside_baseline']:,} fuera del rango del tráfico "
                f"normal; {imp['success_responses_2xx']:,} respuestas 2xx"
            )
    elif re.search(r"patient zero|paciente cero|primer[ao]? (acceso|petici[oó]n|actividad)", q, re.I):
        for c in camps:
            pz, es = c.get("patient_zero") or {}, c.get("exploitation_start") or {}
            lines.append(
                f"- {c['campaign_id']} ({_status(c)}): primera petición {str(pz.get('ts'))[:16]} desde "
                f"{pz.get('source_ip')} (status {pz.get('status')}, UA {str(pz.get('user_agent'))[:40]})"
            )
            if es:
                lines.append(
                    f"  · primer acceso exitoso {str(es.get('ts'))[:16]} desde {es.get('source_ip')} "
                    f"(status {es.get('status')})"
                )
    elif re.search(r"\bttd\b|tiempo de detecci", q, re.I):
        rm = evidence.get("response_metrics") or {}
        if rm.get("ttd_from_first_malicious_request_days") is None:
            return None
        ref = "fecha de detección indicada por el analista" if not rm.get("ttd_is_estimate") else (
            "ESTIMADO hasta el último registro del log; indique la fecha de detección para medirlo")  # fmt: skip
        lines = [
            f"- TTD desde la primera actividad: {rm['ttd_from_first_malicious_request_days']} días",
            f"- TTD desde el primer acceso exitoso: {rm.get('ttd_from_first_successful_access_days')} días",
            f"- Referencia: {str(rm.get('ttd_reference'))[:16]} ({ref})",
        ]
    elif re.search(rf"{_ASK}.*(user.?agents?|\bua\b|herramientas)", q, re.I):
        for c in camps:
            lines.append(
                f"- {c['campaign_id']} ({_status(c)}): "
                + "; ".join(
                    f"{u['user_agent'][:50]} ({u['category']}, desde {str(u['first_seen'])[:16]})"
                    for u in c.get("user_agents", [])
                )  # fmt: skip
            )
    elif re.search(r"cu[aá]nt[ao]s\b.*\bcampa[nñ]as\b|\bqu[eé] campa[nñ]as\b", q, re.I):
        lines = [
            f"- {c['campaign_id']} ({_status(c)}): {len(c['ips'])} IPs, {len(c['tokens'])} credenciales, "
            f"{c['requests']:,} peticiones" for c in evidence.get("campaigns", [])
        ]  # fmt: skip
    else:
        return None
    if not lines:
        return "- No hay campañas que coincidan con la pregunta.\n" + SOURCE
    return "\n".join(lines) + "\n" + SOURCE
