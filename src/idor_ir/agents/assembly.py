"""Ensamblado de la salida final de cada agente: lo que redacta el modelo + lo que fija el código [mejora O13].

El modelo (o la lógica determinista) entrega un BORRADOR; aquí se combina con los datos de la evidencia:
- Triage: severidad mínima por regla, confianza calculada, hipótesis rotuladas (hecho / hipótesis), campañas por
  validar como hipótesis obligatoria y prioridades POR CAMPAÑA (puntos 3 y 4).
- Forensic: patient zero, inicio y automatización desde la evidencia; MITRE con táctica del catálogo y técnicas
  obligatorias (puntos 1 y 7).
- Response: acciones candidatas del código ordenadas por el modelo; las obligatorias que falten se agregan
  marcadas "agregada por política" (puntos 2 y 7).
Todo lo agregado o fijado queda en `checks.code_additions` (transparencia, punto 12).
"""

from __future__ import annotations

import re
from typing import Any

from idor_ir.agents import fallback, mitre
from idor_ir.agents.llm import trim_words
from idor_ir.agents.schemas import (
    Checks,
    ForensicDraft,
    ForensicOutput,
    Hypothesis,
    MitreMapping,
    ResponseAction,
    ResponseDraft,
    ResponseOutput,
    TriageDraft,
    TriageOutput,
)

SEVERITY_ORDER = {"bajo": 0, "medio": 1, "alto": 2, "critico": 3}
# Temas que los logs de acceso NO pueden demostrar: si el modelo los presenta como "hecho", se reclasifican como
# hipótesis (prueba real: "las credenciales fueron obtenidas mediante phishing" rotulado como hecho).
_SPECULATIVE_RE = re.compile(
    r"phishing|robad|robo de|comprometid|filtrad|filtraci|fuga|credential stuffing|fuerza bruta|obtenid[ao]s? "
    r"(mediante|por|a trav)|insider|empleado|motiv|fraude|venta|vend|extorsi|ransom|actor|grupo|pa[ií]s de origen|"
    r"intenci|objetivo del atacante|uso posterior",
    re.I,
)
_HEDGE_RE = re.compile(r"posibl|podr[ií]a|hip[oó]tesis|probabl|quiz[aá]|sugiere|indicar[ií]a|no se sabe", re.I)


def _lower_first(text: str) -> str:
    return text[:1].lower() + text[1:] if text[:2] != text[:2].upper() else text


def confidence(ctx: dict[str, Any]) -> tuple[float, list[str]]:
    """Confianza calculada con la evidencia (punto 3): el modelo ya no la decide (había dicho 99 %)."""
    confirmed = fallback._confirmed(ctx)
    if not confirmed:
        pending = fallback._pending(ctx)
        return (0.5, ["solo campañas por validar"]) if pending else (0.4, ["sin campañas sospechosas"])
    score, basis = 0.6, ["campaña confirmada (IP con nivel crítico y UA de herramienta)"]
    c = confirmed[0]
    imp = c.get("impact", {})
    if imp.get("unique_invoices_2xx_outside_baseline"):
        score += 0.1
        basis.append("objetos fuera del rango del tráfico normal")
    if any(u.get("category") != "navegador_u_otro" for u in c.get("user_agents", [])):
        score += 0.1
        basis.append("user agents de herramientas de automatización")
    phases = c.get("phases", [])
    if phases and phases[0].get("success_ratio") == 0 and any(p.get("success_ratio", 0) > 0 for p in phases):
        score += 0.05
        basis.append("fase de sondeo con 0 % de éxito seguida de éxito")
    if imp.get("success_2xx_with_token") and not imp.get("success_2xx_without_token"):
        score += 0.05
        basis.append("todas las respuestas 2xx fueron con credencial (falla de autorización)")
    return round(min(score, 0.9), 2), basis


def assemble_triage(draft: TriageDraft, ctx: dict[str, Any], extra_checks: Checks | None = None) -> TriageOutput:
    checks = extra_checks or Checks()
    rule_sev, rule_why = fallback.rule_severity(ctx)
    severity = draft.severity
    severity_basis = f"Regla: {rule_why} → mínimo «{rule_sev}»."
    if SEVERITY_ORDER[draft.severity] < SEVERITY_ORDER[rule_sev]:
        checks.code_additions.append(f"Severidad elevada de «{draft.severity}» a «{rule_sev}» ({rule_why})")
        severity = rule_sev

    hyps: list[Hypothesis] = []
    for n, h in enumerate(draft.hypotheses, start=1):
        text = trim_words(h.text.strip(), 230)
        kind = h.kind
        if kind == "hecho" and _SPECULATIVE_RE.search(text) and not _HEDGE_RE.search(text):
            kind = "hipotesis"
            checks.code_additions.append(
                f"Hipótesis {n} reclasificada como hipótesis: los logs de acceso no demuestran ese punto"
            )
        if kind == "hipotesis" and not _HEDGE_RE.search(text):
            text = "Posible: " + _lower_first(text)
        hyps.append(Hypothesis(text=text, kind=kind, origin="modelo"))
    mentioned = " ".join(h.text for h in hyps)
    for c in fallback._pending(ctx):
        if not re.search(rf"\b{re.escape(c['id'])}\b", mentioned):
            hyps.append(
                Hypothesis(
                    text=f"Posible: {c['id']} (por validar: {len(c['ips'])} IPs, {len(c['tokens'])} credenciales) es "
                    "actividad interna/prueba o una segunda campaña; validar con AppSec/QA antes de actuar",
                    kind="hipotesis",
                    origin="código",
                )
            )
            checks.code_additions.append(f"Hipótesis agregada: {c['id']} está por validar")

    conf, basis = confidence(ctx)
    checks.code_additions.append(f"Confianza calculada por el código: {conf:.0%}")
    targets = [f"{c['id']} (confirmada)" for c in fallback._confirmed(ctx)] + [
        f"{c['id']} (validar antes de actuar)" for c in fallback._pending(ctx)
    ]
    return TriageOutput(
        severity=severity,
        attack_type=trim_words(draft.attack_type.strip(), 140),
        confidence=conf,
        hypotheses=[h.text for h in hyps][:6],
        investigation_plan=[trim_words(x.strip(), 230) for x in draft.investigation_plan],
        priority_targets=targets[:6],
        hypotheses_detail=hyps[:6],
        confidence_basis=basis,
        severity_basis=severity_basis,
        checks=_status(checks),
    )


def assemble_forensic(
    draft: ForensicDraft, ctx: dict[str, Any], extra_checks: Checks | None = None
) -> tuple[ForensicOutput, mitre.MitreAssembly]:
    checks = extra_checks or Checks()
    facts = fallback.forensic_facts(ctx)
    result = mitre.assemble([m.model_dump() for m in draft.mitre], fallback.evidence_like(ctx))
    checks.code_additions.append(
        "Patient zero, inicio de la explotación y tipo de automatización tomados de la evidencia"
    )
    checks.code_additions.append(f"Nombre y táctica MITRE desde el catálogo ({mitre.ATTACK_VERSION})")
    for tid in result.added:
        rule = next(m["rule"] for m in result.mappings if m["technique_id"] == tid)
        checks.code_additions.append(f"{tid} agregada por regla de la evidencia: {rule}")
    for tid in result.dropped:
        if tid:
            checks.code_additions.append(f"{tid} descartada (repetida o fuera del catálogo)")
    for m in result.mappings:
        if m.get("justification_issue"):
            if m["justification_source"] == "código":
                checks.code_additions.append(
                    f"{m['technique_id']}: la justificación del modelo no correspondía a la técnica; se usó la de la "
                    "evidencia"
                )
            else:
                checks.issues.append(f"{m['technique_id']}: la justificación no corresponde claramente a la técnica")
    mappings = [MitreMapping.model_validate({k: v for k, v in m.items() if k != "justification_issue"})
                for m in result.mappings]  # fmt: skip
    out = ForensicOutput(
        attack_pattern=trim_words(draft.attack_pattern.strip(), 600),
        reasoning=[trim_words(x.strip(), 280) for x in draft.reasoning],
        patient_zero=facts["patient_zero"][:300],
        exploitation_start=facts["exploitation_start"][:300],
        automation_type=facts["automation_type"][:300],
        campaigns_assessment=trim_words(draft.campaigns_assessment.strip(), 500),
        mitre_attack=mappings[:8],
        open_questions=[trim_words(x.strip(), 230) for x in draft.open_questions],
        checks=_status(checks),
    )
    return out, result


def assemble_response(
    draft: ResponseDraft, candidates: list[ResponseAction], extra_checks: Checks | None = None
) -> ResponseOutput:
    checks = extra_checks or Checks()
    by_id = {a.action_id: a for a in candidates}
    ordered: list[ResponseAction] = []
    used: set[str] = set()
    for rank in draft.ranking:
        aid = rank.action_id.strip().upper()
        if aid not in by_id:
            checks.code_additions.append(f"Acción «{aid[:10]}» ignorada: no está entre las candidatas")
            continue
        if aid in used:
            continue
        used.add(aid)
        rationale = trim_words(rank.rationale.strip(), 200) or by_id[aid].rationale
        ordered.append(by_id[aid].model_copy(update={"rationale": rationale}))
    position = {a.action_id: i for i, a in enumerate(candidates)}
    for a in candidates:
        if a.action_id in used:
            continue
        if a.mandatory:
            # Se inserta en su lugar natural (después de las candidatas que la preceden), no al final.
            k = position[a.action_id]
            at = max((i + 1 for i, x in enumerate(ordered) if position[x.action_id] < k), default=0)
            ordered.insert(at, a.model_copy(update={"added_by_policy": True}))
            checks.code_additions.append(
                f"{a.action_id} ({a.action_type}) agregada por política: obligatoria ({a.reason_required})"
            )
        else:
            checks.code_additions.append(f"{a.action_id} ({a.action_type}) omitida por el modelo (opcional)")
    ordered = [a.model_copy(update={"priority": i}) for i, a in enumerate(ordered, start=1)]
    return ResponseOutput(
        actions=ordered,
        # La lista ya se numera al mostrarla: se quita la numeración que escriba el modelo ("1. 1. Contener").
        playbook=[trim_words(re.sub(r"^\s*\d+[.)-]\s*", "", x).strip(), 230) for x in draft.playbook],
        ordering_rationale=trim_words(draft.ordering_rationale.strip(), 500),
        checks=_status(checks),
    )


def _status(checks: Checks) -> Checks:
    checks.status = "con observaciones" if checks.issues else "verificado"
    return checks
