"""Lógica determinista de los agentes: borradores, datos y acciones candidatas.

Dos usos:
1. **Sin LLM** (o si el LLM falla): produce los mismos borradores que escribiría el modelo; el ensamblado
   (`assembly.py`) los convierte en la salida final. La demo nunca depende de la IA.
2. **Con LLM** [mejora O13, punto 7]: aporta los DATOS que el modelo ya no escribe (patient zero, inicio de
   explotación, automatización) y las ACCIONES CANDIDATAS que el Response Advisor solo ordena y justifica.
"""

from __future__ import annotations

from typing import Any

from idor_ir.agents.mitre import required_techniques
from idor_ir.agents.schemas import (
    ActionRank,
    ForensicDraft,
    ForensicOutput,
    HypothesisDraft,
    MitreChoice,
    ResponseAction,
    ResponseDraft,
    ResponseOutput,
    Severity,
    TriageDraft,
    TriageOutput,
)
from idor_ir.forensics.assessment import STATUS_CORROBORATED, STATUS_PENDING, is_priority
from idor_ir.profile import IncidentProfile


def _confirmed(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """Campañas priorizadas: corroboradas o hipótesis de alta confianza (NO significa IDOR demostrado)."""
    return [c for c in ctx.get("campaigns", []) if is_priority(c)]


def _pending(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    return [c for c in ctx.get("campaigns", []) if c["status"] == STATUS_PENDING]


def _corroborated(ctx: dict[str, Any]) -> bool:
    return any(c["status"] == STATUS_CORROBORATED for c in ctx.get("campaigns", []))


def _profile(ctx: dict[str, Any]) -> IncidentProfile:
    """Perfil del incidente del run (endpoint, parámetros, etiquetas). Contextos antiguos → valores del reto."""
    return IncidentProfile.from_mapping((ctx.get("incident") or {}).get("profile"))


def evidence_like(ctx: dict[str, Any]) -> dict[str, Any]:
    """Adapta el contexto de los agentes a la forma de `evidence.json` que usan las reglas MITRE."""
    return {
        "metadata": {"profile": (ctx.get("incident") or {}).get("profile")},
        "campaigns": [
            {
                "campaign_id": c["id"],
                "status": c["status"],
                "ips": c["ips"],
                "tokens": c["tokens"],
                "impact": c.get("impact", {}),
                "phases": c.get("phases", []),
                "patient_zero": c.get("patient_zero") or {},
                "user_agents": [
                    {"user_agent": u.get("ua", ""), "category": u.get("category")} for u in c.get("user_agents", [])
                ],
            }
            for c in ctx.get("campaigns", [])
        ],
    }


def rule_severity(ctx: dict[str, Any]) -> tuple[Severity, str]:
    """Severidad mínima que exige la evidencia (el modelo puede subirla, nunca bajarla)."""
    confirmed, pending = _confirmed(ctx), _pending(ctx)
    if confirmed:
        objs = sum(c["impact"].get("unique_invoices_2xx", 0) for c in confirmed)
        level = "campaña corroborada" if _corroborated(ctx) else "hipótesis de alta confianza"
        if objs >= 1000:
            return "critico", f"{level} con {objs:,} objetos potencialmente expuestos (≥ 1 000)"
        return "alto", f"{level} con {objs:,} objetos potencialmente expuestos"
    if pending:
        return "medio", "solo campañas por validar"
    return "bajo", "sin campañas sospechosas"


# --------------------------------------------------------------------------- Triage
def triage_draft(ctx: dict[str, Any]) -> TriageDraft:
    confirmed, pending = _confirmed(ctx), _pending(ctx)
    p = _profile(ctx)
    sev, _ = rule_severity(ctx)
    if not confirmed:
        return TriageDraft(
            severity=sev,
            attack_type="Sin hipótesis de alta confianza de IDOR",
            hypotheses=[
                HypothesisDraft(text="Actividad automatizada sin señales concordantes de abuso", kind="hipotesis")
            ],
            investigation_plan=["Validar las campañas por confirmar con los dueños de las cuentas"],
        )
    main = confirmed[0]
    corroborated = _corroborated(ctx)
    objs = main["impact"].get("unique_invoices_2xx", 0)
    hyps = [
        HypothesisDraft(
            text=f"{len(main['tokens'])} credenciales obtuvieron 2xx para {objs:,} {p.object_param} distintos en "
            f"{p.endpoint} con patrón de enumeración",
            kind="hecho",
        ),
        HypothesisDraft(
            text=f"{p.endpoint} no valida que cada {p.object_label} pertenezca al titular de la credencial (IDOR)"
            + (": corroborado con ownership" if corroborated else ": pendiente de corroborar con ownership"),
            kind="hecho" if corroborated else "hipotesis",
        ),
        HypothesisDraft(
            text=f"Operación coordinada: las {len(main['ips'])} IPs de {main['id']} comparten las mismas credenciales",
            kind="hecho",
        ),
    ]
    return TriageDraft(
        severity=sev,
        attack_type=(
            f"IDOR corroborado: enumeración automatizada de {p.object_param} en {p.endpoint}"
            if corroborated
            else f"Patrón compatible con IDOR (hipótesis de alta confianza): enumeración automatizada de "
            f"{p.object_param} con credenciales en {p.endpoint}"
        ),
        hypotheses=hyps,
        investigation_plan=[
            f"Corroborar con la aplicación: titular (ownership) de cada {p.object_label} con 2xx y decisión de "
            "autorización por objeto"
            if not corroborated
            else f"Cuantificar el impacto confirmado por titular con la fuente de ownership de {main['id']}",
            f"Delimitar el alcance de {main['id']}: {p.object_label_plural} con 2xx"
            + (f" y desglose por {p.scope_param}" if p.scope_param else ""),
            "Determinar el origen de las credenciales con el proveedor de identidad (compromiso o cuentas del atacante)",
            "Validar con AppSec/QA las campañas por validar" if pending else "Buscar actividad residual",
        ],
    )


# --------------------------------------------------------------------------- Forensic
def forensic_facts(ctx: dict[str, Any]) -> dict[str, str]:
    """Datos que ya no escribe el modelo: salen tal cual de la evidencia (punto 7)."""
    confirmed = _confirmed(ctx)
    if not confirmed:
        return {"patient_zero": "N/A", "exploitation_start": "N/A", "automation_type": "N/A"}
    c = confirmed[0]
    pz, es = c["patient_zero"], c["exploitation_start"]
    tools = sorted({u["ua"] for u in c["user_agents"] if u["category"] != "navegador_u_otro"})
    constant = any(p.get("constant_daily_volume") for p in c["phases"])
    return {
        "patient_zero": f"{pz['ts']} desde {pz['source_ip']} (status {pz['status']}, UA {pz['user_agent']}); "
        "coincide con el inicio del log, por lo que la actividad pudo empezar antes",
        "exploitation_start": f"Primer acceso exitoso {es['ts']} desde {es['source_ip']} (status {es['status']})"
        if es
        else "Sin acceso exitoso",
        "automation_type": f"Herramientas ({', '.join(tools)})"
        + (" con volumen diario constante por fase" if constant else "")
        + f" desde {len(c['ips'])} IPs rotando las mismas credenciales",
    }


def forensic_draft(ctx: dict[str, Any], tri: TriageOutput | None = None) -> ForensicDraft:
    confirmed, pending = _confirmed(ctx), _pending(ctx)
    p = _profile(ctx)
    start = ((ctx.get("incident") or {}).get("dataset_range") or [None])[0] or "el inicio del log"
    if not confirmed:
        return ForensicDraft(
            attack_pattern="No hay campañas con señales concordantes.",
            reasoning=["Sin IPs críticas", "Sin señales concordantes de enumeración o abuso"],
            campaigns_assessment="Solo actividad por validar." if pending else "Sin actividad sospechosa.",
            mitre=[
                MitreChoice(technique_id="T1595.002", justification="Actividad automatizada de sondeo no concluyente")
            ],
        )
    c = confirmed[0]
    imp, phases = c["impact"], c["phases"]
    phase_txt = "; ".join(
        f"{x['start']}→{x['end']}: {x['median_per_day']:.0f}/día, éxito {x['success_ratio']:.0%}" for x in phases
    )
    tools = sorted({u["ua"] for u in c["user_agents"] if u["category"] != "navegador_u_otro"})
    outside = ", ".join(f"{a}–{b}" for a, b in imp.get("invoice_id_ranges_outside_baseline", [])) or "ninguno"
    req = required_techniques(evidence_like(ctx))
    return ForensicDraft(
        attack_pattern=(
            f"{len(c['tokens'])} credenciales válidas usadas desde {len(c['ips'])} IPs consultaron "
            f"{imp['unique_invoices_2xx']:,} {p.object_label_plural} distintas con éxito; "
            f"{imp['unique_invoices_2xx_outside_baseline']:,} nunca aparecen en el tráfico legítimo. "
            f"Escalada en fases: {phase_txt}."
        ),
        reasoning=[
            f"Una credencial legítima suele consultar solo sus {p.object_label_plural}; aquí {len(c['tokens'])} "
            f"credenciales obtuvieron {imp['unique_invoices_2xx']:,} distintas → compatible con falta de autorización "
            "a nivel de objeto (IDOR); se demuestra solo con ownership",
            f"Consultas a IDs fuera del rango legítimo ({outside}) → enumeración del espacio de IDs",
            f"Volumen diario constante por fase y UA de herramientas ({', '.join(tools)}) → automatización",
            "Fase inicial con 0 % de éxito seguida de éxito → reconocimiento antes de la extracción masiva"
            if phases and phases[0]["success_ratio"] == 0
            else "Éxito desde el inicio → el atacante ya conocía el endpoint",
        ],
        campaigns_assessment=(
            f"1 campaña {'corroborada' if _corroborated(ctx) else 'de alta confianza, sin corroborar'} "
            f"({c['id']}: {len(c['ips'])} IPs, {len(c['tokens'])} credenciales)"
            + (
                f" y {len(pending)} por validar ({', '.join(x['id'] for x in pending)}): confirmar con los "
                "responsables si es actividad interna autorizada (p. ej. pruebas) antes de actuar"
                if pending
                else ""
            )
        ),
        mitre=[MitreChoice(technique_id=r.id, justification=r.justification) for r in req],
        open_questions=[
            "¿Cómo obtuvo el atacante las credenciales (phishing, credential stuffing, registro de cuentas)?",
            f"¿Existen logs anteriores a {start} que muestren el inicio real?",
        ],
    )


# --------------------------------------------------------------------------- Response
def candidate_actions(ctx: dict[str, Any]) -> list[ResponseAction]:
    """Acciones candidatas que arma el código; el modelo solo las ordena y justifica (punto 7).

    Obligatorias (punto 2), según la evidencia:
    - hipótesis sin corroborar → CORROBORAR con la aplicación (ownership, logs de autorización, reproducción);
    - campaña priorizada → rate limit, regla WAF, bloqueo de IPs, revocación de tokens, monitoreo y fix del IDOR
      (contención proporcional: lo reversible es automático; lo de impacto, con aprobación humana);
    - campaña por validar → SOLO validarla con AppSec/QA (nunca bloqueo);
    - objetos con datos personales potencialmente expuestos → Legal/Privacidad, condicionado a corroboración
      (la política bloquea la ejecución mientras el impacto no esté confirmado).
    """
    confirmed, pending = _confirmed(ctx), _pending(ctx)
    p = _profile(ctx)
    actions: list[ResponseAction] = []

    def add(mandatory: bool, reason: str, **kw: Any) -> None:
        actions.append(
            ResponseAction(action_id=f"A{len(actions) + 1}", mandatory=mandatory, reason_required=reason, **kw)
        )

    for c in confirmed:
        if c["status"] != STATUS_CORROBORATED:
            add(True, f"{c['id']} sin corroborar", action_type="corroborate",
                target=f"{c['id']}: ownership de {p.object_label_plural} con 2xx, logs de autorización y reproducción",
                priority=1, phase="inmediata",
                rationale="Convierte la hipótesis en hecho o la descarta; sin esto no hay impacto confirmado",
                false_positive_risk="bajo", business_impact="bajo", requires_human_approval=False)  # fmt: skip
        why = f"{c['id']} priorizada"
        add(True, why, action_type="rate_limit", target=f"{c['id']}: {', '.join(c['ips'])}", priority=1,
            phase="inmediata", rationale="Reduce de inmediato la extracción; reversible y solo afecta a la campaña",
            false_positive_risk="bajo", business_impact="bajo", requires_human_approval=False)  # fmt: skip
        add(True, why, action_type="waf_rule", target=f"{c['id']}: UA de herramientas en {p.endpoint}", priority=2,
            phase="inmediata", rationale="UA vistos solo en tráfico de ataque: falso positivo prácticamente nulo",
            false_positive_risk="bajo", business_impact="bajo", requires_human_approval=False)  # fmt: skip
        add(True, why, action_type="block_ip", target=f"{c['id']}: {', '.join(c['ips'])}", priority=3,
            phase="inmediata", rationale="Corta la infraestructura del atacante; todas las IPs de la campaña a la vez",
            false_positive_risk="medio", business_impact="bajo", requires_human_approval=True)  # fmt: skip
        add(True, why, action_type="revoke_token", target=f"{c['id']}: {', '.join(c['tokens'])}", priority=4,
            phase="inmediata", rationale="Invalida las credenciales usadas; sus titulares pueden ser víctimas",
            false_positive_risk="bajo", business_impact="medio", requires_human_approval=True)  # fmt: skip
    if confirmed:
        add(True, "campaña priorizada", action_type="monitoring",
            target=f"{p.endpoint}: credenciales con > 50 {p.object_param} distintos/día o > 3 IPs", priority=5,
            phase="inmediata", rationale="Detecta reincidencia o nuevas cuentas durante la contención",
            false_positive_risk="bajo", business_impact="bajo", requires_human_approval=False)  # fmt: skip
    for c in pending:
        add(True, f"{c['id']} por validar", action_type="notify",
            target=f"{c['id']}: validar con AppSec/QA si la actividad es interna/autorizada", priority=6,
            phase="inmediata", rationale="Confirmar si es una prueba autorizada antes de cualquier acción técnica",
            false_positive_risk="alto", business_impact="bajo", requires_human_approval=True)  # fmt: skip
    if confirmed:
        add(True, "campaña priorizada", action_type="fix_idor",
            target=f"{p.endpoint}: autorización a nivel de objeto ({p.object_label}.owner == token.owner"
            + (f" y {p.scope_param})" if p.scope_param else ")"), priority=7,
            phase="estrategica", rationale="Elimina la causa raíz (OWASP API1: Broken Object Level Authorization)",
            false_positive_risk="bajo", business_impact="medio", requires_human_approval=True)  # fmt: skip
        add(False, "", action_type="rotate_tokens",
            target=f"Todas las credenciales {p.token_param}; TTL corto y fuera de la URL (cabecera)", priority=8,
            phase="estrategica", rationale="La credencial viaja en la query string (queda en logs y proxies)",
            false_positive_risk="bajo", business_impact="alto", requires_human_approval=True)  # fmt: skip
        exposed = sum(c["impact"].get("unique_invoices_2xx", 0) for c in confirmed)
        if exposed:
            add(True, "datos personales potencialmente expuestos", action_type="notify",
                target=f"Legal/Privacidad: evaluar notificación por exposición de {p.object_label_plural}", priority=9,
                phase="estrategica", rationale=f"Hasta {exposed:,} {p.object_label_plural} potencialmente expuestas: "
                "posible obligación regulatoria; requiere impacto corroborado",
                false_positive_risk="bajo", business_impact="alto", requires_human_approval=True)  # fmt: skip
    return actions


def response_draft(ctx: dict[str, Any], candidates: list[ResponseAction]) -> ResponseDraft:
    pending = _pending(ctx)
    return ResponseDraft(
        ranking=[ActionRank(action_id=a.action_id, rationale=a.rationale) for a in candidates],
        playbook=[
            "1. Corroborar con la aplicación (ownership, logs de autorización, reproducción) y, en paralelo, aplicar "
            "rate limiting y regla WAF (automático, dry-run) con monitoreo intensificado",
            "2. Aprobar el bloqueo de TODAS las IPs y la revocación de las credenciales de la campaña priorizada",
            "3. Validar con AppSec/QA las campañas por validar antes de cualquier acción técnica"
            if pending
            else "3. Verificar que no haya actividad residual",
            "4. Contactar a los titulares de las cuentas usadas y forzar reautenticación",
            "5. Desplegar el fix de autorización a nivel de objeto y pruebas de regresión",
            "6. Notificar (Legal/Privacidad) solo con el impacto corroborado por titular",
        ],
        ordering_rationale="Primero lo reversible y de bajo riesgo que frena la extracción, luego lo que requiere "
        "aprobación por su impacto en usuarios, y al final los cambios estructurales y la notificación.",
    )


# --------------------------------------------------------------------------- compatibilidad (sin LLM)
def triage(ctx: dict[str, Any]) -> TriageOutput:
    from idor_ir.agents.assembly import assemble_triage

    return assemble_triage(triage_draft(ctx), ctx)


def forensic(ctx: dict[str, Any], tri: TriageOutput | None = None) -> ForensicOutput:
    from idor_ir.agents.assembly import assemble_forensic

    return assemble_forensic(forensic_draft(ctx, tri), ctx)[0]


def response(ctx: dict[str, Any], tri: TriageOutput | None = None, fo: ForensicOutput | None = None) -> ResponseOutput:
    from idor_ir.agents.assembly import assemble_response

    candidates = candidate_actions(ctx)
    return assemble_response(response_draft(ctx, candidates), candidates)
