"""Política de automatización vs aprobación humana y validación de salidas del LLM [R10, R11, R13].

La decisión final NO la toma el LLM: el agente propone y esta política, escrita en código y auditable,
puede ENDURECER (nunca relajar) el requisito de aprobación. Así un modelo equivocado o manipulado
por prompt injection no puede auto-aprobar una acción de alto impacto.

Criterio (explicable en la presentación):
| Acción                      | Modo por defecto | Evidencia mínima   | Motivo                                       |
|-----------------------------|------------------|--------------------|----------------------------------------------|
| corroborate                 | automática       | señal              | Solo pide datos a la aplicación; sin impacto |
| monitoring                  | automática       | señal              | Sin impacto en usuarios; reversible          |
| rate_limit (IPs priorizadas)| automática       | señal              | Reversible, degrada solo a esas IPs          |
| waf_rule (UA exclusivos)    | automática       | señal              | UA vistos solo en ese tráfico: FP ~0         |
| block_ip                    | aprobación       | hipótesis          | IP compartida/NAT puede afectar a clientes   |
| revoke_token                | aprobación       | hipótesis          | La cuenta puede ser víctima                  |
| rotate_tokens / fix_idor    | aprobación       | hipótesis          | Cambio global / de código                    |
| notify (legal/regulatorio)  | aprobación       | impacto confirmado | Decisión legal: exige impacto corroborado    |
Además requiere aprobación cualquier acción con riesgo de FP o impacto de negocio distinto de "bajo",
o que apunte a una campaña "por_validar". Si la evidencia no alcanza el mínimo, la acción queda CONDICIONADA:
se recomienda y se documenta, pero no se ejecuta aunque se apruebe.

Ciclo de vida que reporta el servicio: recomendada → (automática | aprobada | rechazada | condicionada) →
ejecutada en dry-run | no ejecutada. La ejecución real no existe en el MVP.
"""

from __future__ import annotations

import re
from typing import Any

from idor_ir.agents.schemas import MITRE_CATALOG, ForensicOutput, ResponseAction, ResponseOutput

ALWAYS_APPROVAL = {"block_ip", "revoke_token", "rotate_tokens", "fix_idor", "notify"}
AUTOMATABLE = {"corroborate", "monitoring", "rate_limit", "waf_rule"}
EVIDENCE_ORDER = ["señal", "hipótesis", "impacto confirmado"]
EVIDENCE_REQUIRED = {
    "corroborate": "señal",
    "monitoring": "señal",
    "rate_limit": "señal",
    "waf_rule": "señal",
    "block_ip": "hipótesis",
    "revoke_token": "hipótesis",
    "rotate_tokens": "hipótesis",
    "fix_idor": "hipótesis",
    "notify": "impacto confirmado",
}


def _rank(level: str) -> int:
    return EVIDENCE_ORDER.index(level) if level in EVIDENCE_ORDER else 1


def apply_policy(
    response: ResponseOutput, pending_campaigns: set[str], evidence_level: str = "hipótesis"
) -> tuple[ResponseOutput, list[dict[str, Any]]]:
    """Devuelve las acciones con la aprobación endurecida y la lista de cambios aplicados (auditoría).

    Las validaciones con AppSec/QA de campañas por validar son `notify` internos: no exigen impacto confirmado.
    """
    overrides: list[dict[str, Any]] = []
    fixed: list[ResponseAction] = []
    for action in response.actions:
        required_level = EVIDENCE_REQUIRED.get(action.action_type, "hipótesis")
        internal_validation = action.action_type == "notify" and any(
            re.search(rf"\b{re.escape(cid)}\b", action.target) for cid in pending_campaigns
        )
        if internal_validation:
            required_level = "señal"
        blocked = (
            f"exige evidencia «{required_level}» y la actual es «{evidence_level}»: corroborar antes de ejecutar"
            if _rank(evidence_level) < _rank(required_level)
            else ""
        )
        reasons = []
        if action.action_type in ALWAYS_APPROVAL:
            reasons.append(f"'{action.action_type}' siempre requiere aprobación")
        if action.false_positive_risk != "bajo":
            reasons.append(f"riesgo de falso positivo {action.false_positive_risk}")
        if action.business_impact != "bajo":
            reasons.append(f"impacto de negocio {action.business_impact}")
        if any(re.search(rf"\b{re.escape(cid)}\b", action.target) for cid in pending_campaigns):
            reasons.append("apunta a una campaña por validar")
        if blocked:
            reasons.append(blocked)
        required = bool(reasons) or action.requires_human_approval
        if required and not action.requires_human_approval:
            overrides.append({"action_id": action.action_id, "from": False, "to": True, "reasons": reasons})
        if blocked:
            overrides.append({"action_id": action.action_id, "blocked": True, "reasons": [blocked]})
        fixed.append(
            action.model_copy(
                update={
                    "requires_human_approval": required,
                    "evidence_required": required_level,
                    "blocked_reason": blocked,
                }
            )
        )
    return response.model_copy(update={"actions": fixed}), overrides


def verify_mitre(forensic: ForensicOutput) -> ForensicOutput:
    """Marca qué técnicas existen en el catálogo y normaliza su nombre."""
    checked = []
    for m in forensic.mitre_attack:
        known = MITRE_CATALOG.get(m.technique_id)
        checked.append(m.model_copy(update={"verified_in_catalog": known is not None, "name": known or m.name}))
    return forensic.model_copy(update={"mitre_attack": checked})
