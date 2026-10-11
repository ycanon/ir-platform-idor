"""Política de automatización vs aprobación humana y validación de salidas del LLM [R10, R11, R13].

La decisión final NO la toma el LLM: el agente propone y esta política, escrita en código y auditable,
puede ENDURECER (nunca relajar) el requisito de aprobación. Así un modelo equivocado o manipulado
por prompt injection no puede auto-aprobar una acción de alto impacto.

Criterio (explicable en la presentación):
| Acción                      | Modo por defecto | Motivo                                                     |
|-----------------------------|------------------|------------------------------------------------------------|
| monitoring                  | automática       | Sin impacto en usuarios; reversible                        |
| rate_limit (IPs confirmadas)| automática       | Reversible, degrada solo al atacante, bajo riesgo de FP    |
| waf_rule (UA exclusivos)    | automática       | UA vistos solo en tráfico de ataque: FP ~0                 |
| block_ip                    | aprobación       | IP compartida/NAT puede afectar clientes legítimos         |
| revoke_token                | aprobación       | La cuenta puede ser víctima; impacto directo en el usuario |
| rotate_tokens / fix_idor    | aprobación       | Cambio global / cambio de código (gestión de cambios)      |
| notify (legal/regulatorio)  | aprobación       | Decisión de negocio y legal                                |
Además requiere aprobación cualquier acción con riesgo de FP o impacto de negocio distinto de "bajo",
o que apunte a una campaña "por_validar".
"""

from __future__ import annotations

import re
from typing import Any

from idor_ir.agents.schemas import MITRE_CATALOG, ForensicOutput, ResponseAction, ResponseOutput

ALWAYS_APPROVAL = {"block_ip", "revoke_token", "rotate_tokens", "fix_idor", "notify"}
AUTOMATABLE = {"monitoring", "rate_limit", "waf_rule"}


def apply_policy(response: ResponseOutput, pending_campaigns: set[str]) -> tuple[ResponseOutput, list[dict[str, Any]]]:
    """Devuelve las acciones con la aprobación endurecida y la lista de cambios aplicados (auditoría)."""
    overrides: list[dict[str, Any]] = []
    fixed: list[ResponseAction] = []
    for action in response.actions:
        reasons = []
        if action.action_type in ALWAYS_APPROVAL:
            reasons.append(f"'{action.action_type}' siempre requiere aprobación")
        if action.false_positive_risk != "bajo":
            reasons.append(f"riesgo de falso positivo {action.false_positive_risk}")
        if action.business_impact != "bajo":
            reasons.append(f"impacto de negocio {action.business_impact}")
        if any(re.search(rf"\b{re.escape(cid)}\b", action.target) for cid in pending_campaigns):
            reasons.append("apunta a una campaña por validar")
        required = bool(reasons) or action.requires_human_approval
        if required and not action.requires_human_approval:
            overrides.append({"action_id": action.action_id, "from": False, "to": True, "reasons": reasons})
        fixed.append(action.model_copy(update={"requires_human_approval": required}))
    return response.model_copy(update={"actions": fixed}), overrides


def verify_mitre(forensic: ForensicOutput) -> ForensicOutput:
    """Marca qué técnicas existen en el catálogo y normaliza su nombre."""
    checked = []
    for m in forensic.mitre_attack:
        known = MITRE_CATALOG.get(m.technique_id)
        checked.append(m.model_copy(update={"verified_in_catalog": known is not None, "name": known or m.name}))
    return forensic.model_copy(update={"mitre_attack": checked})
