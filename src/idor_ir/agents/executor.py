"""Ejecutor de contención en modo DRY-RUN [R11].

No ejecuta nada contra sistemas reales: genera los artefactos que se aplicarían (listas de bloqueo,
reglas WAF, consultas de monitoreo, lista de revocación, tickets) para revisión.

Seguridad: los objetivos concretos (IPs, UA, tokens) se toman de la EVIDENCIA, no del texto libre del
LLM. Una IP solo se incluye si está en los IOCs del análisis; así una salida alucinada o inyectada no
puede convertir una IP arbitraria en una regla de bloqueo.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from idor_ir.agents.schemas import ResponseAction
from idor_ir.forensics.integrity import atomic_write_text
from idor_ir.profile import IncidentProfile

HEADER = "# DRY-RUN — artefacto generado para revisión; NO fue aplicado a ningún sistema.\n"
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class LiveExecutionNotSupported(RuntimeError):
    """El MVP no implementa ejecución real (decisión explícita)."""


def _campaigns_for(action: ResponseAction, evidence: dict[str, Any]) -> list[dict[str, Any]]:
    ids = set(re.findall(r"\bC\d+\b", action.target))
    camps = evidence.get("campaigns", [])
    chosen = [c for c in camps if c["campaign_id"] in ids]
    return chosen or [c for c in camps if c["status"] == "confirmada"]


def _known_ips(evidence: dict[str, Any]) -> set[str]:
    return {i["value"] for i in evidence.get("iocs", {}).get("ips", [])}


def execute(
    actions: list[ResponseAction], evidence: dict[str, Any], out_dir: Path, dry_run: bool = True
) -> list[dict[str, Any]]:
    if not dry_run:
        raise LiveExecutionNotSupported("La ejecución real no está implementada en el MVP; use dry_run=True.")
    out_dir.mkdir(parents=True, exist_ok=True)
    results = []
    known = _known_ips(evidence)
    for action in actions:
        camps = _campaigns_for(action, evidence)
        path = out_dir / f"{action.action_id}_{action.action_type}.txt"
        body, targets = _render(action, camps, known, evidence)
        atomic_write_text(
            path, HEADER + f"# Acción {action.action_id} ({action.action_type}) — {action.target}\n\n" + body
        )
        results.append(
            {
                "action_id": action.action_id,
                "action_type": action.action_type,
                "dry_run": True,
                "artifact": f"actions/{path.name}",
                "resolved_targets": targets,
            }
        )
    return results


def _render(
    action: ResponseAction, camps: list[dict[str, Any]], known: set[str], evidence: dict[str, Any]
) -> tuple[str, list[str]]:
    prof = IncidentProfile.from_evidence(evidence)
    ips = sorted({ip for c in camps for ip in c["ips"]} | (set(_IP_RE.findall(action.target)) & known))
    t = action.action_type
    if t == "block_ip":
        return "\n".join(f"deny {ip};   # nginx" for ip in ips) + "\n", ips
    if t == "rate_limit":
        rules = "\n".join(f"  {ip} 1;" for ip in ips)
        conf = (
            "geo $idor_suspect {\n  default 0;\n" + rules + "\n}\n"
            'map $idor_suspect $idor_key { 0 ""; 1 $binary_remote_addr; }\n'
            "limit_req_zone $idor_key zone=idor:10m rate=5r/m;\n"
            f"location = {prof.endpoint} {{ limit_req zone=idor burst=5 nodelay; }}\n"
        )
        return conf, ips
    if t == "waf_rule":
        uas = sorted({u["user_agent"] for c in camps for u in c["user_agents"] if u["category"] != "navegador_u_otro"})
        tokens = " ".join(re.escape(ua.split("/")[0].split(" ")[0]) for ua in uas)
        rule = (
            f'SecRule REQUEST_FILENAME "@streq {prof.endpoint}" "id:900101,phase:1,chain,deny,status:403,'
            f'msg:\'IDOR campaign automation UA\'"\n  SecRule REQUEST_HEADERS:User-Agent "@pm {tokens}"\n'
        )
        return rule, uas
    if t == "revoke_token":
        toks = [f"{tk['fingerprint']}  ({tk['hint']})" for c in camps for tk in c["tokens"]]
        note = "Valores completos: sensitive/token_map.json (acceso restringido). Notificar a los titulares.\n"
        return note + "\n".join(toks) + "\n", [tk["fingerprint"] for c in camps for tk in c["tokens"]]
    if t == "monitoring":
        query = (
            f"index=web uri_path={prof.endpoint} earliest=-24h\n"
            f"| stats dc({prof.object_param}) as objects dc(src_ip) as ips by {prof.token_param}\n"
            "| where objects > 50 OR ips > 3\n"
        )
        return "Alerta SIEM (pseudo-SPL):\n" + query, [prof.endpoint]
    # fix_idor, rotate_tokens, notify -> ticket de cambio / comunicación
    return (
        f"Ticket: {action.action_type}\nPrioridad: {action.priority} ({action.phase})\nObjetivo: {action.target}\n"
        f"Justificación: {action.rationale}\nImpacto de negocio: {action.business_impact}\n",
        [action.target],
    )
