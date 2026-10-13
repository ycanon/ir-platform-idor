"""Enriquecimiento de las IPs públicas del Top 20 a través del servidor MCP `ti-gateway` [SPECS O4, O10].

Reparto de responsabilidades:
- **ti-gateway** (paquete aparte, sin dependencias de este proyecto): habla con VirusTotal, OTX, AbuseIPDB,
  GreyNoise, IPinfo, Shodan y abuse.ch; aplica caché, cuotas, ritmo, veredicto por fuente y auditoría propia.
- **Este módulo** (lógica del caso): elige las IPs, exige la autorización del analista ANTES de llamar al
  gateway, genera `enrichment/ti_enrichment.json` con hash y registra el evento en la cadena de custodia del caso.

La reputación es la ACTUAL, no la de oct-dic 2020: es contexto, nunca prueba de atribución.
"""

from __future__ import annotations

import ipaddress
import json
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from idor_ir.config import Settings
from idor_ir.enrichment.gateway_client import GatewayError, GatewayLaunch, GatewaySession, run_with_gateway
from idor_ir.forensics.integrity import CustodyLog, FileFingerprint, IntegrityManifest, atomic_write_text

CAVEAT = (
    "Reputación ACTUAL consultada hoy, no la de oct-dic 2020: IPs residenciales o dinámicas pueden haber cambiado "
    "de usuario. Úsese como contexto, no como prueba de atribución."
)
VERDICT_RULE = (
    "Veredicto = nivel más grave entre las fuentes con reputación (malicioso > sospechoso > sin reportes > sin datos). "
    "IPinfo y Shodan aportan contexto ('informativo'). Las listas de confianza se señalan como posible falso positivo."
)
LEVELS = ("malicioso", "sospechoso", "sin reportes", "sin datos")


class TIError(RuntimeError):
    """Error de enriquecimiento con mensaje seguro para mostrar."""


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def select_ips(evidence: dict[str, Any], limit: int = 20) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Solo IPs públicas: una privada no tiene reputación externa y revelaría direccionamiento interno."""
    targets, skipped = [], []
    for row in evidence.get("top20_ips", [])[:limit]:
        ip = str(row.get("ip", ""))
        if is_public_ip(ip):
            targets.append(row)
        else:
            skipped.append({"ip": ip, "reason": "IP privada/reservada: no se envía a terceros"})
    return targets, skipped


def enrich_run(
    run_dir: Path,
    settings: Settings,
    launch: GatewayLaunch,
    sources: list[str],
    consent: dict[str, Any],
    on_progress: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Consulta `sources` en el gateway para las IPs públicas del Top 20 y guarda un artefacto con hash."""
    if not sources:
        raise TIError("Seleccione al menos una fuente")
    emit = on_progress or (lambda kind, data: None)
    evidence_path = run_dir / "evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    targets, skipped = select_ips(evidence)
    started = time.perf_counter()
    by = consent.get("by") or {}
    gateway_consent = {  # lo exige la herramienta MCP ti_lookup y queda en la auditoría del gateway
        "granted": bool(consent.get("confirmed")),
        "run_id": run_dir.name,
        "granted_by": f"{by.get('user', 'desconocido')} ({by.get('role', consent.get('via', 'web'))})"[:120],
        "purpose": "Reputación de IPs públicas del Top 20 del incidente (respuesta a incidentes)",
    }
    if not gateway_consent["granted"]:
        raise TIError("Falta la confirmación del envío de IPs a las fuentes externas")

    async def work(gw: GatewaySession) -> list[dict[str, Any]]:
        out = []
        for n, row in enumerate(targets, start=1):
            emit("lookup", {"ip": row["ip"], "n": n, "total": len(targets)})
            lookup = await gw.lookup(row["ip"], "ip", sources, gateway_consent)
            out.append(
                {
                    "ip": lookup["indicator"],
                    "rank": row.get("rank"),
                    "campaign_id": row.get("campaign_id"),
                    "risk_level": row.get("risk_level"),
                    "verdict": lookup["verdict"],
                    "verdict_reasons": lookup["reasons"],
                    "possible_false_positive": lookup["possible_false_positive"],
                    "context": lookup["context"],
                    "sources": lookup["sources"],
                    "sent_to": lookup["sent_to"],
                }
            )
            emit("ip_done", {"ip": row["ip"], "n": n, "total": len(targets), "verdict": lookup["verdict"]})
        return out

    try:
        results = run_with_gateway(launch, work) if targets else []
    except GatewayError as exc:
        raise TIError(str(exc)) from exc

    all_sources = [s for r in results for s in r["sources"]]
    stopped = {s["source"]: s["error"] for s in all_sources if s["status"] in ("quota", "error") and s.get("error")}
    report = {
        "run_id": run_dir.name,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "gateway": "ti-gateway (MCP, stdio)",
        "sources": sources,
        "caveat": CAVEAT,
        "verdict_rule": VERDICT_RULE,
        "consent": consent,
        "summary": {level: sum(1 for r in results if r["verdict"] == level) for level in LEVELS},
        "ips_sent": sorted({r["ip"] for r in results if r["sent_to"]}),
        "stats": {
            "queried": sum(len(r["sent_to"]) for r in results),
            "cached": sum(1 for s in all_sources if s.get("cached")),
            "errors": sum(1 for s in all_sources if s["status"] in ("quota", "error")),
            "seconds": round(time.perf_counter() - started, 1),
            "stopped": stopped,
        },
        "skipped": skipped,
        "results": results,
    }
    out_dir = run_dir / "enrichment"
    out_dir.mkdir(exist_ok=True)
    report_path = out_dir / "ti_enrichment.json"
    atomic_write_text(report_path, json.dumps(report, indent=2, ensure_ascii=False))
    manifest = IntegrityManifest(run_id=run_dir.name + "-ti", source=FileFingerprint.of(evidence_path))
    manifest.add_artifact(report_path, base=out_dir)
    manifest.save(out_dir / "manifest.json")
    CustodyLog(settings.output_dir / "custody_log.jsonl").append(
        "ti_enrichment",
        {
            "run_id": run_dir.name,
            "sources": sources,
            "ips_sent": report["ips_sent"],
            "consent": consent,
            "artifacts": [a.model_dump() for a in manifest.artifacts],
        },
    )
    return report
