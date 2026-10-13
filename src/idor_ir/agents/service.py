"""Servicio que ejecuta los agentes sobre un run ya analizado y persiste resultados verificables.

Artefactos en `output/<run>/agents/`:
- agents_report.json   salida de los 3 agentes, overrides de política, aprobaciones, ejecución, métricas
- decision_log.jsonl   una línea por decisión (nodo, fuente llm/fallback/humano, latencia, resultado)
- playbook.md          mini-playbook legible
- actions/*.txt        artefactos de contención en dry-run
- manifest.json        hashes de todo lo anterior (+ evento en el registro de custodia)

Reejecución atómica: todo se escribe primero en una carpeta temporal del run y solo al terminar con éxito reemplaza
los artefactos anteriores. Si la ejecución falla, el informe y las acciones previas quedan intactos y coherentes, y
se registra `agents_failed` en la cadena de custodia.
"""

from __future__ import annotations

import json
import shutil
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import polars as pl

from idor_ir.agents.context import build_context
from idor_ir.agents.estimates import backtest_rules, estimate_response_times
from idor_ir.agents.graph import build_graph, run_graph
from idor_ir.agents.llm import LLMClient
from idor_ir.config import Settings
from idor_ir.forensics.assessment import is_priority
from idor_ir.forensics.integrity import CustodyLog, FileFingerprint, IntegrityManifest, atomic_write_text
from idor_ir.profile import IncidentProfile

Decider = Callable[[dict[str, Any]], dict[str, str]]


def approve_all(payload: dict[str, Any]) -> dict[str, str]:
    return {a["action_id"]: "approve" for a in payload["pending_actions"]}


def reject_all(payload: dict[str, Any]) -> dict[str, str]:
    return {a["action_id"]: "reject" for a in payload["pending_actions"]}


def run_agents(
    run_dir: Path,
    settings: Settings,
    llm: LLMClient | None,
    decide: Decider,
    on_event: Callable[[str, dict[str, Any]], None] | None = None,
    llm_meta: dict[str, Any] | None = None,
    started_by: dict[str, str] | None = None,
    decided_by: Callable[[], dict[str, str] | None] | None = None,
) -> dict[str, Any]:
    """`llm_meta`: proveedor, si el contexto salió de la LAN y el consentimiento del analista (gobierno de datos).

    `started_by` / `decided_by`: identidad (usuario y rol) de quien ejecutó los agentes y de quien decidió las
    aprobaciones; quedan en el reporte y en la cadena de custodia (separación recomendación / decisión)."""
    evidence = json.loads((run_dir / "evidence.json").read_text(encoding="utf-8"))
    metrics_path = run_dir / "metrics.json"
    metrics = json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.is_file() else None
    manifest_run = IntegrityManifest.model_validate_json((run_dir / "manifest.json").read_text(encoding="utf-8"))

    out_dir = run_dir / "agents"
    custody = CustodyLog(settings.output_dir / "custody_log.jsonl")
    staging = run_dir / f".agents-staging-{uuid.uuid4().hex[:8]}"
    staging.mkdir(parents=True)
    try:
        report, manifest = _run_and_write(
            run_dir, staging, evidence, metrics, manifest_run, llm, decide, on_event, llm_meta,
            started_by, decided_by,
        )  # fmt: skip
    except BaseException as exc:
        shutil.rmtree(staging, ignore_errors=True)
        custody.append("agents_failed", {"run_id": run_dir.name, "error_type": type(exc).__name__})
        raise
    _promote(staging, out_dir)
    decider = decided_by() if decided_by else None
    custody.append(
        "agents_completed",
        {
            "run_id": run_dir.name,
            "llm": report["llm"],
            "llm_data_egress": report["llm_data_egress"],
            "started_by": started_by,
            "approvals": report["approvals"],
            "approvals_decided_by": decider,
            "artifacts": [a.model_dump() for a in manifest.artifacts],
        },
    )
    return report


_PROMOTED = ("agents_report.json", "decision_log.jsonl", "playbook.md", "manifest.json", "actions")


def _promote(staging: Path, out_dir: Path) -> None:
    """Reemplaza los artefactos anteriores por los nuevos; conserva `chats/` y lo demás de la carpeta."""
    out_dir.mkdir(parents=True, exist_ok=True)
    backup = staging.with_name(staging.name.replace("staging", "previous"))
    backup.mkdir()
    try:
        for name in _PROMOTED:
            if (out_dir / name).exists():
                (out_dir / name).rename(backup / name)
        for name in _PROMOTED:
            if (staging / name).exists():
                (staging / name).rename(out_dir / name)
    except OSError:
        for name in _PROMOTED:  # restaura lo anterior si el reemplazo quedó a medias
            if (backup / name).exists() and not (out_dir / name).exists():
                (backup / name).rename(out_dir / name)
        raise
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    shutil.rmtree(backup, ignore_errors=True)


def action_lifecycle(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Separa recomendación, decisión y ejecución de cada acción (la ejecución real no existe en el MVP)."""
    approvals = report.get("approvals", {})
    executed = {e["action_id"] for e in report.get("executed", [])}
    out = []
    for a in (report.get("response") or {}).get("actions", []):
        aid = a["action_id"]
        if not a.get("requires_human_approval"):
            decision = "automática (sin aprobación)"
        else:
            decision = {"approve": "aprobada", "reject": "rechazada"}.get(approvals.get(aid, ""), "sin decisión")
        if a.get("blocked_reason"):
            execution = "condicionada: " + a["blocked_reason"]
        elif aid in executed:
            execution = "ejecutada en dry-run (artefacto revisable, NO aplicado)"
        else:
            execution = "no ejecutada"
        out.append(
            {
                "action_id": aid,
                "action_type": a["action_type"],
                "recomendada_por": "política" if a.get("added_by_policy") else "agente (candidata del código)",
                "evidencia_requerida": a.get("evidence_required", "señal"),
                "decision": decision,
                "decidida_por": (report.get("approvals_decided_by") or {}).get("user")
                if a.get("requires_human_approval") and aid in approvals
                else None,
                "ejecucion": execution,
                "ejecucion_real": "no soportada en el MVP",
            }
        )
    return out


def _run_and_write(
    run_dir: Path,
    out_dir: Path,
    evidence: dict[str, Any],
    metrics: dict[str, Any] | None,
    manifest_run: IntegrityManifest,
    llm: LLMClient | None,
    decide: Decider,
    on_event: Callable[[str, dict[str, Any]], None] | None,
    llm_meta: dict[str, Any] | None,
    started_by: dict[str, str] | None = None,
    decided_by: Callable[[], dict[str, str] | None] | None = None,
) -> tuple[dict[str, Any], IntegrityManifest]:
    context = build_context(evidence, metrics)
    graph = build_graph(llm, evidence, out_dir / "actions", dry_run=True)

    started = time.perf_counter()
    state = run_graph(graph, context, thread_id=run_dir.name, decide=decide, on_event=on_event)
    agents_s = time.perf_counter() - started

    # Backtest de reglas con las credenciales de las campañas priorizadas. El Parquet guarda la huella de cada
    # credencial; los runs anteriores a ese cambio guardaban el token, que se toma de sensitive/token_map.json.
    priority_fps = [t["fingerprint"] for c in evidence["campaigns"] if is_priority(c) for t in c["tokens"]]
    token_map_path = run_dir / "sensitive" / "token_map.json"
    token_map: dict[str, str] = (
        json.loads(token_map_path.read_text(encoding="utf-8")) if token_map_path.is_file() else {}
    )
    keys = priority_fps + [token_map[fp] for fp in priority_fps if fp in token_map]
    lf = pl.scan_parquet(run_dir / "work" / "parsed.parquet")
    backtest = backtest_rules(lf, keys, profile=IncidentProfile.from_evidence(evidence)) if priority_fps else {}

    pipeline_s = float(manifest_run.parameters.get("pipeline_seconds", 0) or 0)
    estimates = estimate_response_times(pipeline_s + agents_s, evidence.get("response_metrics", {}))
    estimates["detection_backtest"] = backtest

    report = {
        "run_id": run_dir.name,
        "llm": getattr(llm, "name", None) or "deterministic",
        "llm_data_egress": llm_meta or {"provider": "ollama" if llm else None, "off_lan": False},
        "status": state.get("status"),
        "triage": state.get("triage"),
        "forensic": state.get("forensic"),
        "response": state.get("response"),
        "policy_overrides": state.get("policy_overrides", []),
        "approvals": state.get("approvals", {}),
        "started_by": started_by,
        "approvals_decided_by": decided_by() if decided_by else None,
        "executed": state.get("executed", []),
        "evidence_level": (evidence.get("assessment") or {}).get("level", "hipótesis"),
        "response_time_estimates": estimates,
        "agents_seconds": round(agents_s, 1),
        "decision_log_summary": [
            {k: e.get(k) for k in ("node", "source", "latency_s", "error", "unverified_numbers", "fix_calls", "checks")}
            for e in state.get("decision_log", [])
            if e.get("node") in {"triage", "forensic", "response"}
        ],
    }
    report["action_lifecycle"] = action_lifecycle(report)
    manifest = IntegrityManifest(run_id=run_dir.name + "-agents", source=FileFingerprint.of(run_dir / "evidence.json"))
    _write(
        out_dir / "agents_report.json", json.dumps(report, indent=2, ensure_ascii=False, default=str), manifest, out_dir
    )
    _write(
        out_dir / "decision_log.jsonl",
        "".join(json.dumps(e, ensure_ascii=False, default=str) + "\n" for e in state.get("decision_log", [])),
        manifest,
        out_dir,
    )
    _write(out_dir / "playbook.md", render_playbook(report), manifest, out_dir)
    for item in state.get("executed", []):
        manifest.add_artifact(out_dir / item["artifact"], base=out_dir)
    manifest.save(out_dir / "manifest.json")
    return report, manifest


def _write(path: Path, content: str, manifest: IntegrityManifest, base: Path) -> None:
    atomic_write_text(path, content)
    manifest.add_artifact(path, base=base)


def render_playbook(report: dict[str, Any]) -> str:
    tri, fo, ro = report.get("triage") or {}, report.get("forensic") or {}, report.get("response") or {}
    lines = [
        f"# Mini-playbook — run {report['run_id']}",
        "",
        f"*Generado por: {report['llm']} · Todas las acciones en modo DRY-RUN · Nivel de evidencia: "
        f"{report.get('evidence_level', 'hipótesis')}*",
        "",
        f"**Severidad:** {tri.get('severity')} · **Tipo:** {tri.get('attack_type')}",
        "",
        "## Pasos",
        *[f"- {p}" for p in ro.get("playbook", [])],
        "",
        "## Acciones",
        "| ID | Tipo | Fase | Prioridad | Evidencia exigida | Decisión | Ejecución | Objetivo |",
        "|---|---|---|---|---|---|---|---|",
    ]
    lifecycle = {x["action_id"]: x for x in report.get("action_lifecycle") or action_lifecycle(report)}
    for a in ro.get("actions", []):
        lc = lifecycle.get(a["action_id"], {})
        lines.append(
            f"| {a['action_id']} | {a['action_type']} | {a['phase']} | {a['priority']} | "
            f"{lc.get('evidencia_requerida', '')} | {lc.get('decision', '')} | {lc.get('ejecucion', '')[:70]} | "
            f"{a['target'][:80]} |"
        )
    lines += ["", f"**Orden:** {ro.get('ordering_rationale', '')}", "", "## MITRE ATT&CK"]
    lines += [
        f"- {m['technique_id']} {m['name']} ({m['tactic']}; {m.get('source', 'modelo')}): {m['justification']}"
        for m in fo.get("mitre_attack", [])
    ]
    est = report.get("response_time_estimates", {})
    if est:
        lines += [
            "",
            "## Tiempos de respuesta (estimación)",
            f"- TTD {'estimado hasta el fin del log' if est.get('ttd_is_estimate') else 'medido'}: "
            f"{est.get('ttd_days_measured')} días",
            f"- TTR manual {est['manual']['ttr_hours']} h vs automatizado {est['automated']['ttr_hours']} h "
            f"(-{est['reduction']['ttr_percent']} %)",
            f"- TTC manual {est['manual']['ttc_hours']} h vs automatizado {est['automated']['ttc_hours']} h "
            f"(-{est['reduction']['ttc_percent']} %)",
        ]
    return "\n".join(lines) + "\n"
