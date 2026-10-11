"""Servicio que ejecuta los agentes sobre un run ya analizado y persiste resultados verificables.

Artefactos en `output/<run>/agents/`:
- agents_report.json   salida de los 3 agentes, overrides de política, aprobaciones, ejecución, métricas
- decision_log.jsonl   una línea por decisión (nodo, fuente llm/fallback/humano, latencia, resultado)
- playbook.md          mini-playbook legible
- actions/*.txt        artefactos de contención en dry-run
- manifest.json        hashes de todo lo anterior (+ evento en el registro de custodia)
"""

from __future__ import annotations

import json
import shutil
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import polars as pl

from idor_ir.agents.context import build_context
from idor_ir.agents.estimates import backtest_rules, estimate_response_times
from idor_ir.agents.graph import build_graph, run_graph
from idor_ir.agents.llm import LLMClient
from idor_ir.config import Settings
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
) -> dict[str, Any]:
    """`llm_meta`: proveedor, si el contexto salió de la LAN y el consentimiento del analista (gobierno de datos)."""
    evidence = json.loads((run_dir / "evidence.json").read_text(encoding="utf-8"))
    metrics_path = run_dir / "metrics.json"
    metrics = json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.is_file() else None
    manifest_run = IntegrityManifest.model_validate_json((run_dir / "manifest.json").read_text(encoding="utf-8"))

    out_dir = run_dir / "agents"
    if (out_dir / "actions").is_dir():  # cada ejecución reemplaza los artefactos de la anterior
        shutil.rmtree(out_dir / "actions")
    context = build_context(evidence, metrics)
    graph = build_graph(llm, evidence, out_dir / "actions", dry_run=True)

    started = time.perf_counter()
    state = run_graph(graph, context, thread_id=run_dir.name, decide=decide, on_event=on_event)
    agents_s = time.perf_counter() - started

    # Backtest de reglas con los tokens de campañas confirmadas (valores completos solo en memoria).
    token_map_path = run_dir / "sensitive" / "token_map.json"
    token_map: dict[str, str] = (
        json.loads(token_map_path.read_text(encoding="utf-8")) if token_map_path.is_file() else {}
    )
    confirmed_fps = [
        t["fingerprint"] for c in evidence["campaigns"] if c["status"] == "confirmada" for t in c["tokens"]
    ]
    raw_tokens = [token_map[fp] for fp in confirmed_fps if fp in token_map]
    lf = pl.scan_parquet(run_dir / "work" / "parsed.parquet")
    backtest = backtest_rules(lf, raw_tokens, profile=IncidentProfile.from_evidence(evidence)) if raw_tokens else {}

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
        "executed": state.get("executed", []),
        "response_time_estimates": estimates,
        "agents_seconds": round(agents_s, 1),
        "decision_log_summary": [
            {k: e.get(k) for k in ("node", "source", "latency_s", "error", "unverified_numbers", "fix_calls", "checks")}
            for e in state.get("decision_log", [])
            if e.get("node") in {"triage", "forensic", "response"}
        ],
    }
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
    CustodyLog(settings.output_dir / "custody_log.jsonl").append(
        "agents_completed",
        {
            "run_id": run_dir.name,
            "llm": report["llm"],
            "llm_data_egress": report["llm_data_egress"],
            "approvals": report["approvals"],
            "artifacts": [a.model_dump() for a in manifest.artifacts],
        },
    )
    return report


def _write(path: Path, content: str, manifest: IntegrityManifest, base: Path) -> None:
    atomic_write_text(path, content)
    manifest.add_artifact(path, base=base)


def render_playbook(report: dict[str, Any]) -> str:
    tri, fo, ro = report.get("triage") or {}, report.get("forensic") or {}, report.get("response") or {}
    approvals = report.get("approvals", {})
    lines = [
        f"# Mini-playbook — run {report['run_id']}",
        "",
        f"*Generado por: {report['llm']} · Todas las acciones en modo DRY-RUN*",
        "",
        f"**Severidad:** {tri.get('severity')} · **Tipo:** {tri.get('attack_type')}",
        "",
        "## Pasos",
        *[f"- {p}" for p in ro.get("playbook", [])],
        "",
        "## Acciones",
        "| ID | Tipo | Fase | Prioridad | Aprobación | Decisión | Origen | Objetivo |",
        "|---|---|---|---|---|---|---|---|",
    ]
    executed = {e["action_id"] for e in report.get("executed", [])}
    for a in ro.get("actions", []):
        need = "humana" if a["requires_human_approval"] else "automática"
        decision = approvals.get(a["action_id"], "auto") if a["requires_human_approval"] else "auto"
        status = "ejecutada (dry-run)" if a["action_id"] in executed else "no ejecutada"
        lines.append(
            f"| {a['action_id']} | {a['action_type']} | {a['phase']} | {a['priority']} | {need} | "
            f"{decision} → {status} | {'agregada por política' if a.get('added_by_policy') else 'modelo'} | "
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
