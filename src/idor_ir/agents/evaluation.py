"""Banco de evaluación de los agentes y del chat [mejora O13, fase 3 · puntos 10 y 11].

Objetivo: que cada cambio de instrucciones o de modelo se MIDA en vez de juzgarse a ojo. Para un run analizado:
- **Chat**: ~15 preguntas con los hechos esperados sacados de SU evidencia (genérico: sirve para otros
  incidentes). Se puntúa: hechos presentes, frases prohibidas (p. ej. "sin autenticación" cuando todo fue
  autenticado), observaciones de la revisión automática (fechas fuera del log, IPs inexistentes, listas
  incompletas, atribuciones) y tiempo. Se evalúa al MODELO: las preguntas de dato no pasan por el atajo del chat
  híbrido (en producción esas las responde el código, al 100 %).
- **Agentes**: se ejecuta el flujo completo en una carpeta temporal (no toca el reporte del run) y se mide cuánto
  tuvo que corregir el código: obligatorias omitidas, justificaciones MITRE incoherentes, correcciones,
  observaciones abiertas, uso del fallback y tiempo por agente.
- **Comparación**: el mismo banco con varios modelos (p. ej. qwen3:4b vs qwen3:8b) → tabla.

Los reportes quedan en `output/<run>/evaluation/` (JSON + Markdown) con evento en la cadena de custodia.
"""

from __future__ import annotations

import json
import re
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from idor_ir.agents import chat
from idor_ir.agents.context import as_prompt_block, build_context
from idor_ir.agents.mitre import CATALOG, required_techniques
from idor_ir.agents.review import build_facts, review_text
from idor_ir.config import Settings
from idor_ir.forensics.integrity import CustodyLog, atomic_write_text
from idor_ir.profile import IncidentProfile

Progress = Callable[[str, str], None]


@dataclass
class Question:
    id: str
    agent: str
    text: str
    kind: str  # dato | criterio
    expect_all: list[str] = field(default_factory=list)  # deben aparecer TODOS
    expect_any: list[list[str]] = field(default_factory=list)  # de cada grupo, al menos uno
    forbid: list[str] = field(default_factory=list)  # regex que NO debe aparecer


def _fold(text: str) -> str:
    table = str.maketrans("áéíóúüñ", "aeiouun")
    return text.lower().translate(table)


def _plain_numbers(text: str) -> str:
    return re.sub(r"(?<=\d)[.,](?=\d{3}(?!\d))", "", text)


def _has(answer: str, token: str) -> bool:
    if re.fullmatch(r"\d+", token):
        return re.search(rf"(?<![\d.]){token}(?!\d)", _plain_numbers(answer)) is not None
    return _fold(token) in _fold(answer)


def question_bank(evidence: dict[str, Any]) -> list[Question]:
    """~15 preguntas con hechos esperados de la evidencia de ESTE run."""
    prof = IncidentProfile.from_evidence(evidence)
    objs = prof.object_label_plural
    camps = evidence.get("campaigns", [])
    conf = next((c for c in camps if c["status"] == "confirmada"), None)
    pend = next((c for c in camps if c["status"] != "confirmada"), None)
    rm = evidence.get("response_metrics", {})
    qs: list[Question] = []
    if conf is None:
        return qs
    cid, imp = conf["campaign_id"], conf["impact"]
    pz, es = conf.get("patient_zero") or {}, conf.get("exploitation_start") or {}
    authenticated = imp.get("success_2xx_with_token") and not imp.get("success_2xx_without_token")
    no_auth_claim = [r"sin autenticaci", r"no autenticad"] if authenticated else []
    sites = list((imp.get("unique_invoices_2xx_by_site") or {}).keys())
    required = [r.id for r in required_techniques(evidence)]

    def q(agent: str, text: str, kind: str, **kw: Any) -> None:
        qs.append(Question(id=f"Q{len(qs) + 1:02d}", agent=agent, text=text, kind=kind, **kw))

    q("triage", f"¿Cuántas IPs tiene {cid} y cuáles son?", "dato", expect_all=list(conf["ips"]))
    q(
        "triage",
        f"¿Cuántas {objs} únicas se obtuvieron con respuesta 2xx en {cid}?",
        "dato",
        expect_all=[str(imp["unique_invoices_2xx"])],
    )
    q("forensic", f"¿Cuándo ocurrió {cid}?", "dato", expect_all=[str(conf["first_seen"])[:7]])
    if es:
        q(
            "forensic",
            "¿Cuál fue el primer acceso exitoso y desde qué IP?",
            "dato",
            expect_all=[str(es.get("source_ip")), str(es.get("ts"))[:10]],
        )
    q(
        "forensic",
        "¿Quién fue el patient zero y cuándo?",
        "dato",
        expect_all=[str(pz.get("source_ip")), str(pz.get("ts"))[:10]],
    )
    if sites:
        q("triage", f"¿Qué {prof.scope_label}s fueron afectados y con cuántas {objs}?", "dato", expect_all=sites)
    if rm.get("ttd_from_first_malicious_request_days") is not None:
        ttd = rm["ttd_from_first_malicious_request_days"]
        q("response", "¿Cuál es el TTD del incidente?", "dato", expect_any=[[f"{ttd:g}", str(int(ttd))]])
    q(
        "triage",
        "¿Por qué clasificaste la severidad así?",
        "criterio",
        expect_any=[[str(imp["unique_invoices_2xx"]), str(imp["unique_invoices_2xx_outside_baseline"])]],
        forbid=no_auth_claim,
    )
    prio_any = [[cid], ["campaña", "campana"]] + ([["validar", "appsec", "qa"]] if pend else [])
    q("triage", "¿Qué IPs o campañas priorizarías primero y por qué?", "criterio", expect_any=prio_any)
    q(
        "forensic",
        "¿El acceso fue autenticado o sin autenticación? Explica.",
        "criterio",
        expect_any=[["autentic"], ["autoriz", "idor"]],
        forbid=no_auth_claim,
    )
    all_tactics = [
        "Reconnaissance",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Discovery",
        "Collection",
        "Exfiltration",
        "Impact",
        "Command and Control",
    ]
    wrong_tactics = [
        rf"{re.escape(t)}[^\n]{{0,60}}\b({'|'.join(x for x in all_tactics if x not in CATALOG[t].tactics)})\b"
        for t in required
    ]
    q(
        "forensic",
        "¿Qué técnicas MITRE ATT&CK aplican y con qué táctica?",
        "criterio",
        expect_all=required[:3],
        forbid=wrong_tactics,
    )
    if pend:
        q(
            "forensic",
            f"¿Por qué crees que {pend['campaign_id']} es o no es una segunda campaña?",
            "criterio",
            expect_all=[pend["campaign_id"]],
            expect_any=[["validar", "prueba", "interna", "appsec"]],
        )
    q(
        "response",
        "¿Qué acciones requieren aprobación humana y por qué?",
        "criterio",
        expect_any=[["bloque", "block"], ["revoc"]],
    )
    q(
        "response",
        "¿Por qué ese orden de acciones?",
        "criterio",
        expect_any=[["rate", "waf", "reversible", "frena", "limit"]],
    )
    q(
        "triage",
        f"¿Cuál es el alcance en {objs} y usuarios potencialmente afectados?",
        "criterio",
        expect_any=[[str(imp["unique_invoices_2xx"])]],
        forbid=no_auth_claim,
    )
    return qs


def score_answer(question: Question, answer: str, issues: list[dict[str, Any]]) -> dict[str, Any]:
    checks = [(t, _has(answer, t)) for t in question.expect_all]
    checks += [(" | ".join(g), any(_has(answer, t) for t in g)) for g in question.expect_any]
    found = sum(ok for _, ok in checks)
    forbidden = [p for p in question.forbid if re.search(p, answer, re.I)]
    blocking = [i for i in issues if i.get("blocking")]
    base = 100.0 * found / len(checks) if checks else 100.0
    score = max(0.0, base - 25 * len(forbidden) - 20 * len(blocking))
    return {
        "facts_expected": len(checks),
        "facts_found": found,
        "missing": [t for t, ok in checks if not ok],
        "forbidden_hits": forbidden,
        "review_issues": [i["message"] for i in issues],
        "score": round(score, 1),
    }


def run_chat_eval(
    run_dir: Path, llm: Any, limit: int | None = None, progress: Progress | None = None
) -> list[dict[str, Any]]:
    evidence = json.loads((run_dir / "evidence.json").read_text(encoding="utf-8"))
    facts = build_facts(evidence)
    profile = IncidentProfile.from_evidence(evidence)
    results: list[dict[str, Any]] = []
    previous: list[dict[str, Any]] = []
    bank = question_bank(evidence)[: limit or None]
    for i, q in enumerate(bank, start=1):
        if progress:
            progress("chat", f"Pregunta {i}/{len(bank)} ({q.agent}): {q.text}")
        context = chat.chat_context(run_dir, q.agent)
        system = chat.system_prompt(q.agent, profile) + "\n\n" + as_prompt_block(context)
        messages = [{"role": "user", "content": q.text}]
        started = time.perf_counter()
        try:
            answer = llm.stream_chat(system, messages, chat.AGENTS[q.agent]["max_tokens"], lambda _d: None).strip()
            error = None
        except Exception as exc:  # noqa: BLE001 - un fallo del modelo se registra y la evaluación sigue
            answer, error = "", f"{type(exc).__name__}: {str(exc)[:160]}"
        seconds = round(time.perf_counter() - started, 1)
        stats = chat.response_stats(
            getattr(llm, "last_stats", None) or {}, system, messages, previous, getattr(llm, "name", None)
        )
        record = {"model": getattr(llm, "name", "?"), "stats": stats}
        previous.append(record)
        issues = [x.as_dict() for x in review_text(answer, facts, check_numbers=False)] if answer else []
        results.append(
            {
                **asdict(q),
                "answer": answer,
                "error": error,
                "seconds": seconds,
                "stats": stats,
                **score_answer(q, answer, issues),
            }
        )
    return results


def run_agents_eval(run_dir: Path, llm: Any, progress: Progress | None = None) -> dict[str, Any]:
    from idor_ir.agents.graph import build_graph, run_graph
    from idor_ir.agents.service import reject_all

    evidence = json.loads((run_dir / "evidence.json").read_text(encoding="utf-8"))
    metrics_path = run_dir / "metrics.json"
    metrics = json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.is_file() else None
    events: list[str] = []

    def on_event(node: str, entry: dict[str, Any]) -> None:
        events.append(node)
        if progress and node in {"triage", "forensic", "response"}:
            progress("agents", f"{node}: {entry.get('source')} · {entry.get('latency_s')} s")

    started = time.perf_counter()
    with tempfile.TemporaryDirectory() as tmp:  # no toca agents/ del run
        graph = build_graph(llm, evidence, Path(tmp) / "actions")
        state = run_graph(graph, build_context(evidence, metrics), f"eval-{run_dir.name}", reject_all, on_event)
    total = round(time.perf_counter() - started, 1)
    log = {e["node"]: e for e in state.get("decision_log", []) if e.get("node") in {"triage", "forensic", "response"}}
    tri, fo, ro = state.get("triage") or {}, state.get("forensic") or {}, state.get("response") or {}
    added_actions = [a["action_id"] for a in ro.get("actions", []) if a.get("added_by_policy")]
    mitre = fo.get("mitre_attack", [])
    rule_added = [m["technique_id"] for m in mitre if m.get("source") == "regla (evidencia)"]
    incoherent = [
        m["technique_id"] for m in mitre if m.get("justification_source") == "código" and m.get("source") == "modelo"
    ]
    corrections = sum(len((x.get("checks") or {}).get("corrections", [])) for x in (tri, fo, ro))
    open_issues = sum(len((x.get("checks") or {}).get("issues", [])) for x in (tri, fo, ro))
    fallbacks = [n for n, e in log.items() if e.get("source") != "llm"]
    severity_raised = any("Severidad elevada" in a for a in (tri.get("checks") or {}).get("code_additions", []))
    penalties = {
        "acciones obligatorias omitidas por el modelo": 10 * len(added_actions),
        "técnicas obligatorias no elegidas por el modelo": 8 * len(rule_added),
        "justificaciones MITRE incoherentes": 10 * len(incoherent),
        "correcciones necesarias": 5 * corrections,
        "observaciones abiertas": 5 * open_issues,
        "severidad por debajo de la regla": 10 * severity_raised,
        "agentes que cayeron al fallback": 30 * len(fallbacks),
    }
    return {
        "seconds_total": total,
        "seconds_by_agent": {n: e.get("latency_s") for n, e in log.items()},
        "fix_calls": {n: e.get("fix_calls", 0) for n, e in log.items()},
        "sources": {n: e.get("source") for n, e in log.items()},
        "errors": {n: e.get("error") for n, e in log.items() if e.get("error")},
        "severity": tri.get("severity"),
        "mitre": [[m["technique_id"], m["tactic"], m.get("source"), m.get("justification_source")] for m in mitre],
        "actions_added_by_policy": added_actions,
        "corrections": corrections,
        "open_issues": open_issues,
        "penalties": {k: v for k, v in penalties.items() if v},
        "score": max(0, 100 - sum(penalties.values())),
    }


def evaluate(
    run_dir: Path,
    settings: Settings,
    llm: Any,
    chat_eval: bool = True,
    agents_eval: bool = True,
    limit: int | None = None,
    progress: Progress | None = None,
) -> dict[str, Any]:
    started = datetime.now(UTC)
    report: dict[str, Any] = {
        "run_id": run_dir.name,
        "model": getattr(llm, "name", "?"),
        "started": started.isoformat(timespec="seconds"),
    }
    if agents_eval:
        report["agents"] = run_agents_eval(run_dir, llm, progress)
    if chat_eval:
        answers = run_chat_eval(run_dir, llm, limit, progress)
        report["chat"] = {
            "questions": answers,
            "score": round(sum(a["score"] for a in answers) / len(answers), 1) if answers else None,
            "score_dato": _avg([a["score"] for a in answers if a["kind"] == "dato"]),
            "score_criterio": _avg([a["score"] for a in answers if a["kind"] == "criterio"]),
            "seconds_avg": _avg([a["seconds"] for a in answers]),
            "tokens_per_s_avg": _avg(
                [a["stats"].get("tokens_per_s") for a in answers if a["stats"].get("tokens_per_s")]
            ),
            "review_issues": sum(len(a["review_issues"]) for a in answers),
        }
    parts = [x for x in (report.get("agents", {}).get("score"), report.get("chat", {}).get("score")) if x is not None]
    report["score"] = round(sum(parts) / len(parts), 1) if parts else None
    report["finished"] = datetime.now(UTC).isoformat(timespec="seconds")
    _save(run_dir, settings, report)
    return report


def _avg(values: list[Any]) -> float | None:
    nums = [float(v) for v in values if isinstance(v, int | float)]
    return round(sum(nums) / len(nums), 1) if nums else None


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text)[:60]


def _save(run_dir: Path, settings: Settings, report: dict[str, Any]) -> None:
    folder = run_dir / "evaluation"
    folder.mkdir(parents=True, exist_ok=True)
    stem = f"{report['started'].replace(':', '').replace('-', '')[:15]}_{_slug(report['model'])}"
    atomic_write_text(folder / f"{stem}.json", json.dumps(report, indent=2, ensure_ascii=False))
    atomic_write_text(folder / f"{stem}.md", render_markdown(report))
    CustodyLog(settings.output_dir / "custody_log.jsonl").append(
        "llm_evaluation",
        {
            "run_id": run_dir.name,
            "model": report["model"],
            "score": report["score"],
            "file": f"evaluation/{stem}.json",
        },
    )


def list_reports(run_dir: Path) -> list[dict[str, Any]]:
    folder = run_dir / "evaluation"
    out = []
    for path in sorted(folder.glob("*.json")) if folder.is_dir() else []:
        try:
            out.append(json.loads(path.read_text(encoding="utf-8")) | {"file": f"evaluation/{path.name}"})
        except (ValueError, OSError):
            continue
    return out


def summary_row(r: dict[str, Any]) -> dict[str, Any]:
    ag, ch = r.get("agents") or {}, r.get("chat") or {}
    return {
        "modelo": r.get("model"),
        "fecha": r.get("started"),
        "puntaje": r.get("score"),
        "agentes": ag.get("score"),
        "agentes_s": ag.get("seconds_total"),
        "chat": ch.get("score"),
        "chat_dato": ch.get("score_dato"),
        "chat_criterio": ch.get("score_criterio"),
        "chat_s_prom": ch.get("seconds_avg"),
        "tokens_s": ch.get("tokens_per_s_avg"),
        "observaciones": (ag.get("open_issues") or 0) + (ch.get("review_issues") or 0),
    }


def compare_table(reports: list[dict[str, Any]]) -> str:
    rows = [summary_row(r) for r in reports]
    head = [
        "modelo",
        "puntaje",
        "agentes",
        "agentes_s",
        "chat",
        "chat_dato",
        "chat_criterio",
        "chat_s_prom",
        "tokens_s",
        "observaciones",
    ]
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    lines += ["| " + " | ".join("—" if r[h] is None else str(r[h]) for h in head) + " |" for r in rows]
    return "\n".join(lines)


def render_markdown(r: dict[str, Any]) -> str:
    lines = [
        f"# Evaluación de {r['model']} — run {r['run_id']}",
        "",
        f"*{r['started']} → {r.get('finished')}*",
        "",
        f"**Puntaje global:** {r.get('score')}",
        "",
    ]
    ag = r.get("agents")
    if ag:
        lines += [
            "## Agentes",
            "",
            f"- Puntaje: {ag['score']} · tiempo total {ag['seconds_total']} s · por agente {ag['seconds_by_agent']}",
            f"- Fuente: {ag['sources']}",
            f"- Acciones obligatorias que omitió el modelo: {ag['actions_added_by_policy'] or 'ninguna'}",
            f"- MITRE (técnica, táctica, origen, justificación): {ag['mitre']}",
            f"- Correcciones: {ag['corrections']} · observaciones abiertas: {ag['open_issues']}",
            f"- Penalizaciones: {ag['penalties'] or 'ninguna'}",
            "",
        ]
    ch = r.get("chat")
    if ch:
        lines += [
            "## Chat",
            "",
            f"- Puntaje: {ch['score']} (dato {ch['score_dato']}, criterio {ch['score_criterio']}) "
            f"· {ch['seconds_avg']} s/pregunta · {ch['tokens_per_s_avg']} tokens/s",
            "",
            "| # | Agente | Tipo | Pregunta | Puntaje | Faltó | Observaciones | s |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for q in ch["questions"]:
            lines.append(
                f"| {q['id']} | {q['agent']} | {q['kind']} | {q['text']} | {q['score']} | "
                f"{'; '.join(q['missing']) or '—'} | {'; '.join(q['review_issues'] + q['forbidden_hits']) or '—'} "
                f"| {q['seconds']} |"
            )
    return "\n".join(lines) + "\n"
