"""Orquestación multiagente con LangGraph [R8, R11].

Flujo de estados:

    START → triage ──(severidad "bajo")──────────────────────────────┐
                 └──→ forensic → response → policy → human_review → execute → report → END
                                                    (interrupt: pausa hasta la decisión humana)

- Cada nodo-agente intenta el LLM (Ollama) y, si falla, usa la lógica determinista; ambos devuelven el
  mismo esquema y la fuente queda en el decision log.
- `policy` endurece la necesidad de aprobación (el LLM no puede auto-aprobarse).
- `human_review` usa `interrupt()` de LangGraph: el grafo se detiene, persiste su estado en el
  checkpointer y se reanuda con `Command(resume=decisiones)` (intervención humana simulada en la CLI,
  real en la web).
- `execute` siempre corre en dry-run en el MVP.
"""

from __future__ import annotations

import json
import operator
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, TypedDict

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt
from pydantic import BaseModel

from idor_ir.agents import fallback, mitre, prompts
from idor_ir.agents.assembly import assemble_forensic, assemble_response, assemble_triage
from idor_ir.agents.context import as_prompt_block, fichas
from idor_ir.agents.executor import execute
from idor_ir.agents.llm import LLMClient, LLMError
from idor_ir.agents.policy import apply_policy
from idor_ir.agents.review import Facts, Issue, build_facts, review_text
from idor_ir.agents.schemas import (
    Checks,
    ForensicDraft,
    ResponseAction,
    ResponseDraft,
    ResponseOutput,
    TextFix,
    TriageDraft,
    TriageOutput,
)

# Presupuesto de tokens de salida por agente (solo CPU: ~4-5 tokens/s con contexto). Los borradores son más
# pequeños que las salidas completas de antes (punto 7): el modelo ya no escribe datos que el código conoce.
MAX_TOKENS = {"triage": 450, "forensic": 750, "response": 800, "fix": 120}
MAX_FIXES = 3  # correcciones puntuales por agente (cada una ~15-25 s en CPU)
_KIND_ORDER = {"fecha": 0, "ip": 1, "campaña": 2, "atribución": 3, "lista_incompleta": 4, "cifra": 9}


class AgentState(TypedDict, total=False):
    context: dict[str, Any]
    triage: dict[str, Any]
    forensic: dict[str, Any]
    response: dict[str, Any]
    policy_overrides: list[dict[str, Any]]
    approvals: dict[str, str]
    executed: list[dict[str, Any]]
    status: str
    decision_log: Annotated[list[dict[str, Any]], operator.add]  # se acumula entre nodos


_NUM_RE = re.compile(r"\d[\d.,]{2,}\d|\d{3,}")


def unverified_numbers(output: BaseModel, context: dict[str, Any]) -> list[str]:
    """Cifras (>= 3 dígitos) que el LLM escribió y que NO aparecen en los datos que recibió.

    Guardarraíl simple contra alucinaciones numéricas: no bloquea, pero deja constancia en el
    decision log para que el analista lo revise.
    """
    haystack = re.sub(r"[.,]", "", json.dumps(context, ensure_ascii=False))
    text = re.sub(r"\bT\d{4}(?:\.\d{3})?\b", " ", output.model_dump_json())  # IDs MITRE: se validan aparte
    found = {re.sub(r"[.,]", "", n) for n in _NUM_RE.findall(text)}
    # Se ignoran decimales tipo 0.98 (confianza, porcentajes), que no son cifras del incidente.
    return sorted(n for n in found if n not in haystack and not n.startswith("0"))[:10]


def _log(node: str, **fields: Any) -> dict[str, Any]:
    return {"ts": datetime.now(tz=UTC).isoformat(), "node": node, **fields}


def _text_paths(node: str, draft: dict[str, Any]) -> list[tuple[tuple[Any, ...], str]]:
    """Campos de texto del borrador que revisa el código (punto 9)."""
    paths: list[tuple[tuple[Any, ...], str]] = []
    if node == "triage":
        paths.append((("attack_type",), "tipo de ataque"))
        paths += [(("hypotheses", i, "text"), f"hipótesis {i + 1}") for i in range(len(draft.get("hypotheses", [])))]
        paths += [(("investigation_plan", i), f"plan {i + 1}") for i in range(len(draft.get("investigation_plan", [])))]
    elif node == "forensic":
        paths.append((("attack_pattern",), "patrón de ataque"))
        paths += [(("reasoning", i), f"razonamiento {i + 1}") for i in range(len(draft.get("reasoning", [])))]
        paths.append((("campaigns_assessment",), "evaluación de campañas"))
        paths += [(("open_questions", i), f"pregunta {i + 1}") for i in range(len(draft.get("open_questions", [])))]
    else:
        paths += [(("ranking", i, "rationale"), f"justificación {r.get('action_id')}")
                  for i, r in enumerate(draft.get("ranking", []))]  # fmt: skip
        paths += [(("playbook", i), f"playbook {i + 1}") for i in range(len(draft.get("playbook", [])))]
        paths.append((("ordering_rationale",), "orden"))
    return paths


def _get(data: Any, path: tuple[Any, ...]) -> Any:
    for key in path:
        data = data[key]
    return data


def _set(data: Any, path: tuple[Any, ...], value: Any) -> None:
    for key in path[:-1]:
        data = data[key]
    data[path[-1]] = value


def build_graph(llm: LLMClient | None, evidence: dict[str, Any], actions_dir: Path, dry_run: bool = True) -> Any:
    """Construye y compila el grafo. `llm=None` fuerza el modo determinista."""

    ground_truth: dict[str, Any] = evidence  # cifras de referencia para el guardarraíl numérico
    facts: Facts = build_facts(evidence)

    def call_agent(
        node: str, system: str, user: str, schema: type[BaseModel], fallback_fn: Callable[[], BaseModel]
    ) -> tuple[BaseModel, dict[str, Any]]:
        started = time.perf_counter()
        if llm is not None:
            try:
                out = llm.generate(system, user, schema, MAX_TOKENS[node])
                entry = _log(node, source="llm", model=llm.name, latency_s=round(time.perf_counter() - started, 1))
                suspicious = unverified_numbers(out, ground_truth)
                if suspicious:
                    entry["unverified_numbers"] = suspicious
                return out, entry
            except LLMError as exc:
                out = fallback_fn()
                return out, _log(
                    node,
                    source="fallback",
                    model=llm.name,
                    error=str(exc),
                    latency_s=round(time.perf_counter() - started, 1),
                )
        return fallback_fn(), _log(node, source="deterministic", latency_s=round(time.perf_counter() - started, 3))

    def fix_text(text: str, problems: list[str], data: list[str]) -> str | None:
        """Corrección puntual (punto 9): prompt corto SIN el contexto completo → pocos segundos."""
        if llm is None:
            return None
        user = (
            f"<texto>{text}</texto>\n<problemas>{'; '.join(problems)}</problemas>\n"
            f"<datos_correctos>{'; '.join(data)}</datos_correctos>"
        )
        try:
            fixed = llm.generate(prompts.FIX, user, TextFix, MAX_TOKENS["fix"])
        except LLMError:
            return None
        return fixed.texto.strip() or None

    def review_draft(node: str, draft: BaseModel, entry: dict[str, Any]) -> tuple[dict[str, Any], Checks]:
        """Revisa los textos del modelo; pide hasta MAX_FIXES correcciones; el resto queda como observación."""
        data = draft.model_dump()
        checks = Checks()
        if entry.get("source") != "llm":
            return data, checks
        started = time.perf_counter()
        found: list[tuple[tuple[Any, ...], str, list[Issue]]] = []
        for path, label in _text_paths(node, data):
            issues = review_text(str(_get(data, path)), facts)
            if issues:
                found.append((path, label, issues))
        found.sort(key=lambda f: min(_KIND_ORDER.get(i.kind, 5) for i in f[2]))
        fixes = 0
        for path, label, issues in found:
            hard = [i for i in issues if i.blocking]
            soft = [i for i in issues if not i.blocking]
            checks.issues += [f"{label}: {i.message}" for i in soft]
            if not hard:
                continue
            new = fix_text(str(_get(data, path)), [i.message for i in hard], [i.fact for i in hard]) \
                if fixes < MAX_FIXES else None  # fmt: skip
            fixes += new is not None
            remaining = [i for i in review_text(new, facts) if i.blocking] if new else hard
            if new and len(remaining) < len(hard):
                _set(data, path, new)
                checks.corrections.append(f"{label}: corregido ({', '.join(sorted({i.kind for i in hard}))})")
            checks.issues += [f"{label}: {i.message}" for i in remaining]
        if node == "forensic":
            fixes += _fix_mitre(data, checks, MAX_FIXES - fixes if fixes < MAX_FIXES else 0)
        if fixes:
            entry["fix_calls"] = fixes
            entry["fix_latency_s"] = round(time.perf_counter() - started, 1)
        return data, checks

    def _fix_mitre(data: dict[str, Any], checks: Checks, budget: int) -> int:
        """Justificaciones MITRE incoherentes (p. ej. T1078 justificado con el escaneo): corrección puntual."""
        required = {r.id: r for r in mitre.required_techniques(evidence)}
        calls = 0
        for item in data.get("mitre", []):
            tid = item.get("technique_id", "")
            if tid not in mitre.CATALOG or mitre.justification_matches(tid, item.get("justification", "")):
                continue
            if calls >= budget:
                break
            tech = mitre.CATALOG[tid]
            hint = required[tid].justification if tid in required else "datos de la evidencia que correspondan"
            new = fix_text(
                item.get("justification", ""),
                [f"La justificación no corresponde a {tid} {tech.name} ({tech.primary})"],
                [hint],
            )
            calls += new is not None
            if new and mitre.justification_matches(tid, new):
                item["justification"] = new
                checks.corrections.append(f"MITRE {tid}: justificación corregida para que corresponda a la técnica")
        return calls

    def triage_node(state: AgentState) -> dict[str, Any]:
        ctx = state["context"]
        draft, entry = call_agent(
            "triage", prompts.TRIAGE, as_prompt_block(fichas(ctx, detail=False)), TriageDraft,
            lambda: fallback.triage_draft(ctx),
        )  # fmt: skip
        data, checks = review_draft("triage", draft, entry)
        t = assemble_triage(TriageDraft.model_validate(data), ctx, checks)
        entry["decision"] = f"Severidad {t.severity} ({t.confidence:.0%}): {t.attack_type}"
        entry["checks"] = t.checks.model_dump()
        return {"triage": t.model_dump(), "decision_log": [entry]}

    def route_after_triage(state: AgentState) -> str:
        return "report" if state["triage"]["severity"] == "bajo" else "forensic"

    def forensic_node(state: AgentState) -> dict[str, Any]:
        ctx = state["context"]
        tri = TriageOutput.model_validate(state["triage"])
        brief = tri.model_dump(include={"severity", "attack_type", "hypotheses"})
        user = as_prompt_block(fichas(ctx)) + "\n<triage>" + json.dumps(brief, ensure_ascii=False) + "</triage>"
        draft, entry = call_agent(
            "forensic", prompts.FORENSIC, user, ForensicDraft, lambda: fallback.forensic_draft(ctx, tri)
        )
        data, checks = review_draft("forensic", draft, entry)
        fo, assembly = assemble_forensic(ForensicDraft.model_validate(data), ctx, checks)
        entry["decision"] = f"MITRE: {', '.join(m.technique_id for m in fo.mitre_attack)}" + (
            f" (agregadas por regla: {', '.join(assembly.added)})" if assembly.added else ""
        )
        entry["checks"] = fo.checks.model_dump()
        return {"forensic": fo.model_dump(), "decision_log": [entry]}

    def response_node(state: AgentState) -> dict[str, Any]:
        ctx = state["context"]
        candidates = fallback.candidate_actions(ctx)
        fo = state["forensic"]
        forensic_brief = {
            "campaigns_assessment": fo.get("campaigns_assessment"),
            "mitre": [m["technique_id"] for m in fo.get("mitre_attack", [])],
        }
        table = {
            "columnas": ["id", "tipo", "objetivo", "fase", "riesgo_fp", "impacto", "obligatoria"],
            "filas": [[a.action_id, a.action_type, a.target[:90], a.phase, a.false_positive_risk, a.business_impact,
                       a.reason_required or "no"] for a in candidates],
        }  # fmt: skip
        user = (
            as_prompt_block(fichas(ctx, detail=False))
            + "\n<analisis_forense>" + json.dumps(forensic_brief, ensure_ascii=False) + "</analisis_forense>"
            + "\n<acciones_candidatas>" + json.dumps(table, ensure_ascii=False) + "</acciones_candidatas>"
        )  # fmt: skip
        draft, entry = call_agent(
            "response", prompts.RESPONSE, user, ResponseDraft, lambda: fallback.response_draft(ctx, candidates)
        )
        data, checks = review_draft("response", draft, entry)
        ro = assemble_response(ResponseDraft.model_validate(data), candidates, checks)
        added = [a.action_id for a in ro.actions if a.added_by_policy]
        entry["decision"] = f"{len(ro.actions)} acciones" + (f" ({len(added)} agregadas por política)" if added else "")
        entry["checks"] = ro.checks.model_dump()
        return {"response": ro.model_dump(), "decision_log": [entry]}

    def policy_node(state: AgentState) -> dict[str, Any]:
        pending = {c["campaign_id"] for c in evidence.get("campaigns", []) if c["status"] != "confirmada"}
        ro, overrides = apply_policy(ResponseOutput.model_validate(state["response"]), pending)
        need = [a.action_id for a in ro.actions if a.requires_human_approval]
        entry = _log(
            "policy",
            source="code",
            decision=f"{len(need)} requieren aprobación; {len(overrides)} endurecidas",
            overrides=overrides,
        )
        return {"response": ro.model_dump(), "policy_overrides": overrides, "decision_log": [entry]}

    def human_review_node(state: AgentState) -> dict[str, Any]:
        actions = [ResponseAction.model_validate(a) for a in state["response"]["actions"]]
        pending = [a for a in actions if a.requires_human_approval]
        # Las automáticas (reversibles, FP bajo, impacto bajo) no se deciden aquí, pero se informan junto con las
        # pendientes para que el analista vea el plan completo y el criterio de automatización.
        automatic = [a for a in actions if not a.requires_human_approval]
        if not pending:
            return {"approvals": {}, "decision_log": [_log("human_review", source="code", decision="Nada que aprobar")]}
        # Pausa el grafo: el estado queda en el checkpointer hasta recibir Command(resume=...).
        raw = interrupt(
            {
                "pending_actions": [a.model_dump() for a in pending],
                "automatic_actions": [a.model_dump() for a in automatic],
            }
        )
        valid = {a.action_id for a in pending}
        approvals = {
            k: ("approve" if v == "approve" else "reject")
            for k, v in (raw.items() if isinstance(raw, dict) else [])
            if k in valid  # se ignoran IDs desconocidos (entrada no confiable)
        }
        approvals |= {a: "reject" for a in valid - approvals.keys()}  # sin respuesta = rechazada
        entry = _log(
            "human_review",
            source="human",
            decision=f"{sum(v == 'approve' for v in approvals.values())} aprobadas, "
            f"{sum(v == 'reject' for v in approvals.values())} rechazadas; "
            f"{len(automatic)} automáticas sin aprobación",
            approvals=approvals,
            automatic=[a.action_id for a in automatic],
        )
        return {"approvals": approvals, "decision_log": [entry]}

    def execute_node(state: AgentState) -> dict[str, Any]:
        actions = [ResponseAction.model_validate(a) for a in state["response"]["actions"]]
        approvals = state.get("approvals", {})
        to_run = [a for a in actions if not a.requires_human_approval or approvals.get(a.action_id) == "approve"]
        results = execute(to_run, evidence, actions_dir, dry_run=dry_run)
        entry = _log(
            "execute",
            source="code",
            dry_run=dry_run,
            decision=f"{len(results)} acciones ejecutadas en dry-run: {', '.join(r['action_id'] for r in results)}",
        )
        return {"executed": results, "decision_log": [entry]}

    def report_node(state: AgentState) -> dict[str, Any]:
        return {"status": "completado", "decision_log": [_log("report", source="code", decision="Flujo finalizado")]}

    graph = StateGraph(AgentState)
    graph.add_node("triage", triage_node)
    graph.add_node("forensic", forensic_node)
    graph.add_node("response", response_node)
    graph.add_node("policy", policy_node)
    graph.add_node("human_review", human_review_node)
    graph.add_node("execute", execute_node)
    graph.add_node("report", report_node)
    graph.add_edge(START, "triage")
    graph.add_conditional_edges("triage", route_after_triage, {"forensic": "forensic", "report": "report"})
    graph.add_edge("forensic", "response")
    graph.add_edge("response", "policy")
    graph.add_edge("policy", "human_review")
    graph.add_edge("human_review", "execute")
    graph.add_edge("execute", "report")
    graph.add_edge("report", END)
    return graph.compile(checkpointer=InMemorySaver())


def run_graph(
    graph: Any,
    context: dict[str, Any],
    thread_id: str,
    decide: Callable[[dict[str, Any]], dict[str, str]],
    on_event: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Ejecuta el grafo en modo streaming (un evento por nodo terminado).

    Si se interrumpe en `human_review`, llama a `decide(payload)` (consola, web o automático) y lo reanuda.
    `on_event(nodo, datos)` permite mostrar el progreso en vivo (la web lo envía por SSE).
    """
    config = {"configurable": {"thread_id": thread_id}}
    payload: Any = {"context": context, "decision_log": []}
    while True:
        interrupted: dict[str, Any] | None = None
        for chunk in graph.stream(payload, config, stream_mode="updates"):
            for node, update in chunk.items():
                if node == "__interrupt__":
                    interrupted = update[0].value
                    if on_event:
                        on_event("awaiting_approval", interrupted)
                elif on_event:
                    log = (update or {}).get("decision_log", [])
                    on_event(node, log[-1] if log else {})
        if interrupted is None:
            break
        payload = Command(resume=decide(interrupted))
    state: dict[str, Any] = graph.get_state(config).values
    return state
