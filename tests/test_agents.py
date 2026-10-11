"""Tests de los agentes sin Ollama: LLM falso inyectado + escenario SINTÉTICO."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TypeVar

import pytest
from pydantic import BaseModel

from idor_ir import cli
from idor_ir.agents import fallback
from idor_ir.agents.context import build_context
from idor_ir.agents.executor import LiveExecutionNotSupported, execute
from idor_ir.agents.graph import build_graph, run_graph
from idor_ir.agents.llm import LLMError
from idor_ir.agents.policy import apply_policy
from idor_ir.agents.schemas import ResponseAction, ResponseOutput
from idor_ir.agents.service import approve_all, reject_all, run_agents
from idor_ir.config import Settings
from tests.test_detection import synthetic_csv  # noqa: F401

T = TypeVar("T", bound=BaseModel)


@pytest.fixture
def analyzed_run(synthetic_csv: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Settings]:  # noqa: F811
    settings = Settings(output_dir=tmp_path / "out", data_dir=tmp_path)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    assert cli.main(["analyze", "--file", str(synthetic_csv)]) == cli.EXIT_OK
    return next(p for p in settings.output_dir.iterdir() if p.is_dir()), settings


class BrokenLLM:
    """Simula Ollama caído."""

    name = "fake:broken"

    def generate(self, system: str, user: str, schema: type[T], max_tokens: int) -> T:
        raise LLMError("sin conexión")


class ScriptedLLM:
    """Simula los errores REALES de qwen3-4b (05-oct-2026) para comprobar que el código los corrige:

    - Triage: una hipótesis con una fecha fuera del log ("febrero 2021") y otra sin marcar como hipótesis;
    - Forensic: justificaciones MITRE cruzadas (T1078 con el escaneo) y sin T1119;
    - Response: omite el bloqueo de IPs (obligatorio) y menciona una acción inexistente (A99).
    La corrección puntual (TextFix) devuelve un texto correcto.
    """

    name = "fake:scripted"

    def __init__(self, evidence: dict[str, Any]) -> None:
        self.ctx = build_context(evidence)
        self.calls: list[str] = []

    def generate(self, system: str, user: str, schema: type[T], max_tokens: int) -> T:
        self.calls.append(schema.__name__)
        assert "SECRET" not in user and "USER-ID-attacker" not in user  # el LLM nunca ve tokens en claro
        if schema.__name__ == "TriageDraft":
            draft = fallback.triage_draft(self.ctx).model_dump()
            draft["severity"] = "medio"  # por debajo de la regla: el código la eleva
            draft["hypotheses"] = [
                {"text": "La actividad de C1 siguió en febrero 2021 con éxito del 100 %", "kind": "hecho"},
                {"text": "Las credenciales fueron robadas por phishing", "kind": "hipotesis"},
            ]
            return schema.model_validate(draft)
        if schema.__name__ == "ForensicDraft":
            draft = fallback.forensic_draft(self.ctx).model_dump()
            draft["mitre"] = [
                {"technique_id": "T1078", "justification": "Escaneo sistemático de rangos contiguos de IDs"},
                {"technique_id": "T1190", "justification": "Respuestas 2xx en el endpoint sin validar pertenencia"},
            ]
            return schema.model_validate(draft)
        if schema.__name__ == "ResponseDraft":
            candidates = fallback.candidate_actions(self.ctx)
            ranking = [{"action_id": a.action_id, "rationale": "Prioridad por riesgo"} for a in candidates
                       if a.action_type != "block_ip"]  # fmt: skip
            ranking.insert(0, {"action_id": "A99", "rationale": "Bloquear 8.8.8.8"})
            return schema.model_validate({"ranking": ranking, "playbook": ["a", "b", "c"],
                                          "ordering_rationale": "Primero lo reversible"})  # fmt: skip
        if schema.__name__ == "TextFix":
            if "T1078" in user:
                return schema.model_validate({"texto": "Credenciales válidas (token) de varias cuentas usadas"})
            return schema.model_validate({"texto": "La actividad de C1 ocurrió dentro del periodo del log"})
        raise AssertionError(schema.__name__)


def _evidence(run_dir: Path) -> dict[str, Any]:
    return json.loads((run_dir / "evidence.json").read_text(encoding="utf-8"))


def test_policy_hardens_llm_approval() -> None:
    action = ResponseAction(
        action_id="A1",
        action_type="block_ip",
        target="C1",
        priority=1,
        phase="inmediata",
        rationale="x",
        false_positive_risk="bajo",
        business_impact="bajo",
        requires_human_approval=False,
    )
    fixed, overrides = apply_policy(
        ResponseOutput(actions=[action], playbook=["a", "b", "c"], ordering_rationale="x"), set()
    )
    assert fixed.actions[0].requires_human_approval is True
    assert overrides and overrides[0]["action_id"] == "A1"


def test_graph_with_llm_code_fixes_model_errors(analyzed_run: tuple[Path, Settings], tmp_path: Path) -> None:
    run_dir, _ = analyzed_run
    evidence = _evidence(run_dir)
    llm = ScriptedLLM(evidence)
    graph = build_graph(llm, evidence, tmp_path / "actions")
    seen: dict[str, Any] = {}

    def decide(payload: dict[str, Any]) -> dict[str, str]:
        seen.update(payload)
        return reject_all(payload)

    state = run_graph(graph, build_context(evidence), "t1", decide)
    assert llm.calls[:2] == ["TriageDraft", "TextFix"] and "ForensicDraft" in llm.calls and "ResponseDraft" in llm.calls
    assert state["status"] == "completado"

    tri = state["triage"]
    assert tri["severity"] == "alto"  # el modelo dijo "medio"; la regla exige al menos "alto"
    assert 0 < tri["confidence"] <= 0.9 and tri["confidence_basis"]  # la calcula el código
    assert tri["hypotheses"][0] == "La actividad de C1 ocurrió dentro del periodo del log"  # fecha corregida
    assert tri["hypotheses"][1].startswith("Posible:")  # hipótesis rotulada
    assert any("C1" in t for t in tri["priority_targets"])  # prioridad por campaña
    assert tri["checks"]["corrections"] and tri["checks"]["status"] == "verificado"

    mitre = {m["technique_id"]: m for m in state["forensic"]["mitre_attack"]}
    assert mitre["T1190"]["tactic"] == "Initial Access" and mitre["T1078"]["tactic"] == "Initial Access"
    assert "Credenciales" in mitre["T1078"]["justification"]  # corregida por la revisión
    assert mitre["T1119"]["source"] == "regla (evidencia)" and mitre["T1119"]["tactic"] == "Collection"
    assert state["forensic"]["patient_zero"].startswith(evidence["campaigns"][0]["patient_zero"]["ts"])

    actions = {a["action_type"]: a for a in state["response"]["actions"]}
    assert actions["block_ip"]["added_by_policy"] and actions["block_ip"]["requires_human_approval"]
    assert all("8.8.8.8" not in a["target"] for a in state["response"]["actions"])  # A99 ignorada
    executed = {e["action_id"] for e in state["executed"]}
    assert actions["block_ip"]["action_id"] not in executed  # rechazada en la revisión humana
    # La pausa informa también las automáticas: no se deciden y se ejecutan aunque se rechace todo lo demás.
    automatic = {a["action_id"] for a in seen["automatic_actions"]}
    pending = {a["action_id"] for a in seen["pending_actions"]}
    assert automatic and not automatic & pending
    assert all(not a["requires_human_approval"] for a in seen["automatic_actions"])
    assert automatic <= executed and not pending & executed
    assert all("8.8.8.8" not in p.read_text(encoding="utf-8") for p in (tmp_path / "actions").glob("*.txt"))
    sources = {e["node"]: e["source"] for e in state["decision_log"]}
    assert sources["triage"] == "llm" and sources["human_review"] == "human"


def test_fallback_when_llm_down_and_service_outputs(analyzed_run: tuple[Path, Settings]) -> None:
    run_dir, settings = analyzed_run
    report = run_agents(run_dir, settings, BrokenLLM(), approve_all)
    log = [
        json.loads(line)
        for line in (run_dir / "agents" / "decision_log.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert {e["source"] for e in log if e["node"] in {"triage", "forensic", "response"}} == {"fallback"}
    assert report["triage"]["severity"] in {"critico", "alto"}
    assert all(a["dry_run"] for a in report["executed"])
    assert (run_dir / "agents" / "playbook.md").is_file()
    assert "USER-ID-attacker" not in (run_dir / "agents" / "agents_report.json").read_text(encoding="utf-8")
    est = report["response_time_estimates"]
    assert est["automated"]["ttc_hours"] < est["manual"]["ttc_hours"]
    assert est["detection_backtest"]["rule_automation_user_agent"]["would_alert_on"] is not None
    assert cli.main(["verify", "--run", run_dir.name]) == cli.EXIT_OK


def test_live_execution_is_blocked(tmp_path: Path) -> None:
    with pytest.raises(LiveExecutionNotSupported):
        execute([], {}, tmp_path, dry_run=False)


def test_ollama_schema_and_repair() -> None:
    from idor_ir.agents.llm import _inline, ollama_schema, repair
    from idor_ir.agents.schemas import ForensicOutput, ResponseOutput, TriageOutput

    text = json.dumps(ollama_schema(ResponseOutput))
    assert "$ref" not in text and '"minimum"' not in text and '"default"' not in text
    assert '"maxLength"' not in text  # la gramática ya no corta frases (punto 5)
    assert "verified_in_catalog" not in json.dumps(ollama_schema(ForensicOutput))
    # Salida "larga" del modelo: se recorta en una palabra completa y valida en vez de caer al fallback.
    data = {
        "severity": "critico",
        "attack_type": "palabra " * 60,
        "confidence": 1.7,
        "hypotheses": ["h" * 400] * 9,
        "investigation_plan": ["p"],
        "priority_targets": [],
    }
    fixed = TriageOutput.model_validate(repair(data, _inline(TriageOutput)))
    assert len(fixed.attack_type) <= 140 and fixed.attack_type.endswith("palabra…")
    assert fixed.confidence == 1 and len(fixed.hypotheses) == 6


def test_llm_limits_and_numeric_guardrail() -> None:
    from idor_ir.agents.graph import unverified_numbers
    from idor_ir.agents.llm import ollama_schema
    from idor_ir.agents.schemas import ForensicDraft, TriageOutput

    schema = ollama_schema(ForensicDraft)
    assert (
        schema["properties"]["reasoning"]["maxItems"] == 4
        and "maxLength" not in schema["properties"]["reasoning"]["items"]
    )
    out = TriageOutput(
        severity="alto",
        attack_type="x",
        confidence=0.5,
        hypotheses=["10,181 facturas y 99999 inventadas"],
        investigation_plan=["p"],
    )
    assert unverified_numbers(out, {"impact": {"unique": 10181}}) == ["99999"]
