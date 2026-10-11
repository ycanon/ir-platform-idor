"""Banco de evaluación y comparación de modelos (mejora O13, fase 3) con un modelo FALSO (sin Ollama)."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel

from idor_ir.agents import evaluation, fallback
from idor_ir.agents.context import build_context
from idor_ir.config import Settings
from idor_ir.pipeline import run_analysis
from idor_ir.web.app import create_app
from tests.test_detection import synthetic_csv  # noqa: F401

T = TypeVar("T", bound=BaseModel)


class FakeModel:
    """Agentes: devuelve los borradores deterministas. Chat: una respuesta fija (buena o mala)."""

    def __init__(self, evidence: dict[str, Any], answer: str, name: str = "fake:eval") -> None:
        self.ctx = build_context(evidence)
        self.answer = answer
        self.name = name
        self.last_stats = {"prompt_tokens": 1000, "prompt_s": 10.0, "output_tokens": 50, "gen_s": 10.0}

    def generate(self, system: str, user: str, schema: type[T], max_tokens: int) -> T:
        draft: BaseModel
        if schema.__name__ == "TriageDraft":
            draft = fallback.triage_draft(self.ctx)
        elif schema.__name__ == "ForensicDraft":
            draft = fallback.forensic_draft(self.ctx)
        elif schema.__name__ == "ResponseDraft":
            draft = fallback.response_draft(self.ctx, fallback.candidate_actions(self.ctx))
        else:
            return schema.model_validate({"texto": "ok"})
        return schema.model_validate(draft.model_dump())

    def stream_chat(
        self, system: str, messages: list[dict[str, str]], max_tokens: int, on_delta: Callable[[str], None]
    ) -> str:
        on_delta(self.answer)
        return self.answer


@pytest.fixture
def run(synthetic_csv: Path, tmp_path: Path) -> tuple[Path, Settings]:  # noqa: F811
    settings = Settings(data_dir=tmp_path / "data", output_dir=tmp_path / "out")
    settings.data_dir.mkdir()
    return run_analysis(synthetic_csv, settings).run_dir, settings


def _evidence(run_dir: Path) -> dict[str, Any]:
    return json.loads((run_dir / "evidence.json").read_text(encoding="utf-8"))


def test_question_bank_is_built_from_the_run_evidence(run: tuple[Path, Settings]) -> None:
    ev = _evidence(run[0])
    bank = evaluation.question_bank(ev)
    assert 10 <= len(bank) <= 16 and {q.kind for q in bank} == {"dato", "criterio"}
    ips_q = bank[0]
    assert ips_q.expect_all == ev["campaigns"][0]["ips"]
    mitre_q = next(q for q in bank if "MITRE" in q.text)
    assert "T1190" in mitre_q.expect_all and mitre_q.forbid  # tácticas equivocadas penalizan


def test_score_answer_rewards_facts_and_penalizes_errors() -> None:
    q = evaluation.Question(
        "Q1", "triage", "¿IPs?", "dato", expect_all=["1.2.3.4", "10181"], forbid=[r"sin autenticaci"]
    )
    good = evaluation.score_answer(q, "- 1.2.3.4 obtuvo 10,181 facturas", [])
    assert good["score"] == 100 and not good["missing"]
    bad = evaluation.score_answer(
        q, "- acceso sin autenticación", [{"message": "fecha fuera", "blocking": True, "kind": "fecha"}]
    )
    assert bad["score"] == 0 and bad["missing"] == ["1.2.3.4", "10181"] and bad["forbidden_hits"]


def test_evaluate_writes_reports_and_compares(run: tuple[Path, Settings]) -> None:
    run_dir, settings = run
    ev = _evidence(run_dir)
    c = ev["campaigns"][0]
    good_answer = (
        f"- C1: {len(c['ips'])} IPs ({', '.join(c['ips'])}); {c['impact']['unique_invoices_2xx']:,} facturas; "
        f"acceso autenticado, falla de autorización (IDOR); T1595.002 T1078 T1190; priorizar la campaña C1; "
        f"bloquear y revocar con aprobación; rate limit reversible."
    )
    good = evaluation.evaluate(run_dir, settings, FakeModel(ev, good_answer, "fake:bueno"), limit=6)
    bad = evaluation.evaluate(
        run_dir, settings, FakeModel(ev, "- Acceso sin autenticación en febrero 2021.", "fake:malo"), limit=6
    )
    assert good["agents"]["score"] == 100 and good["agents"]["sources"]["triage"] == "llm"
    assert {m[1] for m in good["agents"]["mitre"]} >= {"Initial Access", "Collection"}  # táctica del catálogo
    assert good["chat"]["score"] > bad["chat"]["score"]
    assert any("febrero" in i for q in bad["chat"]["questions"] for i in q["review_issues"])
    files = sorted(p.name for p in (run_dir / "evaluation").iterdir())
    assert len([f for f in files if f.endswith(".json")]) == 2 and any(f.endswith(".md") for f in files)
    table = evaluation.compare_table(evaluation.list_reports(run_dir))
    assert "fake:bueno" in table and "fake:malo" in table
    assert not (run_dir / "agents" / "agents_report.json").exists()  # la evaluación no toca el reporte del run


def test_web_evaluation_endpoints(run: tuple[Path, Settings], monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir, settings = run
    ev = _evidence(run_dir)
    monkeypatch.setattr(
        "idor_ir.agents.llm.OllamaLLM", lambda base_url, model, **kw: FakeModel(ev, "- C1", f"ollama:{model}")
    )
    c = TestClient(create_app(settings))
    c.get("/")
    c.headers["X-CSRF-Token"] = c.cookies.get("irp_csrf") or ""
    assert c.get(f"/api/runs/{run_dir.name}/evaluations").json() == {"reports": [], "latest": None}
    bad = c.post(f"/api/runs/{run_dir.name}/evaluations", json={"models": ["qwen; rm -rf"]})
    assert bad.status_code == 400
    job = c.post(f"/api/runs/{run_dir.name}/evaluations", json={"models": ["m4b", "m8b"], "limit": 3}).json()
    deadline = time.time() + 120
    while time.time() < deadline:
        status = c.get(f"/api/jobs/{job['job_id']}").json()
        if status["status"] in {"completed", "failed"}:
            break
        time.sleep(0.3)
    assert status["status"] == "completed", status
    listed = c.get(f"/api/runs/{run_dir.name}/evaluations").json()
    assert [r["modelo"] for r in listed["reports"]] == ["ollama:m4b", "ollama:m8b"] and listed["latest"]["chat"]
    name = listed["reports"][0]["file"].split("/")[1]
    assert c.get(f"/api/runs/{run_dir.name}/evaluations/{name}").status_code == 200
    assert c.get(f"/api/runs/{run_dir.name}/evaluations/..%2Fevidence.json").status_code == 404
