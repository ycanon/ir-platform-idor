"""Conversación con los agentes: streaming por proveedor, contexto fijo, registro con hash y API web."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from idor_ir.agents import chat
from idor_ir.agents.llm import LLMError
from idor_ir.agents.providers import PROVIDERS, LLMConfig, build_client
from idor_ir.config import Settings
from idor_ir.forensics.integrity import sha256_file
from idor_ir.pipeline import run_analysis
from idor_ir.web.app import create_app
from tests.test_detection import synthetic_csv  # noqa: F401

FAKE_KEY = "sk-test-FAKEKEY0123456789abcdef"


def _sse(events: list[Any]) -> bytes:
    return "".join(f"data: {json.dumps(e) if not isinstance(e, str) else e}\n\n" for e in events).encode()


def _cfg(provider: str) -> LLMConfig:
    spec = PROVIDERS[provider]
    return LLMConfig(
        provider=provider, base_url=spec.base_url or spec.default_url, model="m", api_key=SecretStr(FAKE_KEY)
    )


class FakeLLM:
    name = "fake:modelo"

    def __init__(self, answer: str = "C1 usó 4 tokens desde 5 IPs.\nFuente: caso.campaigns") -> None:
        self.answer = answer
        self.calls: list[tuple[str, list[dict[str, str]]]] = []
        self.max_tokens: list[int] = []
        self.last_stats: dict[str, Any] = {"ttft_s": 0.1, "prompt_tokens": 40, "prompt_s": 0.01,
                                           "prompt_tokens_are_processed": True, "output_tokens": 12, "gen_s": 1.5}  # fmt: skip

    def stream_chat(
        self, system: str, messages: list[dict[str, str]], max_tokens: int, on_delta: Callable[[str], None]
    ) -> str:
        self.calls.append((system, list(messages)))
        self.max_tokens.append(max_tokens)
        for word in self.answer.split(" "):
            on_delta(word + " ")
        return self.answer


# --------------------------------------------------------------------------- streaming por familia de API
def test_openai_compatible_stream_and_retry() -> None:
    bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        if len(bodies) == 1:
            return httpx.Response(400, json={"error": {"message": "temperature not supported"}})
        events = [
            {"choices": [{"delta": {"content": "Hola "}}]},
            {"choices": [{"delta": {"content": "analista"}}]},
            "[DONE]",
        ]
        return httpx.Response(200, content=_sse(events), headers={"content-type": "text/event-stream"})

    client = build_client(_cfg("deepseek"), transport=httpx.MockTransport(handler))
    deltas: list[str] = []
    assert client.stream_chat("sys", [{"role": "user", "content": "hola"}], 100, deltas.append) == "Hola analista"  # type: ignore[union-attr]
    assert deltas == ["Hola ", "analista"] and bodies[0]["stream"] is True
    assert bodies[0]["temperature"] == 0.2 and "temperature" not in bodies[1]  # reintento mínimo
    assert bodies[0]["messages"][0] == {"role": "system", "content": "sys"}


def test_anthropic_stream_and_error_without_key() -> None:
    def ok(request: httpx.Request) -> httpx.Response:
        events = [{"type": "message_start"}, {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "Sí"}},
                  {"type": "content_block_delta", "delta": {"type": "text_delta", "text": ", C1."}}, {"type": "message_stop"}]  # fmt: skip
        return httpx.Response(200, content=_sse(events))

    client = build_client(_cfg("anthropic"), transport=httpx.MockTransport(ok))
    assert client.stream_chat("s", [{"role": "user", "content": "q"}], 50, lambda _d: None) == "Sí, C1."  # type: ignore[union-attr]

    def denied(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"type": "authentication_error", "message": f"bad key {FAKE_KEY}"}})

    bad = build_client(_cfg("anthropic"), transport=httpx.MockTransport(denied))
    with pytest.raises(LLMError) as exc:
        bad.stream_chat("s", [{"role": "user", "content": "q"}], 50, lambda _d: None)  # type: ignore[union-attr]
    assert "401" in str(exc.value) and FAKE_KEY not in str(exc.value)


# --------------------------------------------------------------------------- contexto y registro
@pytest.fixture
def run(synthetic_csv: Path, tmp_path: Path) -> tuple[Path, Settings]:  # noqa: F811
    settings = Settings(data_dir=tmp_path, output_dir=tmp_path / "out")
    result = run_analysis(synthetic_csv, settings)
    return result.run_dir, settings


def test_context_per_agent(run: tuple[Path, Settings]) -> None:
    run_dir, _ = run
    triage, forensic, response = (chat.chat_context(run_dir, a) for a in ("triage", "forensic", "response"))
    # Fichas (punto 4): todas las IPs con su papel, totales rotulados y cifras por IP en tabla aparte.
    assert "cifras_por_ip" in triage and "fases" not in triage["campañas"][0]  # triage: sin detalle forense
    assert forensic["campañas"][0]["fases"] and forensic["campañas"][0]["primera_peticion"]
    ficha = response["campañas"][0]
    assert "TOTAL_de_la_campaña" in ficha and any(k.startswith("ips_todas") for k in ficha)
    assert all("verified_facts" in c for c in (triage, forensic, response))  # fuente de verdad en todos
    assert "Aún no se han ejecutado" in forensic["tu_salida_anterior"]
    assert "USER-ID-attacker" not in json.dumps(forensic)  # solo pistas enmascaradas de tokens
    for ctx in (triage, forensic, response):  # contexto compacto: acelera lectura y escritura en CPU
        assert len(json.dumps(ctx, ensure_ascii=False)) <= chat.MAX_CONTEXT_CHARS


def test_ask_records_history_and_integrity(run: tuple[Path, Settings]) -> None:
    run_dir, settings = run
    llm = FakeLLM()
    deltas: list[str] = []
    rec = chat.ask(run_dir, settings, "triage", "¿Qué\x00 priorizas?‮", llm, {"provider": "fake"}, deltas.append)
    assert rec["question"] == "¿Qué priorizas?" and "".join(deltas).strip() == llm.answer
    system, messages = llm.calls[0]
    assert (
        "<datos_incidente>" in system
        and "no confiables" in system
        and messages == [{"role": "user", "content": "¿Qué priorizas?"}]
    )

    chat.ask(run_dir, settings, "triage", "¿Y luego?", llm, {})
    assert len(llm.calls[1][1]) == 3  # historial: pregunta + respuesta anteriores + nueva pregunta
    chat.new_conversation(run_dir, settings, "triage")
    chat.ask(run_dir, settings, "triage", "Empecemos de nuevo", llm, {})
    assert len(llm.calls[2][1]) == 1  # "nueva conversación" reinicia el historial que recibe el modelo

    path = chat.chats_dir(run_dir) / "triage.jsonl"
    manifest = json.loads((chat.chats_dir(run_dir) / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["artifacts"][0]["sha256"] == sha256_file(path)
    custody = (settings.output_dir / "custody_log.jsonl").read_text(encoding="utf-8")
    assert "agent_chat" in custody and "priorizas" not in custody  # la custodia guarda el hash, no el texto

    invented = chat.ask(run_dir, settings, "forensic", "cifra", FakeLLM("Se accedieron 987654 facturas."), {})
    assert invented["unverified_numbers"] == ["987654"]
    with pytest.raises(chat.ChatError):
        chat.ask(run_dir, settings, "triage", "x" * 2001, llm, {})
    with pytest.raises(chat.ChatError, match="LLM"):
        chat.ask(run_dir, settings, "triage", "hola", None, {})


# --------------------------------------------------------------------------- web
def _wait(c: TestClient, job_id: str) -> dict[str, Any]:
    end = time.time() + 30
    while time.time() < end:
        job = c.get(f"/api/jobs/{job_id}").json()
        if job["status"] in {"completed", "failed"}:
            return job
        time.sleep(0.1)
    raise AssertionError(job)


def test_web_chat_flow(run: tuple[Path, Settings], monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir, settings = run
    c = TestClient(create_app(settings))
    c.get("/")
    c.headers["X-CSRF-Token"] = c.cookies.get("irp_csrf") or ""
    monkeypatch.setattr("idor_ir.agents.providers.build_client", lambda cfg, transport=None: FakeLLM())

    history = c.get(f"/api/runs/{run_dir.name}/chat/forensic").json()
    assert history["records"] == [] and len(history["suggestions"]) == 4 and not history["has_agents_output"]
    assert c.get(f"/api/runs/{run_dir.name}/chat/hacker").status_code == 404
    assert (
        c.post(
            f"/api/runs/{run_dir.name}/chat",
            json={"agent": "forensic", "message": "hola"},
            headers={"X-CSRF-Token": "x"},
        ).status_code
        == 403
    )

    job = c.post(f"/api/runs/{run_dir.name}/chat", json={"agent": "forensic", "message": "¿Cómo empezó?"}).json()
    done = _wait(c, job["job_id"])
    assert done["status"] == "completed" and done["result"]["answer"].startswith("C1")
    assert "".join(e["message"] for e in done["events"] if e["kind"] == "delta").strip() == done["result"]["answer"]
    records = c.get(f"/api/runs/{run_dir.name}/chat/forensic").json()["records"]
    assert records[-1]["question"] == "¿Cómo empezó?" and records[-1]["provider"] == "ollama"
    assert c.get(f"/api/runs/{run_dir.name}/download/agents/chats/forensic.jsonl").status_code == 200
    checks = c.post(f"/api/runs/{run_dir.name}/verify").json()["checks"]
    assert any(ch["check"] == "artefacto agents/chats/forensic.jsonl" and ch["ok"] for ch in checks)
    assert c.post(f"/api/runs/{run_dir.name}/chat/forensic/new").json()["ok"]

    c.post("/api/llm/config", json={"provider": "openai", "api_key": FAKE_KEY, "model": "gpt-x", "activate": True})
    cloud = c.post(f"/api/runs/{run_dir.name}/chat", json={"agent": "response", "message": "¿Por qué?"})
    assert cloud.status_code == 400 and "confirme" in cloud.json()["detail"]
    ok = c.post(
        f"/api/runs/{run_dir.name}/chat", json={"agent": "response", "message": "¿Por qué?", "cloud_consent": True}
    )
    assert _wait(c, ok.json()["job_id"])["result"]["off_lan"] is True


# --------------------------------------------------------------------------- medidas de velocidad
def test_cache_prefix_is_stable_and_limits_per_agent(run: tuple[Path, Settings]) -> None:
    """Precondición de la caché de Ollama: el inicio del prompt es idéntico byte a byte entre preguntas."""
    run_dir, settings = run
    llm = FakeLLM()
    chat.ask(run_dir, settings, "forensic", "Primera", llm, {})
    rec = chat.ask(run_dir, settings, "forensic", "Segunda", llm, {})
    (sys1, msgs1), (sys2, msgs2) = llm.calls
    assert sys1 == sys2  # instrucciones + contexto fijo: mismo texto → Ollama reutiliza el cálculo
    assert msgs2[: len(msgs1)] == msgs1  # la conversación crece al final, sin alterar lo anterior
    assert llm.max_tokens == [400, 400] and "máximo 6 viñetas de UNA línea" in sys1
    chat.ask(run_dir, settings, "triage", "Hola", llm, {})
    assert llm.max_tokens[-1] == 360 and "máximo 5 viñetas" in llm.calls[-1][0]
    st = rec["stats"]
    assert st["cache_hit"] is True and st["tokens_per_s"] == 8.0 and st["prompt_tokens_estimated"] > 500


def test_response_stats_cache_detection() -> None:
    """Cifras reales del equipo de referencia: Ollama informa el total del prompt aun con caché; la delata la velocidad."""
    msgs = [{"role": "user", "content": "x" * 320}]
    model = "ollama:qwen3"
    cold = chat.response_stats(
        {"prompt_tokens": 4074, "prompt_s": 52.9, "prompt_tokens_are_processed": True}, "s" * 10000, msgs
    )
    assert cold["cache_hit"] is False and cold["read_tokens_per_s"] == 77.0
    history = [{"model": model, "stats": cold}]
    warm = chat.response_stats({"prompt_tokens": 4379, "prompt_s": 1.8, "prompt_tokens_are_processed": True},
                               "s" * 10000, msgs, history, model)  # fmt: skip
    assert warm["cache_hit"] is True  # 2 433 tokens/s ≥ 5 × 77
    slow = chat.response_stats({"prompt_tokens": 4200, "prompt_s": 40.0, "prompt_tokens_are_processed": True},
                               "s" * 10000, msgs, history, model)  # fmt: skip
    assert slow["cache_hit"] is False  # 105 tokens/s: lectura en frío (p. ej. tras cambiar de agente)
    no_ref = chat.response_stats(
        {"prompt_tokens": 4379, "prompt_s": 1.8, "prompt_tokens_are_processed": True}, "", msgs
    )
    assert no_ref["cache_hit"] is True  # sin referencia: > 400 tokens/s en CPU solo es posible con caché
    cloud = chat.response_stats({"prompt_tokens": 3000, "cached_tokens": 2800}, "", msgs)
    assert cloud["cache_hit"] is True


def test_stream_usage_stats_openai_and_anthropic() -> None:
    def openai(request: httpx.Request) -> httpx.Response:
        assert json.loads(request.content)["stream_options"] == {"include_usage": True}
        events = [{"choices": [{"delta": {"content": "ok"}, "finish_reason": "length"}]},
                  {"choices": [], "usage": {"prompt_tokens": 1200, "completion_tokens": 5,
                                            "prompt_tokens_details": {"cached_tokens": 1024}}}, "[DONE]"]  # fmt: skip
        return httpx.Response(200, content=_sse(events))

    oa = build_client(_cfg("openai"), transport=httpx.MockTransport(openai))
    oa.stream_chat("s", [{"role": "user", "content": "q"}], 50, lambda _d: None)  # type: ignore[union-attr]
    assert oa.last_stats["prompt_tokens"] == 1200 and oa.last_stats["cached_tokens"] == 1024  # type: ignore[union-attr]
    assert oa.last_stats["done_reason"] == "length" and oa.last_stats["ttft_s"] is not None  # type: ignore[union-attr]

    def anthropic(request: httpx.Request) -> httpx.Response:
        events = [{"type": "message_start", "message": {"usage": {"input_tokens": 900, "cache_read_input_tokens": 0}}},
                  {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "ok"}},
                  {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 7}}]  # fmt: skip
        return httpx.Response(200, content=_sse(events))

    an = build_client(_cfg("anthropic"), transport=httpx.MockTransport(anthropic))
    an.stream_chat("s", [{"role": "user", "content": "q"}], 50, lambda _d: None)  # type: ignore[union-attr]
    assert an.last_stats["prompt_tokens"] == 900 and an.last_stats["output_tokens"] == 7  # type: ignore[union-attr]


def test_ollama_stream_stats(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    import langchain_ollama

    from idor_ir.agents.llm import OllamaLLM

    class FakeChatOllama:
        def __init__(self, **kwargs: Any) -> None:
            assert (
                kwargs["num_ctx"] == 8192 and kwargs["keep_alive"] == "30m"
            )  # iguales a los agentes: no rompe la caché

        def stream(self, history: Any) -> Any:
            yield SimpleNamespace(content="Hola", response_metadata={})
            yield SimpleNamespace(content="", response_metadata={
                "done": True, "done_reason": "stop", "prompt_eval_count": 35, "prompt_eval_duration": 2_000_000_000,
                "eval_count": 76, "eval_duration": 10_000_000_000, "load_duration": 100_000_000})  # fmt: skip

    monkeypatch.setattr(langchain_ollama, "ChatOllama", FakeChatOllama)
    llm = OllamaLLM("http://192.168.1.2:11434", "qwen")
    assert llm.stream_chat("s", [{"role": "user", "content": "q"}], 100, lambda _d: None) == "Hola"
    st = llm.last_stats
    assert (st["prompt_tokens"], st["prompt_s"], st["output_tokens"], st["gen_s"]) == (35, 2.0, 76, 10.0)


# --------------------------------------------------------------------------- chat híbrido y revisión (O13)
def test_data_questions_answered_from_evidence_without_model(run: tuple[Path, Settings]) -> None:
    run_dir, settings = run
    rec = chat.ask(run_dir, settings, "triage", "¿Cuántas IPs tiene C1?", None, {})  # sin LLM configurado
    assert rec["source"] == "evidencia" and "203.0.113.9" in rec["answer"] and "1 IPs" in rec["answer"]
    when = chat.ask(run_dir, settings, "forensic", "¿Cuándo ocurrió C1?", None, {})
    assert "2020-10-01" in when["answer"] and "fase 1" in when["answer"]
    with pytest.raises(chat.ChatError):  # una pregunta de criterio sí necesita el modelo
        chat.ask(run_dir, settings, "triage", "¿Qué IPs priorizarías y por qué?", None, {})


def test_model_answer_gets_code_verification_note(run: tuple[Path, Settings]) -> None:
    run_dir, settings = run
    llm = FakeLLM()
    llm.answer = "- C1 siguió activa en febrero 2021 desde 203.0.113.9.\nFuente: campañas"
    rec = chat.ask(run_dir, settings, "triage", "¿Qué pasó después?", llm, {})
    assert rec["source"] == "modelo" and rec["review"]["issues"][0]["kind"] == "fecha"
    assert "Verificación automática" in rec["review"]["note"] and "2020-10-01" in rec["review"]["note"]


def test_chat_can_use_a_different_provider_and_model(
    run: tuple[Path, Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir, settings = run
    used: list[tuple[str, str]] = []

    def fake_client(cfg: Any, transport: Any = None, **kw: Any) -> FakeLLM:
        used.append((cfg.provider, cfg.model))
        return FakeLLM()

    monkeypatch.setattr("idor_ir.agents.providers.build_client", fake_client)
    c = TestClient(create_app(settings))
    c.get("/")
    c.headers["X-CSRF-Token"] = c.cookies.get("irp_csrf") or ""
    state = c.get("/api/llm").json()
    assert state["active"] == "ollama" and state["chat"]["provider"] is None  # por defecto: igual que los agentes

    # Mismo proveedor, otro modelo.
    st = c.post("/api/llm/chat", json={"provider": None, "model": "qwen3:4b-chat"}).json()
    assert st["chat"]["effective_provider"] == "ollama" and st["chat"]["effective_model"] == "qwen3:4b-chat"
    job = c.post(f"/api/runs/{run_dir.name}/chat", json={"agent": "triage", "message": "¿Qué opinas?"}).json()
    _wait(c, job["job_id"])
    assert used[-1] == ("ollama", "qwen3:4b-chat")

    # Otro proveedor: sin API key se rechaza; con clave, el chat usa la nube y los agentes siguen en Ollama.
    bad = c.post("/api/llm/chat", json={"provider": "openai", "model": "gpt-x"})
    assert bad.status_code == 400 and "API key" in bad.json()["detail"]
    c.post("/api/llm/config", json={"provider": "openai", "api_key": FAKE_KEY})
    st = c.post("/api/llm/chat", json={"provider": "openai", "model": "gpt-x"}).json()
    assert st["active"] == "ollama" and st["chat"]["effective_provider"] == "openai" and st["chat"]["off_lan"]
    need = c.post(f"/api/runs/{run_dir.name}/chat", json={"agent": "triage", "message": "¿Qué opinas?"})
    assert need.status_code == 400 and "confirme" in need.json()["detail"]
    ok = c.post(
        f"/api/runs/{run_dir.name}/chat", json={"agent": "triage", "message": "¿Qué opinas?", "cloud_consent": True}
    )
    assert _wait(c, ok.json()["job_id"])["result"]["provider"] == "openai" and used[-1] == ("openai", "gpt-x")
    # Las preguntas de dato no salen del equipo: no piden autorización aunque el chat esté en la nube.
    data = c.post(f"/api/runs/{run_dir.name}/chat", json={"agent": "triage", "message": "¿Cuántas IPs tiene C1?"})
    assert data.status_code == 200 and _wait(c, data.json()["job_id"])["result"]["source"] == "evidencia"
    # Volver a "igual que los agentes".
    st = c.post("/api/llm/chat", json={"provider": "", "model": ""}).json()
    assert st["chat"]["effective_provider"] == "ollama" and st["chat"]["provider"] is None
