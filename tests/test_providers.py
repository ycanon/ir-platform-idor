"""Proveedores LLM en la nube (mejora opcional O9) con transporte HTTP simulado: sin red ni claves reales."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from idor_ir.agents import providers
from idor_ir.agents.llm import LLMError
from idor_ir.agents.providers import (
    PROVIDERS,
    LLMConfig,
    Ping,
    build_client,
    list_models,
    validate_api_key,
    validate_base_url,
)
from idor_ir.config import Settings
from idor_ir.web.app import create_app
from tests.test_detection import synthetic_csv  # noqa: F401

FAKE_KEY = "sk-test-FAKEKEY0123456789abcdef"  # valor ficticio para pruebas


def _cfg(provider: str, model: str = "modelo-x", key: str | None = FAKE_KEY) -> LLMConfig:
    spec = PROVIDERS[provider]
    return LLMConfig(
        provider=provider,
        base_url=spec.base_url or spec.default_url,
        model=model,
        api_key=SecretStr(key) if key else None,
    )


def _chat(content: str) -> dict[str, Any]:
    return {"choices": [{"message": {"content": content}, "finish_reason": "stop"}]}


def test_openai_request_shape_and_parsing() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_chat('```json\n{"status": "ok"}\n```'))

    client = build_client(_cfg("openai"), transport=httpx.MockTransport(handler))
    assert client.generate("sys", "user", Ping, 64).status == "ok"  # type: ignore[union-attr]
    body = json.loads(seen[0].content)
    assert seen[0].url == "https://api.openai.com/v1/chat/completions"
    assert seen[0].headers["authorization"] == f"Bearer {FAKE_KEY}"
    assert body["response_format"]["type"] == "json_schema"
    assert "temperature" not in body and body["max_completion_tokens"] >= providers.CLOUD_MIN_TOKENS
    assert "JSON" in body["messages"][0]["content"]  # el esquema también va en el prompt


def test_retry_without_optional_params_on_400() -> None:
    bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        if len(bodies) == 1:
            return httpx.Response(400, json={"error": {"message": "response_format not supported"}})
        return httpx.Response(200, json=_chat('{"status": "ok"}'))

    client = build_client(_cfg("deepseek"), transport=httpx.MockTransport(handler))
    client.generate("s", "u", Ping, 64)
    assert bodies[0]["response_format"] == {"type": "json_object"} and bodies[0]["temperature"] == 0
    assert "response_format" not in bodies[1] and "temperature" not in bodies[1]


def test_provider_error_never_leaks_key() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        msg = f"Incorrect API key provided: {FAKE_KEY}. Bearer {FAKE_KEY}"
        return httpx.Response(401, json={"error": {"type": "invalid_request_error", "message": msg}})

    client = build_client(_cfg("openai"), transport=httpx.MockTransport(handler))
    with pytest.raises(LLMError) as exc:
        client.generate("s", "u", Ping, 64)
    assert "HTTP 401" in str(exc.value)
    assert FAKE_KEY not in str(exc.value) and FAKE_KEY[:12] not in str(exc.value)


def test_anthropic_tool_use() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "content": [{"type": "tool_use", "name": "registrar_resultado", "input": {"status": "ok"}}],
                "stop_reason": "tool_use",
            },
        )

    client = build_client(_cfg("anthropic"), transport=httpx.MockTransport(handler))
    assert client.generate("s", "u", Ping, 64).status == "ok"  # type: ignore[union-attr]
    body = json.loads(seen[0].content)
    assert seen[0].headers["x-api-key"] == FAKE_KEY and seen[0].headers["anthropic-version"]
    assert body["tool_choice"] == {"type": "tool", "name": "registrar_resultado"}
    assert body["tools"][0]["input_schema"]["properties"]["status"]


def test_list_models_filters_and_formats() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/api/tags"):
            return httpx.Response(200, json={"models": [{"name": "qwen3:4b"}, {"name": "llama3.2:3b"}]})
        assert request.url.params.get("limit") == "1000"  # Anthropic pagina; se piden todos
        return httpx.Response(200, json={"data": [{"id": "claude-x"}, {"id": "text-embedding-3"}, {"id": "a-tts"}]})

    transport = httpx.MockTransport(handler)
    assert list_models(_cfg("anthropic"), transport) == ["claude-x"]
    assert list_models(_cfg("ollama", key=None), transport) == ["llama3.2:3b", "qwen3:4b"]
    with pytest.raises(LLMError, match="API key"):
        list_models(_cfg("openai", key=None), transport)


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        ("http://10.0.0.20:11434", True),
        ("http://localhost:1234/v1/", True),
        ("https://mi-llm.example.com/v1", True),
        ("http://mi-llm.example.com/v1", False),  # API key en claro por Internet
        ("https://user:pass@example.com", False),
        ("https://example.com/v1?x=1", False),
        ("ftp://192.168.1.1", False),
        ("javascript:alert(1)", False),
    ],
)
def test_validate_base_url(url: str, ok: bool) -> None:
    if ok:
        assert not validate_base_url(url).endswith("/")
    else:
        with pytest.raises(ValueError):
            validate_base_url(url)


def test_validate_api_key_blocks_header_injection() -> None:
    assert validate_api_key(f"  {FAKE_KEY} ") == FAKE_KEY
    for bad in ("short", f"{FAKE_KEY}\r\nX-Evil: 1", "con espacio dentro 123456"):
        with pytest.raises(ValueError):
            validate_api_key(bad)


# --------------------------------------------------------------------------- web
@pytest.fixture
def web(synthetic_csv: Path, tmp_path: Path) -> TestClient:  # noqa: F811
    data = tmp_path / "data"
    data.mkdir()
    (data / "synthetic.csv").write_bytes(synthetic_csv.read_bytes())
    c = TestClient(create_app(Settings(data_dir=data, output_dir=tmp_path / "out")))
    c.get("/")
    c.headers["X-CSRF-Token"] = c.cookies.get("irp_csrf") or ""
    return c


def test_web_key_is_write_only(web: TestClient) -> None:
    r = web.post("/api/llm/config", json={"provider": "openai", "api_key": FAKE_KEY, "model": "gpt-x"})
    assert r.status_code == 200 and FAKE_KEY not in r.text
    openai = next(p for p in r.json()["providers"] if p["id"] == "openai")
    assert openai["key_configured"] and openai["key_hint"] == "••••cdef"
    assert FAKE_KEY not in web.get("/api/llm").text
    too_long = web.post("/api/llm/config", json={"provider": "openai", "api_key": FAKE_KEY * 30})
    assert too_long.status_code == 422 and FAKE_KEY not in too_long.text  # el 422 no devuelve el valor
    assert (
        web.post("/api/llm/config", json={"provider": "openai", "base_url": "https://evil.example"}).status_code == 400
    )
    cleared = web.post("/api/llm/config", json={"provider": "openai", "clear_key": True}).json()
    assert not next(p for p in cleared["providers"] if p["id"] == "openai")["key_configured"]


def test_web_activation_rules_and_status(web: TestClient) -> None:
    assert web.post("/api/llm/config", json={"provider": "anthropic", "activate": True}).status_code == 400
    web.post(
        "/api/llm/config", json={"provider": "anthropic", "api_key": FAKE_KEY, "model": "claude-x", "activate": True}
    )
    status = web.get("/api/llm/status").json()
    assert status == {**status, "provider": "anthropic", "ready": True, "off_lan": True}
    ollama = web.post("/api/llm/config", json={"provider": "ollama", "base_url": "http://10.0.0.5:11434"}).json()
    assert next(p for p in ollama["providers"] if p["id"] == "ollama")["base_url"] == "http://10.0.0.5:11434"


def _wait(c: TestClient, job_id: str, statuses: set[str]) -> dict[str, Any]:
    end = time.time() + 60
    while time.time() < end:
        job = c.get(f"/api/jobs/{job_id}").json()
        if job["status"] in statuses:
            return job
        time.sleep(0.2)
    raise AssertionError(job)


def test_cloud_agents_require_consent_and_never_send_raw_tokens(
    web: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.content.decode())
        if request.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": "modelo-x"}]})
        return httpx.Response(200, json=_chat("no es json"))  # fuerza el fallback determinista

    real_client = providers._client
    monkeypatch.setattr(providers, "_client", lambda transport: real_client(httpx.MockTransport(handler)))

    job = web.post("/api/analyses", json={"dataset": "synthetic.csv"}).json()
    run_id = _wait(web, job["job_id"], {"completed", "failed"})["result"]["run_id"]
    web.post("/api/llm/config", json={"provider": "openai", "api_key": FAKE_KEY, "model": "modelo-x", "activate": True})

    denied = web.post(f"/api/runs/{run_id}/agents", json={"use_llm": True})
    assert denied.status_code == 400 and "confirme" in denied.json()["detail"]

    agents = web.post(f"/api/runs/{run_id}/agents", json={"use_llm": True, "cloud_consent": True}).json()
    waiting = _wait(web, agents["job_id"], {"awaiting_approval", "failed"})
    web.post(f"/api/jobs/{agents['job_id']}/approvals", json={"decisions": {}})
    assert waiting["status"] == "awaiting_approval"
    assert _wait(web, agents["job_id"], {"completed", "failed"})["status"] == "completed"

    report = web.get(f"/api/runs/{run_id}").json()["agents"]
    assert report["llm"] == "openai:modelo-x"
    assert report["approvals"] and set(report["approvals"].values()) == {"reject"}  # sin decisión = rechazo
    assert report["llm_data_egress"]["off_lan"] and report["llm_data_egress"]["consent"]
    prompts = [s for s in sent if "messages" in s]
    assert len(prompts) == 3  # triage, forensic, response
    assert not any("USER-ID-attacker" in s for s in prompts)  # solo pistas enmascaradas salen a la nube
    assert all(s["source"] == "fallback" for s in report["decision_log_summary"])
