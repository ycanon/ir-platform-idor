"""Tests de la interfaz web: seguridad y flujo de la API con el dataset SINTÉTICO."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from idor_ir.config import Settings
from idor_ir.web.app import create_app
from tests.test_detection import synthetic_csv  # noqa: F401


@pytest.fixture
def client(synthetic_csv: Path, tmp_path: Path) -> TestClient:  # noqa: F811
    data = tmp_path / "data"
    data.mkdir()
    (data / "synthetic.csv").write_bytes(synthetic_csv.read_bytes())
    app = create_app(Settings(data_dir=data, output_dir=tmp_path / "out"))
    c = TestClient(app)
    c.get("/")  # obtiene la cookie CSRF
    return c


def _csrf(c: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": c.cookies.get("irp_csrf") or ""}


CUSTODY = {
    "collected_by": "Analista SOC (prueba)",
    "collected_at": "2026-10-05T08:30",
    "source_system": "API Gateway · producción",
    "source_timezone": "UTC",
    "case_id": "INC-0001",
}


def _custody(**overrides: str) -> dict[str, str]:
    return {"X-Custody-Metadata": quote(json.dumps({**CUSTODY, **overrides}))}


def _upload(c: TestClient, body: bytes, name: str = "logs.csv", **overrides: str):  # type: ignore[no-untyped-def]
    headers = {**_csrf(c), "X-Filename": quote(name), **_custody(**overrides)}
    return c.post("/api/datasets/upload", content=body, headers=headers)


def _wait(c: TestClient, job_id: str, statuses: set[str], timeout: float = 60) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        job = c.get(f"/api/jobs/{job_id}").json()
        if job["status"] in statuses:
            return job
        time.sleep(0.2)
    raise AssertionError(f"timeout esperando {statuses}: {job}")


def test_security_headers_and_csrf(client: TestClient) -> None:
    r = client.get("/")
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert client.post("/api/analyses", json={"dataset": "synthetic.csv"}).status_code == 403  # sin token CSRF
    assert client.get("/docs").status_code == 404  # Swagger UI (CDN externo) desactivado
    assert client.get("/openapi.json").status_code == 200


def test_path_traversal_and_sensitive_downloads_blocked(client: TestClient) -> None:
    assert client.get("/api/runs/..%2F..%2Fetc").status_code == 404
    assert client.post("/api/analyses", json={"dataset": "../secret.csv"}, headers=_csrf(client)).status_code == 404
    assert client.get("/api/runs/20200101T000000Z-abcdef/download/sensitive/token_map.json").status_code == 404
    for artifact in ("work/parsed.parquet", "agents/actions/../../sensitive/token_map.json", "agents/actions/x.txt"):
        assert client.get(f"/api/runs/20200101T000000Z-abcdef/download/{artifact}").status_code == 404


def test_upload_validation(client: TestClient) -> None:
    bad_ext = client.post("/api/datasets/upload", content=b"x", headers={**_csrf(client), "X-Filename": "a.exe"})
    assert bad_ext.status_code == 400
    no_custody = client.post(
        "/api/datasets/upload", content=b"a,b\n1,2\n", headers={**_csrf(client), "X-Filename": "x.csv"}
    )
    assert no_custody.status_code == 400 and "custodia" in no_custody.json()["detail"]
    missing_field = _upload(client, b"a,b\n1,2\n", collected_by="")
    assert missing_field.status_code == 400 and "collected_by" in missing_field.json()["detail"]
    future = _upload(client, b"a,b\n1,2\n", collected_at="2999-01-01T00:00")
    assert future.status_code == 400
    assert _upload(client, b"a,b\n1,2\n", name="x.csv").status_code == 400  # encabezado CSV inválido
    assert _upload(client, b"a,b\n1,2\n", source_sha256="zz").status_code == 400
    names = [d["name"] for d in client.get("/api/datasets").json()]
    assert names == ["synthetic.csv"]  # el archivo rechazado no queda en disco


def test_upload_custody_intake_read_only_and_analysis(client: TestClient, synthetic_csv: Path, tmp_path: Path) -> None:  # noqa: F811
    body = synthetic_csv.read_bytes()
    sha = hashlib.sha256(body).hexdigest()
    # Hash informado en origen distinto → se rechaza y no queda nada en disco.
    assert _upload(client, body, source_sha256="0" * 64).status_code == 400
    assert [d["name"] for d in client.get("/api/datasets").json()] == ["synthetic.csv"]

    r = _upload(client, body, name="facturación logs.csv", source_sha256=sha.upper())
    assert r.status_code == 200, r.text
    up = r.json()
    assert up["sha256"] == sha and up["read_only"] and up["source_hash_match"] is True
    assert up["evidence_id"].startswith("EV-")  # se genera si el analista no lo indica
    listed = {d["name"]: d for d in client.get("/api/datasets").json()}[up["name"]]
    assert listed["custody"] and listed["read_only"]

    stored = tmp_path / "data" / up["name"]
    sidecar = json.loads(stored.with_name(stored.name + ".custody.json").read_text(encoding="utf-8"))
    assert sidecar["intake"]["collected_by"] == CUSTODY["collected_by"]
    assert sidecar["automatic"]["original_filename"] == "facturación logs.csv"

    job = client.post("/api/analyses", json={"dataset": up["name"]}, headers=_csrf(client)).json()
    done = _wait(client, job["job_id"], {"completed", "failed"})
    assert done["status"] == "completed", done
    run_id = done["result"]["run_id"]
    summary = client.get(f"/api/runs/{run_id}").json()
    assert summary["custody_intake"]["intake"]["evidence_id"] == up["evidence_id"]
    assert summary["manifest"]["parameters"]["source_read_only"] is True
    assert any(a["name"] == "custody_intake.json" for a in summary["manifest"]["artifacts"])
    for artifact in ("custody_intake.json", "profile.json", "metrics.json", "detection.json"):
        assert client.get(f"/api/runs/{run_id}/download/{artifact}").status_code == 200

    log = (tmp_path / "out" / "custody_log.jsonl").read_text(encoding="utf-8")
    assert '"evidence_received"' in log and '"custody_intake_verified"' in log

    # Si el archivo se altera después de recibirlo, el análisis se niega (cadena de custodia rota).
    stored.chmod(0o644)
    stored.write_bytes(body + b"\n")
    job = client.post("/api/analyses", json={"dataset": up["name"]}, headers=_csrf(client)).json()
    failed = _wait(client, job["job_id"], {"completed", "failed"})
    assert failed["status"] == "failed" and "custodia" in failed["error"]


def test_full_flow_analysis_agents_approvals(client: TestClient) -> None:
    job = client.post("/api/analyses", json={"dataset": "synthetic.csv"}, headers=_csrf(client)).json()
    done = _wait(client, job["job_id"], {"completed", "failed"})
    assert done["status"] == "completed", done
    run_id = done["result"]["run_id"]
    summary = client.get(f"/api/runs/{run_id}").json()
    assert summary["evidence"]["campaigns"][0]["status"] == "alta_confianza"
    assert "USER-ID-attacker" not in client.get(f"/api/runs/{run_id}").text
    assert client.get(f"/api/runs/{run_id}/download/iocs.csv").status_code == 200

    agents = client.post(f"/api/runs/{run_id}/agents", json={"use_llm": False}, headers=_csrf(client)).json()
    waiting = _wait(client, agents["job_id"], {"awaiting_approval", "failed"})
    assert waiting["status"] == "awaiting_approval" and waiting["pending_actions"]
    automatic = {a["action_id"] for a in waiting["automatic_actions"]}  # se muestran sin selector en la interfaz
    assert automatic and not automatic & {a["action_id"] for a in waiting["pending_actions"]}
    first = waiting["pending_actions"][0]["action_id"]
    r = client.post(
        f"/api/jobs/{agents['job_id']}/approvals",
        json={"decisions": {first: "approve", "A99": "approve"}},
        headers=_csrf(client),
    )
    assert r.json()["accepted"] == {first: "approve"}  # IDs desconocidos se descartan
    assert _wait(client, agents["job_id"], {"completed", "failed"})["status"] == "completed"
    report = client.get(f"/api/runs/{run_id}").json()["agents"]
    assert report["approvals"][first] == "approve"
    assert automatic <= {e["action_id"] for e in report["executed"]}  # automáticas ejecutadas sin aprobación
    artifact = "agents/" + report["executed"][0]["artifact"]
    dl = client.get(f"/api/runs/{run_id}/download/{artifact}")
    assert dl.status_code == 200 and "DRY-RUN" in dl.text.upper()
    verify = client.post(f"/api/runs/{run_id}/verify", headers=_csrf(client)).json()
    assert verify["ok"] and verify["source_checked"]
    assert "irp_agent_nodes_total" in client.get("/metrics").text


def test_access_token_login(synthetic_csv: Path, tmp_path: Path) -> None:  # noqa: F811
    app = create_app(Settings(data_dir=tmp_path, output_dir=tmp_path / "out", access_token="s3cret-token-xyz"))  # noqa: S106 (valor de prueba)
    c = TestClient(app)
    assert c.get("/api/runs").status_code == 401
    assert c.get("/", follow_redirects=False).status_code == 303
    assert c.post("/login", data={"access_token": "wrong", "user": "ana"}).status_code == 401
    assert c.post("/login", data={"access_token": "s3cret-token-xyz"}).status_code == 401  # sin nombre (auditoría)
    r = c.post("/login", data={"access_token": "s3cret-token-xyz", "user": "Ana Analista"}, follow_redirects=False)
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "s3cret" not in cookie and "Max-Age" in cookie
    assert "Secure" not in cookie  # HTTP en el test: Secure solo por HTTPS o IRP_COOKIE_SECURE
    assert c.get("/api/runs").status_code == 200
    cfg = c.get("/api/config").json()
    assert cfg["user"] == "Ana Analista" and cfg["role"] == "operador_unico" and cfg["can_approve"]
    # Una cookie alterada (rol cambiado sin la firma) no abre la API.
    value = c.cookies.get("irp_session") or ""
    c.cookies.set("irp_session", value.replace(".", "x.", 1))
    assert c.get("/api/runs").status_code == 401


def _login(c: TestClient, token: str, user: str) -> None:
    c.post("/login", data={"access_token": token, "user": user}, follow_redirects=False)
    c.get("/")  # cookie CSRF


def test_rbac_analyst_cannot_approve_or_change_providers(synthetic_csv: Path, tmp_path: Path) -> None:  # noqa: F811
    """Separación de funciones: el analista recomienda/ejecuta en dry-run; solo el aprobador decide y configura."""
    data = tmp_path / "data"
    data.mkdir()
    (data / "synthetic.csv").write_bytes(synthetic_csv.read_bytes())
    settings = Settings(
        data_dir=data, output_dir=tmp_path / "out",
        access_token="analyst-token-0123456789", approver_token="approver-token-0123456789",  # noqa: S106
    )  # fmt: skip
    analyst, approver = TestClient(create_app(settings)), None
    _login(analyst, "analyst-token-0123456789", "ana")
    assert analyst.get("/api/config").json()["role"] == "analista"
    assert analyst.post("/api/llm/config", json={"provider": "ollama"}, headers=_csrf(analyst)).status_code == 403
    assert analyst.post("/api/ti/config", json={}, headers=_csrf(analyst)).status_code == 403
    job = analyst.post("/api/analyses", json={"dataset": "synthetic.csv"}, headers=_csrf(analyst)).json()
    run_id = _wait(analyst, job["job_id"], {"completed", "failed"})["result"]["run_id"]
    agents = analyst.post(f"/api/runs/{run_id}/agents", json={"use_llm": False}, headers=_csrf(analyst)).json()
    waiting = _wait(analyst, agents["job_id"], {"awaiting_approval", "failed"})
    first = waiting["pending_actions"][0]["action_id"]
    url = f"/api/jobs/{agents['job_id']}/approvals"
    assert analyst.post(url, json={"decisions": {first: "approve"}}, headers=_csrf(analyst)).status_code == 403

    # El aprobador usa la MISMA app (misma clave de sesión) con su propia sesión.
    approver = TestClient(analyst.app)
    _login(approver, "approver-token-0123456789", "carlos ciso")
    assert approver.get("/api/config").json()["role"] == "aprobador"
    r = approver.post(url, json={"decisions": {first: "approve"}}, headers=_csrf(approver)).json()
    assert r["decided_by"] == {"user": "carlos ciso", "role": "aprobador"}
    assert _wait(analyst, agents["job_id"], {"completed", "failed"})["status"] == "completed"
    report = analyst.get(f"/api/runs/{run_id}").json()["agents"]
    assert report["started_by"] == {"user": "ana", "role": "analista"}
    assert report["approvals_decided_by"]["user"] == "carlos ciso"
    raw = (tmp_path / "out" / "custody_log.jsonl").read_text(encoding="utf-8")
    events = [json.loads(line) for line in raw.splitlines()]
    done = next(e for e in events if e["event"] == "agents_completed")
    assert done["details"]["approvals_decided_by"] == {"user": "carlos ciso", "role": "aprobador"}
    assert {"user": "ana", "role": "analista"} in [e["details"] for e in events if e["event"] == "session_started"]
    assert "approver-token" not in raw and "analyst-token" not in raw


def test_approver_token_must_differ(tmp_path: Path) -> None:
    same = "same-token-0123456789"
    with pytest.raises(ValueError, match="distinto"):
        create_app(Settings(data_dir=tmp_path, output_dir=tmp_path / "o", access_token=same, approver_token=same))


@pytest.mark.parametrize(
    ("host", "access", "approver", "ok"),
    [
        ("127.0.0.1", None, None, True),  # local de un usuario
        ("0.0.0.0", None, None, False),  # noqa: S104 - fail-closed: red sin token
        ("0.0.0.0", "short", None, False),  # noqa: S104 - token débil
        ("0.0.0.0", "a-long-access-token-123", "a-long-access-token-123", False),  # noqa: S104 - iguales
        ("0.0.0.0", "a-long-access-token-123", None, True),  # noqa: S104
    ],
)
def test_serve_is_fail_closed(tmp_path: Path, host: str, access: str | None, approver: str | None, ok: bool) -> None:
    from idor_ir.cli import serve_preflight

    settings = Settings(data_dir=tmp_path, output_dir=tmp_path / "o", access_token=access, approver_token=approver)
    assert (serve_preflight(host, settings, tls=False) is None) is ok


@pytest.mark.parametrize("access_token", [None, "s3cret-token-xyz"])
def test_metrics_token(tmp_path: Path, access_token: str | None) -> None:
    """Con IRP_METRICS_TOKEN, /metrics exige `Authorization: Bearer` (Prometheus) aunque no haya token de acceso."""
    settings = Settings(
        data_dir=tmp_path,
        output_dir=tmp_path / "out",
        access_token=access_token,
        metrics_token="metrics-ro-token-123",  # noqa: S106 (valor de prueba)
    )
    c = TestClient(create_app(settings))
    assert c.get("/metrics").status_code == 401
    assert c.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    ok = c.get("/metrics", headers={"Authorization": "Bearer metrics-ro-token-123"})
    assert ok.status_code == 200 and "irp_chat_turns_total" in ok.text
    # El token de métricas NO abre el resto de la API.
    if access_token:
        assert c.get("/api/config", headers={"Authorization": "Bearer metrics-ro-token-123"}).status_code == 401
    assert c.get("/api/health").status_code == 200


def test_metrics_token_blank_is_disabled(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path, output_dir=tmp_path / "out", metrics_token="  ")  # noqa: S106 (valor en blanco)
    assert settings.metrics_token is None
    assert TestClient(create_app(settings)).get("/metrics").status_code == 200


def test_ownership_source_is_allowlisted(client: TestClient) -> None:
    """La fuente de ownership solo puede ser un CSV de la lista blanca de data/ y distinto del log analizado."""
    h = _csrf(client)
    body = {"dataset": "synthetic.csv", "ownership": "../../etc/passwd"}
    assert client.post("/api/analyses", json=body, headers=h).status_code == 404
    body = {"dataset": "synthetic.csv", "ownership": "synthetic.csv"}
    assert client.post("/api/analyses", json=body, headers=h).status_code == 422
