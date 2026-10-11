"""Integración IR Platform ↔ servidor MCP ti-gateway por stdio real (subproceso), con servicios simulados locales."""

from __future__ import annotations

import json
import sys
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from idor_ir.config import Settings
from idor_ir.enrichment.gateway_client import GatewayLaunch
from idor_ir.enrichment.ti import enrich_run, select_ips
from idor_ir.forensics.integrity import sha256_file
from idor_ir.web.app import create_app
from tests.test_detection import synthetic_csv  # noqa: F401

FAKE_GATEWAY = str(Path(__file__).with_name("fake_gateway.py"))
VT_KEY = "vt-FAKE-0123456789abcdef0123"  # ficticias
ABUSE_KEY = "abuse-FAKE-0123456789abcdef"
RUN_ID = "20261004T000000Z-abcdef"


class _Handler(BaseHTTPRequestHandler):
    seen: list[str] = []

    def _json(self, obj: Any, code: int = 200) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        type(self).seen.append(f"{self.path} key={self.headers.get('x-apikey') or self.headers.get('Key') or ''}")
        if self.path.startswith("/vt/api/v3/ip_addresses/"):
            mal = 4 if self.path.endswith("73.130.229.200") else 0
            return self._json(
                {
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {"malicious": mal, "harmless": 70},
                            "as_owner": "COMCAST-7922",
                            "country": "US",
                        }
                    }
                }
            )
        if self.path.startswith("/abuseipdb/api/v2/check"):
            return self._json(
                {
                    "data": {
                        "abuseConfidenceScore": 30,
                        "totalReports": 3,
                        "numDistinctUsers": 2,
                        "usageType": "Fixed Line ISP",
                        "countryCode": "US",
                    }
                }
            )
        return self._json({"error": {"code": "NotFound"}}, 404)

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def upstream() -> Iterator[str]:
    _Handler.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def _run_dir(settings: Settings, ips: list[str]) -> Path:
    run_dir = settings.output_dir / RUN_ID
    run_dir.mkdir(parents=True)
    top = [{"rank": i + 1, "ip": ip, "campaign_id": "C1", "risk_level": "critico"} for i, ip in enumerate(ips)]
    (run_dir / "evidence.json").write_text(json.dumps({"top20_ips": top}), encoding="utf-8")
    return run_dir


def test_select_ips_skips_private() -> None:
    targets, skipped = select_ips({"top20_ips": [{"ip": "10.0.0.1"}, {"ip": "8.8.8.8"}, {"ip": "203.0.113.9"}]})
    assert [t["ip"] for t in targets] == ["8.8.8.8"] and len(skipped) == 2


def test_enrich_run_through_real_stdio_gateway(tmp_path: Path, upstream: str) -> None:
    settings = Settings(data_dir=tmp_path, output_dir=tmp_path / "out")
    run_dir = _run_dir(settings, ["73.130.229.200", "10.0.0.5", "24.163.83.34"])
    launch = GatewayLaunch(
        data_dir=settings.output_dir / "ti_gateway",
        client_name="pytest",
        keys={"virustotal": SecretStr(VT_KEY), "abuseipdb": SecretStr(ABUSE_KEY)},
        per_minute={"virustotal": 1000},
        command=[sys.executable, FAKE_GATEWAY, upstream],
    )
    report = enrich_run(run_dir, settings, launch, ["virustotal", "abuseipdb"], {"confirmed": True})

    assert [s["ip"] for s in report["skipped"]] == ["10.0.0.5"]
    first, second = report["results"]
    assert first["verdict"] == "malicioso" and second["verdict"] == "sospechoso"  # VT 4 motores / AbuseIPDB 30 %
    assert first["context"]["usage_type"] == "Fixed Line ISP"
    assert report["ips_sent"] == ["24.163.83.34", "73.130.229.200"] and report["stats"]["queried"] == 4
    assert any(VT_KEY in s for s in _Handler.seen)  # la clave llegó al servicio (por la cabecera)…
    artifact = run_dir / "enrichment" / "ti_enrichment.json"
    manifest = json.loads((run_dir / "enrichment" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["artifacts"][0]["sha256"] == sha256_file(artifact)
    state_dir = settings.output_dir / "ti_gateway"
    for path in (
        artifact,
        settings.output_dir / "custody_log.jsonl",
        state_dir / "audit.jsonl",
        state_dir / "cache.json",
    ):
        text = path.read_text(encoding="utf-8")
        assert VT_KEY not in text and ABUSE_KEY not in text  # …pero no quedó en ningún archivo

    again = enrich_run(run_dir, settings, launch, ["virustotal", "abuseipdb"], {"confirmed": True})
    assert again["stats"]["cached"] == 4 and again["ips_sent"] == []  # segunda vez: todo desde la caché compartida


# --------------------------------------------------------------------------- web
@pytest.fixture
def web(tmp_path: Path, upstream: str) -> tuple[TestClient, Settings]:
    settings = Settings(
        data_dir=tmp_path / "data",
        output_dir=tmp_path / "out",
        ti_gateway_command=[sys.executable, FAKE_GATEWAY, upstream],
    )
    settings.data_dir.mkdir()
    c = TestClient(create_app(settings))
    c.get("/")
    c.headers["X-CSRF-Token"] = c.cookies.get("irp_csrf") or ""
    return c, settings


def _wait(c: TestClient, job_id: str) -> dict[str, Any]:
    end = time.time() + 90
    while time.time() < end:
        job = c.get(f"/api/jobs/{job_id}").json()
        if job["status"] in {"completed", "failed"}:
            return job
        time.sleep(0.3)
    raise AssertionError(job)


def test_web_catalog_keys_consent_and_job(web: tuple[TestClient, Settings]) -> None:
    c, settings = web
    catalog = c.get("/api/ti").json()["sources"]  # el catálogo viene del gateway por MCP
    assert {s["id"] for s in catalog} == {
        "virustotal",
        "otx",
        "abuseipdb",
        "greynoise",
        "ipinfo",
        "shodan",
        "abusech",
        "misp",
    }
    assert next(s for s in catalog if s["id"] == "virustotal")["publishes_queries"]

    r = c.post("/api/ti/config", json={"keys": {"virustotal": VT_KEY}, "per_minute": {"virustotal": 1000}})
    assert r.status_code == 200 and VT_KEY not in r.text
    vt = next(s for s in r.json()["sources"] if s["id"] == "virustotal")
    assert vt["key_configured"] and vt["key_hint"] == "••••0123" and vt["origin"] == "ui" and vt["per_minute"] == 1000
    bad = c.post("/api/ti/config", json={"keys": {"virustotal": VT_KEY * 40}})
    assert bad.status_code == 422 and VT_KEY not in bad.text  # el 422 no devuelve el valor
    assert c.post("/api/ti/config", json={"keys": {"inventada": VT_KEY}}).status_code == 400

    check = c.post("/api/ti/test", json={"source": "virustotal"}).json()
    assert check["ok"] and VT_KEY not in json.dumps(check)

    _run_dir(settings, ["73.130.229.200", "192.168.0.10"])
    denied = c.post(f"/api/runs/{RUN_ID}/enrich", json={"sources": ["virustotal"]})
    assert denied.status_code == 400 and "Confirme" in denied.json()["detail"]
    missing = c.post(f"/api/runs/{RUN_ID}/enrich", json={"sources": ["shodan"], "consent": True})
    assert missing.status_code == 400 and "shodan" in missing.json()["detail"]

    job = c.post(f"/api/runs/{RUN_ID}/enrich", json={"sources": ["virustotal"], "consent": True}).json()
    assert _wait(c, job["job_id"])["status"] == "completed"
    ti = c.get(f"/api/runs/{RUN_ID}").json()["enrichment"]
    assert ti["results"][0]["verdict"] == "malicioso" and ti["consent"]["sources"] == ["virustotal"]
    assert c.get(f"/api/runs/{RUN_ID}/download/enrichment/ti_enrichment.json").status_code == 200
    used = next(s for s in c.get("/api/ti").json()["sources"] if s["id"] == "virustotal")["quota_used"]
    assert used == 2  # 1 validación + 1 consulta, contados por el gateway

    cleared = c.post("/api/ti/config", json={"clear": ["virustotal"]}).json()
    assert not next(s for s in cleared["sources"] if s["id"] == "virustotal")["key_configured"]


def test_web_synthetic_dataset_sends_nothing(synthetic_csv: Path, web: tuple[TestClient, Settings]) -> None:  # noqa: F811
    c, settings = web
    (settings.data_dir / "synthetic.csv").write_bytes(synthetic_csv.read_bytes())
    run_id = _wait(c, c.post("/api/analyses", json={"dataset": "synthetic.csv"}).json()["job_id"])["result"]["run_id"]
    c.post("/api/ti/config", json={"keys": {"virustotal": VT_KEY}})
    job = c.post(f"/api/runs/{run_id}/enrich", json={"sources": ["virustotal"], "consent": True}).json()
    assert _wait(c, job["job_id"])["status"] == "completed"
    ti = c.get(f"/api/runs/{run_id}").json()["enrichment"]
    assert ti["results"] == [] and ti["skipped"] and _Handler.seen == []  # solo IPs privadas/documentación
    checks = c.post(f"/api/runs/{run_id}/verify").json()["checks"]
    assert any(ch["check"] == "artefacto enrichment/ti_enrichment.json" and ch["ok"] for ch in checks)


def test_web_misp_url_is_validated_and_required(web: tuple[TestClient, Settings]) -> None:
    c, _ = web
    c.get("/api/ti")
    bad = c.post("/api/ti/config", json={"urls": {"misp": "http://misp.example.com"}})
    assert bad.status_code == 400 and "misp.example.com" not in bad.text  # el error no repite la URL
    r = c.post("/api/ti/config", json={"keys": {"misp": "misp-FAKE-0123456789abcdef0123"}})
    misp = next(s for s in r.json()["sources"] if s["id"] == "misp")
    assert misp["needs_url"] and misp["key_configured"] and not misp["usable"]  # clave sin URL: no utilizable
    r = c.post("/api/ti/config", json={"urls": {"misp": "https://misp.empresa.test/"}})
    misp = next(s for s in r.json()["sources"] if s["id"] == "misp")
    assert misp["base_url"] == "https://misp.empresa.test" and misp["usable"]
    r = c.post("/api/ti/config", json={"urls": {"misp": ""}})
    assert next(s for s in r.json()["sources"] if s["id"] == "misp")["base_url"] is None


def test_web_misp_certificate_is_validated_and_never_a_private_key(web: tuple[TestClient, Settings]) -> None:
    from tests.test_ti_gateway import TEST_CERT

    c, _ = web
    c.get("/api/ti")
    bad = c.post(
        "/api/ti/config", json={"ca_pems": {"misp": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"}}
    )
    assert bad.status_code == 400 and "clave privada" in bad.json()["detail"]
    ok = c.post("/api/ti/config", json={"ca_pems": {"misp": TEST_CERT}})
    misp = next(s for s in ok.json()["sources"] if s["id"] == "misp")
    assert misp["ca_fingerprint"] and "BEGIN" not in ok.text  # solo la huella vuelve al navegador
    cleared = c.post("/api/ti/config", json={"ca_pems": {"misp": ""}})
    assert next(s for s in cleared.json()["sources"] if s["id"] == "misp")["ca_fingerprint"] is None


def test_web_misp_skip_tls_only_internal_and_audited(web: tuple[TestClient, Settings]) -> None:
    c, settings = web
    c.get("/api/ti")
    c.post("/api/ti/config", json={"urls": {"misp": "https://misp.comunidad.example"}})
    ext = c.post("/api/ti/config", json={"tls_insecure": {"misp": True}})
    assert ext.status_code == 400 and "red interna" in ext.json()["detail"]
    ok = c.post("/api/ti/config", json={"urls": {"misp": "https://10.0.0.70"}, "tls_insecure": {"misp": True}})
    assert next(s for s in ok.json()["sources"] if s["id"] == "misp")["tls_verify"] is False
    custody = (settings.output_dir / "custody_log.jsonl").read_text(encoding="utf-8")
    assert "ti_tls_verification_changed" in custody and "sin verificar" in custody
    # Si la URL pasa a ser externa, la excepción se desactiva sola.
    moved = c.post("/api/ti/config", json={"urls": {"misp": "https://misp.comunidad.example"}})
    assert next(s for s in moved.json()["sources"] if s["id"] == "misp")["tls_verify"] is True
