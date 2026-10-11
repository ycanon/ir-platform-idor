"""Perfil del incidente: la plataforma debe servir para otros IDOR, no solo para /invoices/search.

Datasets SINTÉTICOS generados en el test (mismo esquema de 8 campos [Reto §2]):
- "orders": otro endpoint y otros nombres de parámetros (/orders/search?order_id&tenant&token).
- autenticación: un ataque con todas las respuestas 2xx autenticadas y otro con parte de las 2xx SIN credencial.
  El hecho de autenticación se debe DERIVAR de los datos (no ser un texto fijo del escenario).
"""

from __future__ import annotations

import json
import random
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from idor_ir.agents import fallback
from idor_ir.agents.context import build_context, verified_facts
from idor_ir.agents.executor import _render
from idor_ir.agents.schemas import ResponseAction
from idor_ir.config import Settings
from idor_ir.pipeline import run_analysis
from idor_ir.profile import IncidentProfile

HEADER = "timestamp,http_status,http_host,http_uri,http_method,http_referer,http_user_agent,source_ip\n"
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/87.0"
ORDERS = {
    "target_endpoint": "/orders/search",
    "object_param": "order_id",
    "scope_param": "tenant",
    "token_param": "token",
    "object_label": "pedido",
    "object_label_plural": "pedidos",
    "scope_label": "cliente",
}


def _csv(tmp_path: Path, *, orders: bool = False, attacker_without_token_every: int = 0) -> Path:
    """Tráfico normal + un actor que enumera IDs contiguos con un UA de herramienta.

    attacker_without_token_every=N → una de cada N peticiones del atacante va SIN credencial (y recibe 200).
    """
    ep, oid, scope, tok = ("/orders/search", "order_id", "tenant", "token") if orders else (
        "/invoices/search", "invoice_id", "site_id", "authtoken")  # fmt: skip
    rng = random.Random(11)  # noqa: S311 - datos de prueba

    def row(day: int, minute: int, status: int, obj: int, token: str | None, ua: str, ip: str) -> str:
        ts = f"2020-10-{day:02d} {minute // 60:02d}:{minute % 60:02d}:00"
        uri = f"{ep}?{oid}={obj}&{scope}=S1" + (f"&{tok}={token}" if token else "")
        return f'{ts},{status},h.test,{uri},GET,-,"{ua}",{ip}'

    rows = [
        row(rng.randint(1, 28), rng.randint(0, 1439), rng.choice([200, 401, 304]), rng.randint(1000, 1999),
            f"USER-u{i % 10}", BROWSER_UA, f"10.0.0.{i + 1}")
        for i in range(60) for _ in range(40)
    ]  # fmt: skip
    for n, obj in enumerate(range(1500, 2400)):
        no_token = attacker_without_token_every and n % attacker_without_token_every == 0
        rows.append(row(1 + n % 28, n % 1440, 200, obj, None if no_token else "USER-attacker", "Scrapy/2.3.0",
                        "203.0.113.9"))  # fmt: skip
    path = tmp_path / "logs.csv"
    path.write_text(HEADER + "\n".join(rows) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(output_dir=tmp_path / "out", data_dir=tmp_path / "data", timestamp_format="%Y-%m-%d %H:%M:%S")


def _values(obj: object) -> str:
    """Solo los VALORES de texto (las claves internas canónicas, p. ej. `3_facturas_...`, se mantienen)."""
    if isinstance(obj, dict):
        return " ".join(_values(v) for v in obj.values())
    if isinstance(obj, list):
        return " ".join(_values(v) for v in obj)
    return str(obj)


def _evidence(run_dir: Path) -> dict:
    return json.loads((run_dir / "evidence.json").read_text(encoding="utf-8"))


def test_profile_validation_rejects_injection() -> None:
    with pytest.raises(ValueError):
        IncidentProfile(endpoint="/x; drop")
    with pytest.raises(ValueError):
        IncidentProfile(object_param="id&evil=1")
    with pytest.raises(ValueError):
        IncidentProfile(object_label="<script>")
    assert IncidentProfile(scope_param="").request_template == "GET /invoices/search?invoice_id={id}&authtoken={token}"


def test_for_run_validates_and_scope_can_be_empty(settings: Settings) -> None:
    s = settings.for_run({"target_endpoint": "/orders/search", "scope_param": "", "detection_date": "2021-01-12"})
    assert s.profile().endpoint == "/orders/search" and s.profile().scope_param == ""
    assert s.detection_date is not None and s.detection_date.year == 2021
    assert settings.for_run({"object_param": ""}).object_param == "invoice_id"  # vacío = valor configurado
    with pytest.raises(ValueError):
        settings.for_run({"target_endpoint": "orders"})
    with pytest.raises(ValueError):
        settings.for_run({"detection_date": "12/01/2021"})


def test_all_authenticated_yields_affirmative_authorization_fact(tmp_path: Path, settings: Settings) -> None:
    ev = _evidence(run_analysis(_csv(tmp_path), settings).run_dir)
    camp = ev["campaigns"][0]
    assert camp["impact"]["success_2xx_without_token"] == 0
    assert camp["impact"]["success_2xx_with_token"] == camp["impact"]["success_responses_2xx"] > 0
    facts = " ".join(verified_facts(ev))
    assert "AUTENTICADO" in facts and "AUTORIZACIÓN" in facts
    assert "sin autenticación" not in facts.lower() and "SIN authtoken" not in facts


def test_some_success_without_token_is_reported(tmp_path: Path, settings: Settings) -> None:
    ev = _evidence(run_analysis(_csv(tmp_path, attacker_without_token_every=10), settings).run_dir)
    imp = next(c for c in ev["campaigns"] if "203.0.113.9" in c["ips"])["impact"]
    assert imp["success_2xx_without_token"] == 90
    facts = " ".join(verified_facts(ev))
    assert "SIN authtoken" in facts and "posible acceso sin credencial" in facts


def test_other_endpoint_and_labels_flow_through(tmp_path: Path, settings: Settings) -> None:
    # SIN indicar nada: el perfil se deduce del dataset (.env tiene los valores de /invoices/search).
    run_dir = run_analysis(_csv(tmp_path, orders=True), settings).run_dir
    ev = _evidence(run_dir)
    assert ev["metadata"]["profile"] == {
        "endpoint": "/orders/search", "object_param": "order_id", "scope_param": "tenant", "token_param": "token",
        "object_label": "pedido", "object_label_plural": "pedidos", "scope_label": "tenant",
    }  # fmt: skip
    inference = ev["metadata"]["profile_inference"]
    assert inference["detected"] and inference["confidence"] == "alta" and len(inference["evidence"]) >= 3
    camp = ev["campaigns"][0]
    assert camp["status"] == "confirmada" and camp["impact"]["unique_invoices_2xx"] == 900
    blob = _values(ev)
    assert "/invoices/search" not in blob and "factura" not in blob
    assert "pedidos" in blob and "order_id" in blob

    ctx = build_context(ev)
    assert ctx["incident"]["endpoint"].startswith("GET /orders/search?order_id=")
    tri = fallback.triage(ctx)
    fo = fallback.forensic(ctx, tri)
    rs = fallback.response(ctx, tri, fo)
    text = _values([tri.model_dump(), fo.model_dump(), rs.model_dump()])
    assert "/invoices/search" not in text and "factura" not in text and "authtoken" not in text
    assert "/orders/search" in text and "pedidos" in text

    camps = [c for c in ev["campaigns"] if c["status"] == "confirmada"]
    for kind in ("rate_limit", "waf_rule", "monitoring"):
        action = ResponseAction(
            action_id="A1", action_type=kind, target="x", priority=1, phase="inmediata", rationale="r",
            false_positive_risk="bajo", business_impact="bajo", requires_human_approval=False,
        )  # fmt: skip
        body, _ = _render(action, camps, set(), ev)
        assert "/orders/search" in body and "/invoices/search" not in body
    assert "dc(order_id)" in _render(action, camps, set(), ev)[0]


def test_detection_date_is_optional(tmp_path: Path, settings: Settings) -> None:
    csv = _csv(tmp_path)
    rm = _evidence(run_analysis(csv, settings).run_dir)["response_metrics"]
    # Sin fecha: el TTD se ESTIMA hasta el último registro del log y queda marcado como estimado.
    assert rm["detection_date"] is None and rm["ttd_is_estimate"]
    assert rm["ttd_reference_source"] == "fin del log (estimado)" and rm["ttd_from_first_malicious_request_days"] > 0
    rm = _evidence(run_analysis(csv, settings.for_run({"detection_date": "2021-01-12"})).run_dir)["response_metrics"]
    assert rm["detection_date"].startswith("2021-01-12") and rm["ttd_from_first_malicious_request_days"] > 90
    assert not rm["ttd_is_estimate"] and rm["ttd_reference_source"] == "analista"


def test_web_analysis_accepts_profile_and_rejects_invalid(tmp_path: Path, settings: Settings) -> None:
    from idor_ir.web.app import create_app

    data = tmp_path / "data"
    data.mkdir()
    (data / "orders.csv").write_bytes(_csv(tmp_path, orders=True).read_bytes())
    client = TestClient(create_app(settings), base_url="http://127.0.0.1")
    client.get("/")
    headers = {"X-CSRF-Token": client.cookies.get("irp_csrf", "")}
    cfg = client.get("/api/config").json()
    assert cfg["profile"]["target_endpoint"] == "/invoices/search" and cfg["detection_date"] is None
    assert "detection_date_note" not in cfg
    assert cfg["profile_mode"] == "auto"
    manual = {"dataset": "orders.csv", "profile_mode": "manual"}
    bad = client.post("/api/analyses", json={**manual, "target_endpoint": "<x>"}, headers=headers)
    assert bad.status_code == 422 and "<x>" not in bad.text
    # En modo automático los campos del perfil se ignoran (solo cuenta la fecha, que sí se valida).
    auto = client.post("/api/analyses", json={"dataset": "orders.csv", "target_endpoint": "<x>"}, headers=headers)
    assert auto.status_code == 200
    bad_date = client.post("/api/analyses", json={"dataset": "orders.csv", "detection_date": "ayer"}, headers=headers)
    assert bad_date.status_code == 422
    deadline = time.time() + 60
    while time.time() < deadline and client.get(f"/api/jobs/{auto.json()['job_id']}").json()["status"] in {
        "queued",
        "running",
    }:
        time.sleep(0.3)
    ok = client.post("/api/analyses", json={**manual, **ORDERS}, headers=headers)
    assert ok.status_code == 200 and "job_id" in ok.json()


def test_overrides_apply_on_top_of_detection_and_fixed_mode(tmp_path: Path, settings: Settings) -> None:
    from idor_ir.pipeline import resolve_incident_profile

    csv = _csv(tmp_path, orders=True)
    prof, info = resolve_incident_profile(csv, settings.for_run({"scope_label": "cliente"}))
    assert (
        prof.endpoint == "/orders/search"
        and prof.scope_label == "cliente"
        and info["overrides"] == {"scope_label": "cliente"}
    )
    fixed, info = resolve_incident_profile(csv, settings.model_copy(update={"profile_mode": "fixed"}))
    assert fixed.endpoint == "/invoices/search" and info["mode"] == "fijo (.env)"


def test_autodetect_picks_idor_endpoint_among_several_and_warns_path_ids(tmp_path: Path) -> None:
    from idor_ir.ingestion import scan_logs
    from idor_ir.ingestion.autoprofile import infer_profile, object_labels

    rng = random.Random(3)  # noqa: S311 - datos de prueba
    rows = []
    # Tráfico normal MAYORITARIO en /invoices/search: cada usuario ve pocas facturas (las suyas).
    for u in range(80):
        own = [rng.randint(1000, 99999) for _ in range(5)]
        for _ in range(60):
            rows.append(f"2020-10-01 10:00:00,200,h,/invoices/search?invoice_id={rng.choice(own)}&site_id=S1"
                        f"&authtoken=TOKEN-user-{u:04d}xyz,GET,-,ua,10.0.1.{u}")  # fmt: skip
    # Ataque en otro endpoint: una credencial recorre 500 pedidos distintos.
    for n in range(500):
        rows.append(f"2020-10-02 10:00:00,200,h,/api/v2/orders?orderId={5000 + n}&sessionKey=SESSKEYabcdef0123456789"
                    ",GET,-,curl/7.1,203.0.113.7")  # fmt: skip
    rows += [f"2020-10-03 10:00:00,200,h,/api/users/{n}/avatar,GET,-,ua,10.0.2.1" for n in range(50)]
    path = tmp_path / "multi.csv"
    path.write_text(HEADER + "\n".join(rows) + "\n", encoding="utf-8")

    inf = infer_profile(scan_logs(path), IncidentProfile())
    p = inf.profile
    assert (p.endpoint, p.object_param, p.token_param, p.scope_param) == ("/api/v2/orders", "orderId", "sessionKey", "")
    assert (p.object_label, p.object_label_plural) == ("pedido", "pedidos")
    text = " ".join(inf.evidence)
    assert "/invoices/search" in text and "/api/users/{id}/avatar" in text  # alternativa e IDs en la ruta
    assert {c["endpoint"] for c in inf.candidates} == {"/api/v2/orders", "/invoices/search"}
    assert object_labels("/v1/patients/lookup", "pid") == ("paciente", "pacientes")
    assert object_labels("/x", "zzz") == ("zzz", "zzzs") and object_labels("/x", "q1") == ("objeto", "objetos")


def test_no_object_endpoint_falls_back_to_configured(tmp_path: Path) -> None:
    from idor_ir.ingestion import scan_logs
    from idor_ir.ingestion.autoprofile import infer_profile

    path = tmp_path / "static.csv"
    path.write_text(HEADER + "2020-10-01 10:00:00,200,h,/home,GET,-,ua,10.0.0.1\n", encoding="utf-8")
    inf = infer_profile(scan_logs(path), IncidentProfile())
    assert not inf.detected and inf.confidence == "baja" and inf.profile == IncidentProfile()
