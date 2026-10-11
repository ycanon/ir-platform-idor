"""Tests de la evidencia sobre el dataset SINTÉTICO de test_detection."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from idor_ir import cli
from idor_ir.config import Settings
from idor_ir.forensics.evidence import _components, id_ranges

# Reutiliza el generador sintético de test_detection.
from tests.test_detection import synthetic_csv  # noqa: F401


def test_id_ranges_merges_small_gaps() -> None:
    assert id_ranges([1, 2, 3, 50, 300, 301]) == [[1, 50], [300, 301]]
    assert id_ranges([]) == []


def test_components_groups_shared_tokens() -> None:
    comps = _components([("ip1", "t1"), ("ip2", "t1"), ("ip3", "t9")])
    sizes = sorted((len(ips), len(toks)) for ips, toks in comps)
    assert sizes == [(1, 1), (2, 1)]


def test_evidence_end_to_end(synthetic_csv: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    settings = Settings(output_dir=tmp_path / "out", data_dir=tmp_path, detection_date=datetime(2020, 12, 1))
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    assert cli.main(["analyze", "--file", str(synthetic_csv)]) == cli.EXIT_OK
    run_dir = next(p for p in settings.output_dir.iterdir() if p.is_dir())

    raw = (run_dir / "evidence.json").read_text(encoding="utf-8")
    assert "USER-ID-attacker" not in raw  # tokens enmascarados
    ev = json.loads(raw)

    c1 = ev["campaigns"][0]
    assert c1["campaign_id"] == "C1" and c1["status"] == "confirmada"
    assert c1["ips"] == ["203.0.113.9"]
    assert c1["impact"]["unique_invoices_2xx"] == 900
    # Los IDs 2000-2399 nunca aparecen en el tráfico normal (que usa 1000-1999).
    assert c1["impact"]["invoice_id_ranges_outside_baseline"][-1][1] == 2399
    assert c1["impact"]["unique_invoices_2xx_outside_baseline"] >= 400
    assert ev["incident_answers"]["2_evidencia_idor"]["respuesta"] == "Sí"
    start = ev["incident_answers"]["1_inicio_explotacion"]
    assert start["ip_primer_acceso"] == "203.0.113.9" and isinstance(start["inicio_censurado"], bool)
    assert start["primera_actividad_maliciosa"] <= start["primer_acceso_exitoso_2xx"]
    assert ev["incident_answers"]["7_usuarios_potencialmente_afectados"]["limite_superior"] == 900
    assert ev["top20_ips"][0]["ip"] == "203.0.113.9"
    assert any(u["value"] == "Scrapy/2.3.0" and u["exclusive_to_attack"] for u in ev["iocs"]["user_agents"])
    timeline = [e["ts"] for e in ev["timeline"]]
    assert timeline == sorted(timeline)
    assert ev["response_metrics"]["ttd_from_first_malicious_request_days"] > 0

    csv_text = (run_dir / "iocs.csv").read_text(encoding="utf-8")
    assert "203.0.113.9" in csv_text and "USER-ID-attacker" not in csv_text
    assert cli.main(["verify", "--run", run_dir.name, "--file", str(synthetic_csv)]) == cli.EXIT_OK
