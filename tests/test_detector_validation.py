"""Validación del detector con datos etiquetados (retroalimentación del evaluador: precisión, recall, FP, umbrales).

Banco SINTÉTICO generado en el test. Además de comprobar que el reporte se produce, fija como regresión los puntos
ciegos que la validación encontró y que se corrigieron: la rotación de IPs con una sola credencial.
"""

from __future__ import annotations

import json
from pathlib import Path

import polars as pl

from idor_ir.anomaly.model import add_model_columns, isolation_forest_scores
from idor_ir.cli import main
from idor_ir.config import get_settings
from idor_ir.detection.features import actor_features
from idor_ir.detection.validation import ATTACK_STYLES, evaluate, evaluate_campaigns, generate


def test_benchmark_is_labelled_and_deterministic() -> None:
    a, b = generate(seed=3, users=120), generate(seed=3, users=120)
    assert a.rows.equals(b.rows)
    styles = set(a.labels["authtoken"].values())
    assert set(ATTACK_STYLES) <= styles and "integracion_api" in styles and "monitor" in styles
    assert sum(1 for v in a.labels["source_ip"].values() if v == "ips_rotativas_un_token") == 20


def test_metrics_per_variant_and_style() -> None:
    r = evaluate(seed=3, baseline_seed=103, users=150)
    tok = r["keys"]["authtoken"]["variants"]["produccion_en_muestra"]
    medio = tok["at_level"]["medio"]
    assert {"tp", "fp", "fn", "tn", "precision", "recall", "fpr", "f1"} <= medio.keys()
    assert len(tok["curve"]) == 19  # umbrales 5..95
    # Regresión: la credencial que rota 20 IPs se detecta (antes la normalización por IP la escondía).
    assert tok["recall_by_style_at_medio"]["ips_rotativas_un_token"]["recall_at_medio"] == 1.0
    # Los falsos positivos son automatización legítima, no usuarios comunes con navegador.
    assert "usuario" not in tok["false_positives_by_kind_at_medio"]


def test_isolation_forest_can_be_fitted_on_a_separate_window() -> None:
    train = add_model_columns(actor_features(generate(seed=11, users=120, attacks=False).rows.lazy(), "source_ip"))
    test = add_model_columns(actor_features(generate(seed=12, users=120).rows.lazy(), "source_ip"), train)
    scores = isolation_forest_scores(test, reference=train)
    assert scores.len() == test.height and 0.0 <= scores.min() and scores.max() <= 1.0  # type: ignore[operator]


def test_campaign_layer_groups_rotating_ips_by_credential(tmp_path: Path) -> None:
    r = evaluate_campaigns(tmp_path, seed=3, users=150)
    rotating = [c for c in r["campaigns"] if "ips_rotativas_un_token" in c["composition"]]
    assert rotating and rotating[0]["ips"] == 20  # pivote por credencial: las 20 IPs en una sola campaña
    assert r["priority_precision"] == 1.0
    assert not r["attack_styles_missed"]


def test_cli_writes_validation_report(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("IRP_OUTPUT_DIR", str(tmp_path / "out"))
    get_settings.cache_clear()
    try:
        assert main(["validate-detector", "--seeds", "1", "--users", "120", "--no-campaigns"]) == 0
    finally:
        get_settings.cache_clear()
    reports = list((tmp_path / "out" / "validation").glob("detector_validation_*.json"))
    assert len(reports) == 1
    data = json.loads(reports[0].read_text(encoding="utf-8"))
    assert data["limitations"] and set(data["summary_at_medio"]) == {"source_ip", "authtoken"}
    curve = pl.DataFrame(data["runs"][0]["keys"]["authtoken"]["variants"]["solo_reglas"]["curve"])
    assert curve["threshold"].to_list() == [float(t) for t in range(5, 100, 5)]
