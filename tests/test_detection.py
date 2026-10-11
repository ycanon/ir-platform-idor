"""Tests de detección con un dataset SINTÉTICO generado en el test.

El escenario sintético (tráfico normal + un actor que enumera IDs con un UA de herramienta) solo
verifica que la mecánica de features, reglas y scoring funciona; no reproduce el dataset del reto.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import polars as pl
import pytest

from idor_ir import cli
from idor_ir.anomaly.model import robust_z
from idor_ir.config import Settings
from idor_ir.detection import IdorDetector, traffic_metrics
from idor_ir.detection.features import actor_features
from idor_ir.ingestion import enrich, scan_logs
from idor_ir.redaction import token_hint

HEADER = "timestamp,http_staus,http_host,http_uri,http_method,http_referer,http_user_agent,source_ip\n"
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/87.0"


def _row(day: int, minute: int, status: int, invoice: int, token: str, ua: str, ip: str) -> str:
    ts = f"2020-{day:02d}-10T{minute // 60:02d}:{minute % 60:02d}"  # formato AAAA-DD-MM validado
    uri = f"/invoices/search?invoice_id={invoice}&site_id=SiteA&authtoken={token}"
    return f'{ts},{status},h.test,{uri},GET,-,"{ua}",{ip}'


@pytest.fixture
def synthetic_csv(tmp_path: Path) -> Path:
    rng = random.Random(7)  # noqa: S311 - datos de prueba, no criptografía
    rows: list[str] = []
    # 60 IPs normales: pocas peticiones a IDs aleatorios del rango legítimo, UA de navegador.
    for i in range(60):
        ip = f"10.0.{i // 250}.{i % 250 + 1}"
        for _ in range(40):
            rows.append(
                _row(rng.randint(1, 28), rng.randint(0, 1439), rng.choice([200, 401, 304]),
                     rng.randint(1000, 1999), f"USER-ID-u{i % 10}", BROWSER_UA, ip)
            )  # fmt: skip
    # Atacante: 1 IP, 1 token, 900 IDs contiguos (incluye IDs fuera del rango normal), UA Scrapy.
    for n, invoice in enumerate(range(1500, 2400)):
        rows.append(_row(1 + n % 28, n % 1440, 200, invoice, "USER-ID-attacker", "Scrapy/2.3.0", "203.0.113.9"))
    path = tmp_path / "synthetic.csv"
    path.write_text(HEADER + "\n".join(rows) + "\n", encoding="utf-8")
    return path


def _lf(path: Path) -> pl.LazyFrame:
    return enrich(scan_logs(path), "%Y-%d-%mT%H:%M")


def test_robust_z_flags_outlier_and_handles_constant() -> None:
    z = robust_z(pl.Series("x", [10, 11, 9, 10, 12, 10, 100]))
    assert z[-1] > 3.5 and abs(z[0]) < 1
    assert robust_z(pl.Series("x", [5, 5, 5])).to_list() == [0.0, 0.0, 0.0]


def test_features_capture_density_and_automation(synthetic_csv: Path) -> None:
    feats = actor_features(_lf(synthetic_csv), "source_ip")
    attacker = feats.filter(pl.col("actor") == "203.0.113.9").row(0, named=True)
    assert attacker["unique_invoices"] == 900
    assert attacker["invoice_density"] > 0.99  # 899 de 900 IDs tienen vecino +1
    assert attacker["automation_ratio"] == 1.0
    normal = feats.filter(pl.col("actor") != "203.0.113.9")
    assert normal["automation_ratio"].max() == 0.0


def test_detector_ranks_attacker_first(synthetic_csv: Path) -> None:
    result = IdorDetector().run(_lf(synthetic_csv))
    ips = result.actors["source_ip"]
    top = ips.row(0, named=True)
    assert top["actor"] == "203.0.113.9"
    assert top["risk_level"] == "critico"
    assert any("Enumeración masiva" in r for r in top["reasons"])
    assert ips.filter(pl.col("actor") != "203.0.113.9")["risk_level"].is_in(["critico"]).sum() == 0
    tokens = result.actors["authtoken"]
    assert tokens.row(0, named=True)["actor"] == "USER-ID-attacker"


def test_traffic_metrics(synthetic_csv: Path) -> None:
    m = traffic_metrics(_lf(synthetic_csv))
    assert m["requests_per_ip"]["top"][0]["ip"] == "203.0.113.9"
    assert m["error_rates"]["count_403"] == 0
    assert len(m["temporal"]["per_hour"]) > 0


def test_token_hint() -> None:
    assert token_hint("ATUSER-ID-pruebauser") == "ATUSER-ID-pr…er"
    assert token_hint("abc") == "…"


def test_cli_analyze_masks_tokens_and_verifies(
    synthetic_csv: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    settings = Settings(output_dir=tmp_path / "out", data_dir=tmp_path)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    assert cli.main(["analyze", "--file", str(synthetic_csv)]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "USER-ID-attacker" not in out  # el resumen solo muestra la pista del token

    run_dir = next(p for p in settings.output_dir.iterdir() if p.is_dir())
    detection = (run_dir / "detection.json").read_text(encoding="utf-8")
    assert "USER-ID-attacker" not in detection  # tokens enmascarados en el artefacto
    token_map = json.loads((run_dir / "sensitive" / "token_map.json").read_text(encoding="utf-8"))
    assert "USER-ID-attacker" in token_map.values()  # disponible solo en el archivo restringido
    assert (run_dir / "metrics.json").is_file()
    assert cli.main(["verify", "--run", run_dir.name, "--file", str(synthetic_csv)]) == cli.EXIT_OK
