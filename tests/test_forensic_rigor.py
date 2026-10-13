"""Rigor forense (retroalimentación del evaluador): señal → hipótesis → corroboración → impacto confirmado.

Datasets SINTÉTICOS generados en el test. Verifican que:
- sin una fuente de la aplicación, la plataforma NO declara IDOR demostrado ni cuenta accesos indebidos;
- la atribución del tráfico no depende de una lista fija de user agents (un atacante con navegador común se detecta);
- una fuente de ownership corrobora (o descarta) la hipótesis y solo entonces hay impacto confirmado;
- el Parquet de staging no guarda credenciales en claro y el mapa de tokens queda solo para el dueño;
- la notificación legal queda condicionada mientras el impacto no esté corroborado.
"""

from __future__ import annotations

import json
import os
import random
import stat
import sys
from pathlib import Path

import polars as pl
import pytest

from idor_ir.agents import fallback
from idor_ir.agents.context import build_context
from idor_ir.agents.policy import apply_policy
from idor_ir.agents.schemas import ResponseOutput
from idor_ir.config import Settings
from idor_ir.pipeline import AnalysisError, run_analysis

HEADER = "timestamp,http_status,http_host,http_uri,http_method,http_referer,http_user_agent,source_ip\n"
BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/87.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) Safari/605.1",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/84.0",
]


def _row(day: int, minute: int, status: int, obj: int, token: str, ua: str, ip: str) -> str:
    ts = f"2020-10-{day:02d} {minute // 60:02d}:{minute % 60:02d}:00"
    return f'{ts},{status},h.test,/invoices/search?invoice_id={obj}&site_id=S1&authtoken={token},GET,-,"{ua}",{ip}'


def _dataset(tmp_path: Path, attacker_ua: str) -> Path:
    """60 usuarios normales (cada uno consulta SUS facturas) + un atacante que enumera facturas ajenas."""
    rng = random.Random(5)  # noqa: S311 - datos de prueba
    rows = []
    for i in range(60):
        own = range(1000 + i * 10, 1010 + i * 10)  # 10 facturas propias por usuario
        rows += [
            _row(rng.randint(1, 28), rng.randint(0, 1439), rng.choice([200, 304]), rng.choice(own),
                 f"USER-u{i}", rng.choice(BROWSERS), f"10.0.0.{i + 1}")
            for _ in range(40)
        ]  # fmt: skip
    for n, obj in enumerate(range(1000, 1600)):  # facturas de otros 60 titulares
        rows.append(_row(1 + n % 28, n % 1440, 200, obj, "USER-attacker", attacker_ua, "203.0.113.9"))
    path = tmp_path / "logs.csv"
    path.write_text(HEADER + "\n".join(rows) + "\n", encoding="utf-8")
    return path


def _ownership(tmp_path: Path, attacker_owns_all: bool = False) -> Path:
    lines = ["invoice_id,site_id,owner"]
    for i in range(60):
        for obj in range(1000 + i * 10, 1010 + i * 10):
            lines.append(f"{obj},S1,{'USER-attacker' if attacker_owns_all else f'USER-u{i}'}")
    path = tmp_path / "ownership.csv"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(output_dir=tmp_path / "out", data_dir=tmp_path, timestamp_format="%Y-%m-%d %H:%M:%S")


def _evidence(run_dir: Path) -> dict:
    return json.loads((run_dir / "evidence.json").read_text(encoding="utf-8"))


def test_browser_attacker_is_attributed_without_fixed_ua_list(tmp_path: Path, settings: Settings) -> None:
    # UA de navegador común: la lista de herramientas no lo reconoce; la atribución no debe depender de ella.
    ev = _evidence(run_analysis(_dataset(tmp_path, BROWSERS[0]), settings).run_dir)
    camp = next(c for c in ev["campaigns"] if "203.0.113.9" in c["ips"])
    assert camp["attribution"]["method"] == "ip_completa"
    assert camp["impact"]["unique_invoices_2xx"] == 600
    assert camp["status"] in {"alta_confianza", "por_validar"}  # hipótesis, nunca IDOR demostrado


def test_unknown_tool_ua_is_attributed_by_concentration(tmp_path: Path, settings: Settings) -> None:
    # Herramienta nueva que no está en ninguna lista: su UA solo lo usa el atacante → segmento concentrado.
    ev = _evidence(run_analysis(_dataset(tmp_path, "ExfilKit/0.1"), settings).run_dir)
    camp = next(c for c in ev["campaigns"] if "203.0.113.9" in c["ips"])
    assert camp["attribution"]["method"] == "segmentos_ua_concentrados"
    assert camp["attribution"]["user_agents_concentrados"] == ["ExfilKit/0.1"]
    assert "ExfilKit/0.1" in ev["assumptions"]["user_agents_concentrated"]


def test_ownership_corroborates_and_quantifies_confirmed_impact(tmp_path: Path, settings: Settings) -> None:
    run = run_analysis(_dataset(tmp_path, "Scrapy/2.3.0"), settings, ownership=_ownership(tmp_path))
    ev = _evidence(run.run_dir)
    camp = ev["campaigns"][0]
    assert camp["status"] == "corroborada" and camp["corroboration"]["status"] == "evaluada"
    assert camp["corroboration"]["unauthorized_2xx"] == 600 and camp["corroboration"]["unique_owners_exposed"] == 60
    answers = ev["incident_answers"]
    assert answers["2_evidencia_idor"]["respuesta"] == "Sí, corroborado"
    assert answers["3_alcance_exposicion"]["accesos_indebidos_confirmados"] == 600
    assert answers["7_titulares_potencialmente_expuestos"]["confirmados"] == 60
    assert ev["assessment"]["level"] == "impacto confirmado"
    manifest = json.loads((run.run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["parameters"]["ownership_source"]["rows"] == 600
    raw = (run.run_dir / "evidence.json").read_text(encoding="utf-8")
    assert "USER-u1" not in raw and "USER-attacker" not in raw  # titulares y credenciales solo como huella


def test_ownership_can_refute_the_hypothesis(tmp_path: Path, settings: Settings) -> None:
    run = run_analysis(_dataset(tmp_path, "Scrapy/2.3.0"), settings, ownership=_ownership(tmp_path, True))
    camp = next(c for c in _evidence(run.run_dir)["campaigns"] if "203.0.113.9" in c["ips"])
    assert camp["status"] == "descartada" and camp["corroboration"]["unauthorized_2xx"] == 0


def test_invalid_ownership_source_is_rejected(tmp_path: Path, settings: Settings) -> None:
    bad = tmp_path / "bad.csv"
    bad.write_text("id,owner\n1,x\n", encoding="utf-8")
    with pytest.raises(AnalysisError):
        run_analysis(_dataset(tmp_path, "Scrapy/2.3.0"), settings, ownership=bad)


def test_staging_has_no_raw_credentials_and_token_map_is_private(tmp_path: Path, settings: Settings) -> None:
    run = run_analysis(_dataset(tmp_path, "Scrapy/2.3.0"), settings)
    staged = pl.read_parquet(run.run_dir / "work" / "parsed.parquet")
    assert staged["authtoken"].str.starts_with("tok_").all()
    assert not staged["authtoken"].str.contains("USER-").any()
    token_map = run.run_dir / "sensitive" / "token_map.json"
    assert "USER-attacker" in token_map.read_text(encoding="utf-8")  # única copia: necesaria para revocar
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(token_map).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(token_map.parent).st_mode) == 0o700


def test_legal_notification_is_conditioned_until_corroboration(tmp_path: Path, settings: Settings) -> None:
    ev = _evidence(run_analysis(_dataset(tmp_path, "Scrapy/2.3.0"), settings).run_dir)
    ctx = build_context(ev)
    tri = fallback.triage(ctx)
    ro = fallback.response(ctx, tri, fallback.forensic(ctx, tri))
    assert ro.actions[0].action_type == "corroborate"  # lo primero: convertir la hipótesis en hecho
    fixed, overrides = apply_policy(ResponseOutput.model_validate(ro.model_dump()), set(), "hipótesis")
    notify = next(a for a in fixed.actions if a.action_type == "notify")
    assert notify.blocked_reason and notify.evidence_required == "impacto confirmado"
    assert any(o.get("blocked") for o in overrides)
    fixed_ok, _ = apply_policy(ResponseOutput.model_validate(ro.model_dump()), set(), "impacto confirmado")
    assert not next(a for a in fixed_ok.actions if a.action_type == "notify").blocked_reason
