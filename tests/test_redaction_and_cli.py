from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from idor_ir import cli
from idor_ir.config import Settings
from idor_ir.logging_setup import JsonFormatter, RedactingFilter
from idor_ir.redaction import fingerprint_token, mask_secret, redact_text


def test_redact_query_token() -> None:
    text = "/invoices/search?invoice_id=1&site_id=2&authtoken=abc123XYZ"
    assert redact_text(text) == "/invoices/search?invoice_id=1&site_id=2&authtoken=***"


def test_redact_headers() -> None:
    assert "k3y" not in redact_text("x-apikey: k3y")
    assert "tok" not in redact_text("Authorization: Bearer tok")


def test_fingerprint_is_stable_and_hides_value() -> None:
    fp = fingerprint_token("SECRET_A")
    assert fp == fingerprint_token("SECRET_A")
    assert fp.startswith("tok_") and "SECRET" not in fp


def test_mask_secret() -> None:
    assert mask_secret("abcdef1234") == "••••1234"
    assert mask_secret("ab") == "••"


def test_log_record_is_redacted_and_single_line() -> None:
    record = logging.makeLogRecord(
        {"msg": "uri=%s", "args": ("/x?authtoken=SECRET\nFAKE LINE",), "levelno": 20, "levelname": "INFO", "name": "t"}
    )
    RedactingFilter().filter(record)
    line = JsonFormatter().format(record)
    assert "SECRET" not in line
    assert "\n" not in line
    assert json.loads(line)["msg"].startswith("uri=/x?authtoken=***")


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(output_dir=tmp_path / "out", data_dir=tmp_path)


def test_cli_ingest_and_verify(
    sample_csv: Path,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    assert cli.main(["ingest", "--file", str(sample_csv)]) == cli.EXIT_OK
    run_id = next(p.name for p in settings.output_dir.iterdir() if p.is_dir())
    out = capsys.readouterr().out
    assert "SECRET_A" not in out  # el resumen no expone tokens
    assert cli.main(["verify", "--run", run_id, "--file", str(sample_csv)]) == cli.EXIT_OK


def test_cli_rejects_bad_extension(tmp_path: Path, settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    bad = tmp_path / "x.exe"
    bad.write_bytes(b"MZ")
    assert cli.main(["ingest", "--file", str(bad)]) == cli.EXIT_INPUT


def test_cli_verify_blocks_path_traversal(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    settings.output_dir.mkdir(parents=True)
    assert cli.main(["verify", "--run", "../.."]) == cli.EXIT_INPUT
