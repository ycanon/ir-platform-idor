from __future__ import annotations

from datetime import datetime
from pathlib import Path

import polars as pl
import pytest

from idor_ir.ingestion import SchemaError, enrich, profile_dataset, scan_logs, validate_header


def test_validate_header_ok(sample_csv: Path) -> None:
    check = validate_header(sample_csv)
    assert check.extra_columns == ()


def test_validate_header_tolerates_bom_and_case(tmp_path: Path) -> None:
    path = tmp_path / "bom.csv"
    header = "﻿Timestamp,HTTP_STATUS,http_host,http_uri,http_method,http_referer,http_user_agent,source_ip,extra"
    path.write_text(header + "\n", encoding="utf-8")
    assert validate_header(path).extra_columns == ("extra",)


def test_header_alias_http_staus(tmp_path: Path) -> None:
    """El archivo real trae `http_staus` (sic); debe mapearse a `http_status`."""
    path = tmp_path / "alias.csv"
    path.write_text(
        "timestamp,http_staus,http_host,http_uri,http_method,http_referer,http_user_agent,source_ip\n"
        "2020-01-12T00:16,200,h,/invoices/search?invoice_id=1&site_id=S&authtoken=T,GET,-,ua,1.1.1.1\n",
        encoding="utf-8",
    )
    assert validate_header(path).extra_columns == ()
    row = enrich(scan_logs(path)).collect().row(0, named=True)
    assert row["status"] == 200
    assert row["ts"] == datetime(2020, 1, 12, 0, 16)  # formato sin segundos


def test_date_order_hint(tmp_path: Path) -> None:
    header = "timestamp,http_status,http_host,http_uri,http_method,http_referer,http_user_agent,source_ip\n"
    dd_mm = tmp_path / "ddmm.csv"
    dd_mm.write_text(header + "2020-25-12T00:00,200,h,/x,GET,-,ua,1.1.1.1\n", encoding="utf-8")
    assert profile_dataset(dd_mm).date_order_hint == "AAAA-DD-MM"
    mm_dd = tmp_path / "mmdd.csv"
    mm_dd.write_text(header + "2020-12-25T00:00,200,h,/x,GET,-,ua,1.1.1.1\n", encoding="utf-8")
    assert profile_dataset(mm_dd).date_order_hint == "AAAA-MM-DD"


def test_validate_header_missing_column(tmp_path: Path) -> None:
    path = tmp_path / "bad.csv"
    path.write_text("timestamp,http_status\n1,2\n", encoding="utf-8")
    with pytest.raises(SchemaError, match="Faltan columnas"):
        validate_header(path)


def test_validate_header_wrong_separator(sample_csv: Path) -> None:
    with pytest.raises(SchemaError, match="separador"):
        validate_header(sample_csv, separator=";")


def test_enrich_extracts_query_params(sample_csv: Path) -> None:
    df = enrich(scan_logs(sample_csv)).collect()
    first = df.row(0, named=True)
    assert first["invoice_id"] == "100"
    assert first["invoice_id_num"] == 100
    assert first["site_id"] == "1"
    assert first["authtoken"] == "SECRET_A"
    assert first["path"] == "/invoices/search"
    assert first["status"] == 200
    assert first["ts"] == datetime(2020, 1, 1, 10, 0, 0)
    # Fila sin parámetros: nulls, no error.
    assert df.row(3, named=True)["invoice_id"] is None
    # Valores malformados se vuelven null (y se cuentan en el perfil).
    bad = df.row(4, named=True)
    assert bad["invoice_id_num"] is None and bad["status"] is None and bad["ts"] is None


def test_enrich_does_not_match_param_suffix(tmp_path: Path) -> None:
    path = tmp_path / "s.csv"
    path.write_text(
        "timestamp,http_status,http_host,http_uri,http_method,http_referer,http_user_agent,source_ip\n"
        "2020-01-01 00:00:00,200,h,/invoices/search?xinvoice_id=9,GET,-,ua,1.1.1.1\n",
        encoding="utf-8",
    )
    assert enrich(scan_logs(path)).collect()["invoice_id"][0] is None


def test_profile_dataset(sample_csv: Path) -> None:
    profile = profile_dataset(sample_csv)
    assert profile.total_rows == 5
    assert profile.unique_source_ips == 3
    assert profile.target_endpoint_rows == 4
    assert profile.rows_with_invoice_id == 4
    assert profile.rows_with_numeric_invoice_id == 3
    assert profile.unparsed_timestamps == 1
    assert profile.unparsed_status == 1
    assert profile.status_counts["200"] == 3
    assert profile.first_timestamp == datetime(2020, 1, 1, 10, 0, 0)
    assert profile.last_timestamp == datetime(2020, 1, 2, 11, 0, 0)


def test_scan_is_lazy(sample_csv: Path) -> None:
    assert isinstance(scan_logs(sample_csv), pl.LazyFrame)


def test_default_format_parses_real_layout(tmp_path: Path) -> None:
    """Formato validado AAAA-DD-MM: '2020-31-12T23:59' es 31-dic y '2020-01-10' es 1-oct."""
    from idor_ir.config import DEFAULT_TIMESTAMP_FORMAT, Settings

    header = "timestamp,http_staus,http_host,http_uri,http_method,http_referer,http_user_agent,source_ip\n"
    path = tmp_path / "real.csv"
    path.write_text(
        header + "2020-31-12T23:59,200,h,/x,GET,-,ua,1.1.1.1\n2020-01-10T00:00,200,h,/x,GET,-,ua,1.1.1.1\n",
        encoding="utf-8",
    )
    profile = profile_dataset(path, timestamp_format=DEFAULT_TIMESTAMP_FORMAT)
    assert profile.unparsed_timestamps == 0
    assert profile.first_timestamp == datetime(2020, 10, 1, 0, 0)
    assert profile.last_timestamp == datetime(2020, 12, 31, 23, 59)
    assert Settings(timestamp_format="").timestamp_format == DEFAULT_TIMESTAMP_FORMAT
    assert Settings(timestamp_format="auto").timestamp_format is None
