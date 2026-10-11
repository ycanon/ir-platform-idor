"""Lectura eficiente del dataset con Polars (modo lazy + motor streaming).

Por qué Polars [R1, R4]:
- `scan_csv` NO carga el archivo: construye un plan de consulta (LazyFrame).
- Al ejecutar con `engine="streaming"` el archivo se procesa por lotes, en paralelo y con
  memoria acotada; solo se materializan los resultados agregados (unas pocas filas).
- Las operaciones de texto (regex sobre `http_uri`) son vectorizadas en Rust, no bucles Python.
  Con pandas + `chunksize` habría que iterar en Python y aplicar regex por chunk en un solo hilo.

Decisión: todas las columnas se leen como texto (`infer_schema=False`) y se convierten de forma
explícita y tolerante (`strict=False`). Así un valor malformado se vuelve `null` y se CUENTA,
en lugar de abortar el procesamiento o descartarse en silencio (importante para el forense).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import polars as pl

from idor_ir.ingestion.schema import REQUIRED_COLUMNS, canonical_name, validate_header
from idor_ir.profile import IncidentProfile

# Regex para extraer parámetros del endpoint afectado. Los nombres vienen del perfil del incidente
# (reto [Reto §2]: invoice_id, site_id, authtoken). `[?&]` asegura el parámetro exacto (no "xinvoice_id") y
# `re.escape` impide que un nombre configurado se interprete como regex.
_PARAM_PATTERN = r"[?&]{name}=([^&#]*)"


def _param(name: str) -> pl.Expr:
    if not name:
        return pl.lit(None, dtype=pl.String)
    return pl.col("http_uri").str.extract(_PARAM_PATTERN.format(name=re.escape(name)), group_index=1)


def scan_logs(path: Path, separator: str = ",") -> pl.LazyFrame:
    """Devuelve un LazyFrame con las columnas canónicas como texto. No lee datos todavía."""
    return (
        pl.scan_csv(
            path,
            separator=separator,
            has_header=True,
            infer_schema=False,  # todo como String; conversiones explícitas abajo
            encoding="utf8-lossy",  # bytes inválidos se reemplazan en vez de abortar
        )
        .rename(
            # Normaliza nombres (minúsculas/espacios/alias como `http_staus`) igual que validate_header.
            canonical_name
        )
        .select(list(REQUIRED_COLUMNS))
    )  # solo las columnas canónicas, en orden fijo


def enrich(
    lf: pl.LazyFrame, timestamp_format: str | None = None, profile: IncidentProfile | None = None
) -> pl.LazyFrame:
    """Agrega columnas derivadas tipadas. Sigue siendo lazy.

    - `ts`: timestamp parseado (formato configurable; si es None, Polars lo infiere).
    - `status`: código HTTP como entero.
    - `path`: URI sin query string (para filtrar el endpoint afectado).
    - `invoice_id`, `site_id`, `authtoken`: nombres internos canónicos de los parámetros del perfil
      (objeto, ámbito, credencial). En el reto: invoice_id, site_id, authtoken [Reto §2].
    - `invoice_id_num`: versión numérica del identificador (necesaria para detectar secuencialidad).
    """
    p = profile or IncidentProfile()
    return lf.with_columns(
        ts=pl.col("timestamp").str.strip_chars().str.to_datetime(format=timestamp_format, strict=False),
        status=pl.col("http_status").str.strip_chars().cast(pl.Int16, strict=False),
        path=pl.col("http_uri").str.extract(r"^([^?#]*)", group_index=1),
        invoice_id=_param(p.object_param),
        site_id=_param(p.scope_param),
        authtoken=_param(p.token_param),
    ).with_columns(
        invoice_id_num=pl.col("invoice_id").cast(pl.Int64, strict=False),
    )


@dataclass(frozen=True)
class DatasetProfile:
    """Perfil básico del dataset: resultado verificable de la ingesta."""

    total_rows: int
    first_timestamp: datetime | None
    last_timestamp: datetime | None
    unparsed_timestamps: int
    unparsed_status: int
    unique_source_ips: int
    target_endpoint: str
    target_endpoint_rows: int
    rows_with_invoice_id: int
    rows_with_numeric_invoice_id: int
    status_counts: dict[str, int] = field(default_factory=dict)
    method_counts: dict[str, int] = field(default_factory=dict)
    # Diagnóstico de fecha: filas por fecha "cruda" (primeros 10 caracteres) y rango de los dos
    # campos numéricos tras el año. Sirve para decidir si el formato es AAAA-MM-DD o AAAA-DD-MM.
    raw_date_counts: dict[str, int] = field(default_factory=dict)
    date_field_ranges: dict[str, list[int]] = field(default_factory=dict)
    date_order_hint: str = "desconocido"
    elapsed_seconds: float = 0.0


def profile_dataset(
    path: Path,
    separator: str = ",",
    timestamp_format: str | None = None,
    target_endpoint: str | None = None,
    profile: IncidentProfile | None = None,
) -> DatasetProfile:
    """Calcula el perfil del dataset en streaming y devuelve solo agregados."""
    validate_header(path, separator)  # falla rápido si el formato no es compatible
    started = time.perf_counter()
    profile = profile or IncidentProfile()
    target_endpoint = target_endpoint or profile.endpoint

    lf = enrich(scan_logs(path, separator), timestamp_format, profile)

    summary_q = lf.select(
        total_rows=pl.len(),
        first_ts=pl.col("ts").min(),
        last_ts=pl.col("ts").max(),
        unparsed_ts=pl.col("ts").is_null().sum(),
        unparsed_status=pl.col("status").is_null().sum(),
        unique_ips=pl.col("source_ip").n_unique(),
        target_rows=(pl.col("path") == target_endpoint).sum(),
        with_invoice=pl.col("invoice_id").is_not_null().sum(),
        numeric_invoice=pl.col("invoice_id_num").is_not_null().sum(),
    )
    status_q = lf.group_by("http_status").agg(n=pl.len())
    method_q = lf.group_by("http_method").agg(n=pl.len())
    date_q = lf.group_by(raw_date=pl.col("timestamp").str.strip_chars().str.slice(0, 10)).agg(n=pl.len())

    # collect_all ejecuta las consultas; el motor streaming mantiene la memoria acotada.
    summary, status_df, method_df, date_df = pl.collect_all([summary_q, status_q, method_q, date_q], engine="streaming")
    row = summary.row(0, named=True)
    ranges, hint = _date_field_diagnostics(date_df)

    return DatasetProfile(
        total_rows=int(row["total_rows"]),
        first_timestamp=row["first_ts"],
        last_timestamp=row["last_ts"],
        unparsed_timestamps=int(row["unparsed_ts"]),
        unparsed_status=int(row["unparsed_status"]),
        unique_source_ips=int(row["unique_ips"]),
        target_endpoint=target_endpoint,
        target_endpoint_rows=int(row["target_rows"]),
        rows_with_invoice_id=int(row["with_invoice"]),
        rows_with_numeric_invoice_id=int(row["numeric_invoice"]),
        status_counts=_counts(status_df, "http_status"),
        method_counts=_counts(method_df, "http_method"),
        raw_date_counts=dict(sorted(_counts(date_df, "raw_date").items())),
        date_field_ranges=ranges,
        date_order_hint=hint,
        elapsed_seconds=round(time.perf_counter() - started, 3),
    )


def _counts(df: pl.DataFrame, key: str) -> dict[str, int]:
    """Convierte un group_by en dict ordenado de mayor a menor frecuencia."""
    ordered = df.sort("n", descending=True)
    return {str(k): int(n) for k, n in zip(ordered[key], ordered["n"], strict=True)}


def _date_field_diagnostics(date_df: pl.DataFrame) -> tuple[dict[str, list[int]], str]:
    """Rango de los campos 2 y 3 de fechas `AAAA-xx-yy` y pista del orden día/mes.

    Si un campo supera 12 solo puede ser el día. Si ninguno lo supera, el orden es ambiguo
    y debe confirmarse con información externa (p. ej. el periodo indicado en el reto).
    """
    parts = date_df.select(
        f2=pl.col("raw_date").str.extract(r"^\d{4}-(\d{2})-\d{2}$", 1).cast(pl.Int32, strict=False),
        f3=pl.col("raw_date").str.extract(r"^\d{4}-\d{2}-(\d{2})$", 1).cast(pl.Int32, strict=False),
    ).drop_nulls()
    if parts.is_empty():
        return {}, "desconocido"
    ranges = {
        "campo2": [int(parts["f2"].min()), int(parts["f2"].max())],  # type: ignore[arg-type]
        "campo3": [int(parts["f3"].min()), int(parts["f3"].max())],  # type: ignore[arg-type]
    }
    if ranges["campo2"][1] > 12 >= ranges["campo3"][1]:
        hint = "AAAA-DD-MM"
    elif ranges["campo3"][1] > 12 >= ranges["campo2"][1]:
        hint = "AAAA-MM-DD"
    else:
        hint = "ambiguo"
    return ranges, hint
