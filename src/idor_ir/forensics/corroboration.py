"""Corroboración del IDOR con una fuente de propiedad (ownership) de la aplicación.

El log HTTP no dice a quién pertenece cada objeto. Una exportación de la aplicación (p. ej. la base de facturación)
sí: con ella se puede comprobar, petición por petición, si la credencial que obtuvo un 2xx era la del titular.
Solo entonces hay IDOR DEMOSTRADO e impacto CONFIRMADO.

Formato del CSV de ownership (separador coma, encabezado obligatorio):
- `<object_param>` (p. ej. `invoice_id`): identificador del objeto.
- `<scope_param>` (opcional, p. ej. `site_id`): ámbito, si el identificador solo es único dentro de él.
- `owner`: identificador del titular expresado como la credencial del log (`<token_param>`). En producción se
  obtiene uniendo el titular del objeto con el proveedor de identidad (usuario → credenciales).

Los titulares nunca se guardan en claro: se comparan por huella (`tok_…`), igual que las credenciales del log.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import polars as pl

from idor_ir.profile import IncidentProfile
from idor_ir.redaction import fingerprint_token

OWNER_COLUMN = "owner"
_MAX_ROWS = 50_000_000


class OwnershipError(ValueError):
    """La fuente de ownership no tiene el formato esperado."""


def load_ownership(path: Path, profile: IncidentProfile | None = None) -> pl.DataFrame:
    """Lee el CSV y devuelve (invoice_id_num, [site_id], owner_fp). Valida columnas antes de leer datos."""
    p = profile or IncidentProfile()
    try:
        with path.open(encoding="utf-8-sig") as handle:
            header = handle.readline().strip().split(",")
    except OSError as exc:
        raise OwnershipError("No se pudo leer la fuente de ownership.") from exc
    cols = [c.strip().lower() for c in header]
    if p.object_param not in cols or OWNER_COLUMN not in cols:
        raise OwnershipError(f"La fuente de ownership debe tener las columnas '{p.object_param}' y '{OWNER_COLUMN}'.")
    use_scope = bool(p.scope_param) and p.scope_param in cols

    raw = pl.read_csv(path, infer_schema=False, n_rows=_MAX_ROWS, encoding="utf8-lossy")
    raw = raw.rename({c: c.strip().lower() for c in raw.columns})
    owners = raw[OWNER_COLUMN].drop_nulls().unique().to_list()
    fp = pl.DataFrame({OWNER_COLUMN: owners, "owner_fp": [fingerprint_token(o) for o in owners]})
    df = raw.join(fp, on=OWNER_COLUMN, how="left").with_columns(
        invoice_id_num=pl.col(p.object_param).str.strip_chars().cast(pl.Int64, strict=False)
    )
    keep = ["invoice_id_num", "owner_fp"] + (["site_id"] if use_scope else [])
    if use_scope:
        df = df.rename({p.scope_param: "site_id"}) if p.scope_param != "site_id" else df
    out = df.select(keep).drop_nulls(["invoice_id_num", "owner_fp"]).unique()
    if out.is_empty():
        raise OwnershipError("La fuente de ownership no tiene filas válidas.")
    return out


def corroborate(rows_2xx: pl.DataFrame, ownership: pl.DataFrame) -> dict[str, Any]:
    """Clasifica cada respuesta 2xx de una campaña: titular (autorizado), NO titular (acceso indebido) o sin dato.

    `rows_2xx` necesita `invoice_id_num`, `authtoken` (huella) y, si la fuente lo trae, `site_id`.
    """
    keys = ["invoice_id_num"] + (["site_id"] if "site_id" in ownership.columns else [])
    joined = rows_2xx.select([*keys, "authtoken"]).join(ownership, on=keys, how="left")
    unknown = joined.filter(pl.col("owner_fp").is_null())
    known = joined.filter(pl.col("owner_fp").is_not_null())
    authorized = known.filter(pl.col("owner_fp") == pl.col("authtoken"))
    unauthorized = known.filter(pl.col("owner_fp") != pl.col("authtoken"))
    by_scope: dict[str, int] = {}
    if "site_id" in unauthorized.columns:
        agg = unauthorized.group_by("site_id").agg(n=pl.col("invoice_id_num").n_unique()).sort("site_id")
        by_scope = {str(r["site_id"]): int(r["n"]) for r in agg.iter_rows(named=True)}
    return {
        "checked_2xx": joined.height,
        "unauthorized_2xx": unauthorized.height,
        "authorized_2xx": authorized.height,
        "unknown_owner_2xx": unknown.height,
        "unique_objects_unauthorized": int(unauthorized["invoice_id_num"].n_unique()),
        "unique_objects_unauthorized_by_scope": by_scope,
        "unique_owners_exposed": int(unauthorized["owner_fp"].n_unique()),
    }
