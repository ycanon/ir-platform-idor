"""Esquema del dataset de logs y validación de encabezado.

Los 8 campos provienen literalmente de la sección "Dataset provisto" del reto [Reto §2].
No se asume nada más del formato (separador, formato de fecha, comillas): eso queda
pendiente de validar con `three_months.csv` [SPECS P1] y es configurable.

Extensibilidad: si en el futuro se soporta otro formato de log, se define otro `LogSchema`
(con sus columnas y un mapeo a los nombres canónicos) sin tocar los detectores.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

# Columnas canónicas documentadas en el reto [Reto §2].
REQUIRED_COLUMNS: tuple[str, ...] = (
    "timestamp",
    "http_status",
    "http_host",
    "http_uri",
    "http_method",
    "http_referer",
    "http_user_agent",
    "source_ip",
)

# Alias observados en archivos reales -> nombre canónico.
# `http_staus` (sic) aparece en el encabezado de la muestra de three_months.csv (sample_2000.csv,
# validada el 03-oct-2026), mientras el enunciado documenta `http_status`. Se normaliza aquí para que el
# resto del código use siempre el nombre documentado.
COLUMN_ALIASES: dict[str, str] = {
    "http_staus": "http_status",
}


def canonical_name(raw: str) -> str:
    """Normaliza un nombre de columna: espacios, mayúsculas y alias conocidos."""
    name = raw.strip().lower()
    return COLUMN_ALIASES.get(name, name)


# Longitud máxima razonable de la línea de encabezado: evita leer un archivo binario
# o malformado completo como si fuera la primera línea.
_MAX_HEADER_BYTES = 64 * 1024


class SchemaError(ValueError):
    """El archivo no cumple el esquema mínimo soportado."""


@dataclass(frozen=True)
class HeaderCheck:
    """Resultado de validar el encabezado del CSV."""

    columns: tuple[str, ...]
    extra_columns: tuple[str, ...]


def validate_header(path: Path, separator: str = ",") -> HeaderCheck:
    """Lee SOLO la primera línea y verifica que estén las columnas requeridas.

    - `utf-8-sig` elimina un BOM si el archivo fue exportado desde Excel/Windows.
    - Se normalizan espacios y mayúsculas en los nombres de columna.
    - Columnas adicionales se toleran (se reportan), columnas faltantes son error.
    """
    with path.open("r", encoding="utf-8-sig", errors="strict", newline="") as handle:
        first_line = handle.readline(_MAX_HEADER_BYTES)

    if not first_line.strip():
        raise SchemaError("El archivo está vacío o no tiene encabezado.")

    row = next(csv.reader([first_line], delimiter=separator))
    columns = tuple(canonical_name(col) for col in row)

    missing = [col for col in REQUIRED_COLUMNS if col not in columns]
    if missing:
        # El mensaje lista solo nombres de columnas esperadas (no contenido del archivo).
        raise SchemaError(
            f"Faltan columnas requeridas: {', '.join(missing)}. "
            f"Verifique el separador configurado (IRP_CSV_SEPARATOR='{separator}')."
        )

    extra = tuple(col for col in columns if col not in REQUIRED_COLUMNS)
    return HeaderCheck(columns=columns, extra_columns=extra)
