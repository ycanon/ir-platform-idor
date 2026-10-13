"""Acta de recepción de evidencia (cadena de custodia) para archivos cargados.

Los datos que la plataforma NO puede obtener del archivo (quién lo recolectó, de qué sistema, cuándo, con qué
autorización, en qué zona horaria está el log…) los diligencia el analista al cargarlo. La plataforma añade los
datos automáticos (nombre original, tamaño, SHA-256, fecha de recepción en UTC, protección contra escritura) y
guarda todo en un archivo acompañante `<archivo>.csv.custody.json` junto al CSV, también de solo lectura.
"""

from __future__ import annotations

import json
import os
import re
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

SIDECAR_SUFFIX = ".custody.json"
SCHEMA = "custody_intake/v1"
_SINGLE_LINE_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_MULTI_LINE_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")  # conserva \t y \n
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_WRITE_BITS = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH


class CustodyIntakeError(ValueError):
    """El acta de recepción es inválida o no coincide con el archivo."""


class CustodyIntake(BaseModel):
    """Campos del formato de cadena de custodia que solo puede aportar una persona."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    collected_by: str = Field(min_length=3, max_length=120, description="Quién recolectó (nombre y rol)")
    collected_at: datetime = Field(description="Fecha y hora de la recolección/extracción")
    source_system: str = Field(min_length=2, max_length=160, description="Sistema de origen del log")
    source_timezone: str = Field(min_length=1, max_length=60, description="Zona horaria de los timestamps")
    case_id: str = Field(default="", max_length=80, description="Caso o ticket del incidente")
    evidence_id: str = Field(default="", max_length=80, description="Identificador de la evidencia")
    collection_method: str = Field(default="", max_length=240, description="Cómo se extrajo (consulta, export…)")
    authorization: str = Field(default="", max_length=240, description="Autorización o base legal")
    received_by: str = Field(default="", max_length=120, description="Quién recibe / custodio actual")
    source_sha256: str = Field(default="", max_length=64, description="SHA-256 calculado en el origen")
    description: str = Field(default="", max_length=600)
    notes: str = Field(default="", max_length=1000)

    @field_validator(
        "collected_by", "source_system", "source_timezone", "case_id", "evidence_id",
        "collection_method", "authorization", "received_by", mode="before",
    )  # fmt: skip
    @classmethod
    def _single_line(cls, value: Any) -> Any:
        return _SINGLE_LINE_CTRL.sub(" ", value).strip() if isinstance(value, str) else value

    @field_validator("description", "notes", mode="before")
    @classmethod
    def _multi_line(cls, value: Any) -> Any:
        return _MULTI_LINE_CTRL.sub(" ", value).strip() if isinstance(value, str) else value

    @field_validator("source_sha256", mode="before")
    @classmethod
    def _sha(cls, value: Any) -> Any:
        if isinstance(value, str):
            value = value.strip().lower()
            if value and not _SHA256_RE.fullmatch(value):
                raise ValueError("debe ser un SHA-256 de 64 caracteres hexadecimales")
        return value

    @field_validator("collected_at")
    @classmethod
    def _not_future(cls, value: datetime) -> datetime:
        # Sin zona horaria se interpreta tal cual; se tolera un día por diferencias de zona.
        now = datetime.now(tz=UTC) if value.tzinfo else datetime.now(tz=UTC).replace(tzinfo=None)
        if value > now + timedelta(days=1):
            raise ValueError("la fecha de recolección no puede estar en el futuro")
        return value


def sidecar_path(source: Path) -> Path:
    return source.with_name(source.name + SIDECAR_SUFFIX)


def make_read_only(path: Path) -> bool:
    """Quita los permisos de escritura y de lectura ajena (atributo «solo lectura» en Windows, 0400 en POSIX).

    Devuelve si el archivo quedó efectivamente sin bits de escritura. Es una protección operativa: la garantía
    criptográfica sigue siendo el SHA-256 registrado (algunos montajes, p. ej. de Docker Desktop, la ignoran)."""
    try:
        os.chmod(path, stat.S_IREAD)  # 0400: solo el dueño puede leer (no 0444)
    except OSError:
        return False
    return is_read_only(path)


def is_read_only(path: Path) -> bool:
    try:
        return not (path.stat().st_mode & _WRITE_BITS)
    except OSError:
        return False


def build_record(
    intake: CustodyIntake, *, original_filename: str, stored_name: str, size_bytes: int, sha256: str,
    tool: str, evidence_id: str, read_only: bool,
) -> dict[str, Any]:  # fmt: skip
    data = intake.model_dump(mode="json")
    data["evidence_id"] = evidence_id
    return {
        "schema": SCHEMA,
        "intake": data,
        "automatic": {
            "original_filename": _SINGLE_LINE_CTRL.sub("_", Path(original_filename).name)[:200],
            "stored_name": stored_name,
            "size_bytes": size_bytes,
            "hash_algorithm": "SHA-256",
            "sha256": sha256,
            "source_hash_match": (intake.source_sha256 == sha256) if intake.source_sha256 else None,
            "received_at_utc": datetime.now(tz=UTC).isoformat(),
            "tool": tool,
            "read_only": read_only,
        },
    }


def write_sidecar(source: Path, record: dict[str, Any]) -> Path:
    path = sidecar_path(source)
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    make_read_only(path)
    return path


def load_intake(source: Path) -> dict[str, Any] | None:
    """Lee el acta acompañante del archivo, si existe. Un acta corrupta es un error (no se ignora)."""
    path = sidecar_path(source)
    if not path.is_file():
        return None
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
        sha = record["automatic"]["sha256"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise CustodyIntakeError("El acta de cadena de custodia del archivo está dañada o es ilegible.") from exc
    if record.get("schema") != SCHEMA or not isinstance(sha, str) or not _SHA256_RE.fullmatch(sha):
        raise CustodyIntakeError("El acta de cadena de custodia del archivo no tiene un formato válido.")
    return dict(record)
