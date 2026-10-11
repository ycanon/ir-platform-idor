"""Integridad de la evidencia: hash del original, manifiesto y registro de custodia [R7].

Tres piezas, cada una con un propósito distinto:

1. `sha256_file`: hash del archivo original calculado por bloques de 1 MiB
   (un archivo de 1.1 GB nunca se carga completo en memoria).

2. `IntegrityManifest`: "acta" de una ejecución de análisis: qué archivo se analizó
   (nombre, tamaño, SHA-256), con qué herramienta/versión/parámetros y qué artefactos produjo,
   cada uno con su propio hash. Permite a un tercero re-verificar todo.

3. `CustodyLog`: registro append-only en JSONL donde cada entrada incluye el hash de la anterior
   (cadena de hashes). Si alguien modifica o borra una entrada intermedia, `verify()` lo detecta.
   No sustituye a un almacenamiento WORM, pero hace la manipulación evidente (tamper-evident).
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from idor_ir import TOOL_NAME, __version__

_CHUNK_SIZE = 1024 * 1024  # 1 MiB
GENESIS_HASH = "0" * 64  # "hash previo" de la primera entrada de la cadena


def sha256_file(path: Path) -> str:
    """SHA-256 en hexadecimal, leyendo el archivo por bloques."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _utc_now() -> str:
    return datetime.now(tz=UTC).isoformat()


def _canonical_json(data: dict[str, Any]) -> str:
    """JSON determinista (claves ordenadas, sin espacios) para que el hash sea reproducible."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def atomic_write_text(path: Path, content: str) -> None:
    """Escribe en un archivo temporal y lo renombra: nunca deja un archivo a medio escribir."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp_", suffix=path.suffix)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


class FileFingerprint(BaseModel):
    """Identidad verificable de un archivo."""

    name: str  # solo el nombre, no la ruta absoluta (evita exponer estructura del equipo)
    size_bytes: int
    sha256: str
    modified_utc: str

    @classmethod
    def of(cls, path: Path) -> FileFingerprint:
        stat = path.stat()
        return cls(
            name=path.name,
            size_bytes=stat.st_size,
            sha256=sha256_file(path),
            modified_utc=datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat(),
        )


class IntegrityManifest(BaseModel):
    """Manifiesto de integridad de una ejecución de análisis."""

    run_id: str
    tool: str = TOOL_NAME
    tool_version: str = __version__
    created_utc: str = Field(default_factory=_utc_now)
    source: FileFingerprint
    parameters: dict[str, Any] = Field(default_factory=dict)
    artifacts: list[FileFingerprint] = Field(default_factory=list)

    def add_artifact(self, path: Path, base: Path | None = None) -> FileFingerprint:
        """Registra un artefacto. Con `base`, el nombre se guarda como ruta relativa (p. ej. `work/x.parquet`)."""
        fingerprint = FileFingerprint.of(path)
        if base is not None:
            fingerprint = fingerprint.model_copy(update={"name": path.relative_to(base).as_posix()})
        self.artifacts.append(fingerprint)
        return fingerprint

    def save(self, path: Path) -> None:
        atomic_write_text(path, self.model_dump_json(indent=2))


def verify_source(manifest: IntegrityManifest, path: Path) -> bool:
    """True si el archivo actual coincide con el hash registrado en el manifiesto."""
    return sha256_file(path) == manifest.source.sha256


class CustodyLog:
    """Registro de custodia encadenado por hashes (JSONL, solo se agrega)."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS_HASH
        last = GENESIS_HASH
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last = json.loads(line)["entry_hash"]
        return last

    def append(self, event: str, details: dict[str, Any]) -> dict[str, Any]:
        """Agrega un evento. `details` no debe contener secretos (se usa con datos ya enmascarados)."""
        body = {
            "ts": _utc_now(),
            "event": event,
            "details": details,
            "prev_hash": self._last_hash(),
        }
        entry = {**body, "entry_hash": hashlib.sha256(_canonical_json(body).encode()).hexdigest()}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(_canonical_json(entry) + "\n")
        return entry

    def verify(self) -> bool:
        """Recalcula la cadena completa. False si alguna entrada fue alterada, borrada o reordenada."""
        if not self.path.exists():
            return True
        expected_prev = GENESIS_HASH
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                entry = json.loads(line)
                stored_hash = entry.pop("entry_hash", None)
                if entry.get("prev_hash") != expected_prev:
                    return False
                recalculated = hashlib.sha256(_canonical_json(entry).encode()).hexdigest()
                if recalculated != stored_hash:
                    return False
                expected_prev = stored_hash
        return True
