"""Estado compartido entre procesos: caché de resultados, contadores de cuota y auditoría encadenada.

Con transporte stdio cada cliente lanza su PROPIA copia del gateway (la web, Claude Desktop...). Para que
la cuota diaria de VirusTotal no se duplique entre copias, el estado vive en archivos de un directorio común
(`TI_DATA_DIR`) protegidos por un candado de archivo (creación exclusiva, portable Windows/Linux).
Nada de lo que se guarda aquí es secreto: ni claves ni cabeceras.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

LOCK_TIMEOUT_S = 10.0
LOCK_STALE_S = 30.0  # un candado más viejo se considera huérfano (proceso terminado abruptamente)


class StateError(RuntimeError):
    pass


@contextlib.contextmanager
def file_lock(path: Path) -> Iterator[None]:
    lock = path.with_suffix(path.suffix + ".lock")
    deadline = time.monotonic() + LOCK_TIMEOUT_S
    while True:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            break
        except FileExistsError:
            try:
                if time.time() - lock.stat().st_mtime > LOCK_STALE_S:
                    lock.unlink(missing_ok=True)
                    continue
            except FileNotFoundError:
                continue
            if time.monotonic() > deadline:
                raise StateError(f"No se pudo bloquear {path.name} (otro proceso lo retiene)") from None
            time.sleep(0.02)
    try:
        yield
    finally:
        lock.unlink(missing_ok=True)


def _read(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}  # inexistente o corrupto: el estado no es evidencia, se reconstruye


def _write(path: Path, data: dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)  # atómico en el mismo volumen


def period_key(period: str, now: datetime | None = None) -> str:
    now = now or datetime.now(UTC)
    if period == "week":
        year, week, _ = now.isocalendar()
        return f"{year}-W{week:02d}"
    if period == "month":
        return now.strftime("%Y-%m")
    return now.date().isoformat()


class StateStore:
    def __init__(self, data_dir: Path, cache_ttl_hours: int = 24) -> None:
        self.dir = data_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        self.cache_path = self.dir / "cache.json"
        self.quota_path = self.dir / "quota.json"
        self.audit_path = self.dir / "audit.jsonl"
        self.ttl_s = cache_ttl_hours * 3600

    # ---- caché
    def cache_get(self, key: str) -> dict[str, Any] | None:
        if self.ttl_s <= 0:
            return None
        entry = _read(self.cache_path).get(key)
        if isinstance(entry, dict) and time.time() - float(entry.get("fetched_at", 0)) < self.ttl_s:
            return entry
        return None

    def cache_put(self, key: str, result: dict[str, Any]) -> None:
        if self.ttl_s <= 0:
            return
        with file_lock(self.cache_path):
            data = _read(self.cache_path)
            now = time.time()
            data = {k: v for k, v in data.items() if now - float(v.get("fetched_at", 0)) < self.ttl_s}  # purga
            data[key] = {"fetched_at": now, "result": result}
            _write(self.cache_path, data)

    # ---- cuota (contador por fuente y periodo)
    def quota_used(self, source: str, period: str) -> int:
        return int(_read(self.quota_path).get(source, {}).get(period_key(period), 0))

    def quota_try_consume(self, source: str, period: str, limit: int | None) -> bool:
        """Reserva una consulta si queda cupo. Atómico entre procesos (lee-verifica-escribe bajo candado)."""
        with file_lock(self.quota_path):
            data = _read(self.quota_path)
            key = period_key(period)
            used = int(data.get(source, {}).get(key, 0))
            if limit is not None and used >= limit:
                return False
            data[source] = {key: used + 1}  # solo se conserva el periodo en curso
            _write(self.quota_path, data)
            return True

    # ---- auditoría (JSONL encadenado con SHA-256: alterar o borrar una línea rompe la cadena)
    def audit(self, event: str, details: dict[str, Any]) -> None:
        with file_lock(self.audit_path):
            prev = "0" * 64
            if self.audit_path.is_file():
                lines = self.audit_path.read_text(encoding="utf-8").splitlines()
                if lines:
                    prev = json.loads(lines[-1])["hash"]
            entry = {"ts": datetime.now(UTC).isoformat(timespec="seconds"), "event": event, "details": details}
            entry["prev"] = prev
            entry["hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
            with self.audit_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def verify_audit(self) -> bool:
        if not self.audit_path.is_file():
            return True
        prev = "0" * 64
        for line in self.audit_path.read_text(encoding="utf-8").splitlines():
            entry = json.loads(line)
            digest = entry.pop("hash")
            if (
                entry["prev"] != prev
                or hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest() != digest
            ):
                return False
            prev = digest
        return True
