from __future__ import annotations

import hashlib
import json
from pathlib import Path

from idor_ir.forensics import CustodyLog, IntegrityManifest, sha256_file, verify_source
from idor_ir.forensics.integrity import FileFingerprint


def test_sha256_matches_hashlib(sample_csv: Path) -> None:
    assert sha256_file(sample_csv) == hashlib.sha256(sample_csv.read_bytes()).hexdigest()


def test_manifest_roundtrip_and_tamper_detection(sample_csv: Path, tmp_path: Path) -> None:
    manifest = IntegrityManifest(run_id="r1", source=FileFingerprint.of(sample_csv))
    out = tmp_path / "manifest.json"
    manifest.save(out)
    loaded = IntegrityManifest.model_validate_json(out.read_text(encoding="utf-8"))
    assert verify_source(loaded, sample_csv)
    # Manipular un byte del original debe romper la verificación.
    sample_csv.write_text(sample_csv.read_text(encoding="utf-8") + "x", encoding="utf-8")
    assert not verify_source(loaded, sample_csv)


def test_manifest_stores_only_file_name(sample_csv: Path) -> None:
    fp = FileFingerprint.of(sample_csv)
    assert fp.name == "sample.csv"  # sin ruta absoluta del equipo


def test_custody_chain_valid(tmp_path: Path) -> None:
    log = CustodyLog(tmp_path / "custody.jsonl")
    log.append("a", {"x": 1})
    log.append("b", {"x": 2})
    assert log.verify()


def test_custody_chain_detects_modification(tmp_path: Path) -> None:
    path = tmp_path / "custody.jsonl"
    log = CustodyLog(path)
    log.append("a", {"x": 1})
    log.append("b", {"x": 2})
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["details"]["x"] = 999  # manipulación
    lines[0] = json.dumps(entry)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not log.verify()


def test_custody_chain_detects_deletion(tmp_path: Path) -> None:
    path = tmp_path / "custody.jsonl"
    log = CustodyLog(path)
    for i in range(3):
        log.append("e", {"i": i})
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    assert not log.verify()
