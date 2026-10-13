"""Orquestación del análisis: un único punto de entrada usado por la CLI y por la web.

Flujo de `run_analysis`:
1. Hash SHA-256 del original + evento de custodia.
2. Perfil del CSV en streaming.
3. [detect=True] "Staging" columnar: el CSV se parsea UNA vez a Parquet (tipado y comprimido,
   ~35 MB frente a 1.1 GB). Las consultas posteriores leen solo las columnas que necesitan.
   Medido: detección 45 s leyendo el CSV repetidamente vs ~8 s leyendo el Parquet.
4. [detect=True] Métricas de tráfico + detectores registrados (MVP: IDOR) + risk scoring.
5. Re-hash del original (no debe cambiar durante el análisis).
6. Artefactos JSON + manifiesto de integridad + eventos de custodia.

Datos sensibles: los tokens nunca se escriben completos en los artefactos de análisis NI en el Parquet de
staging: desde el staging se trabaja con la huella (`tok_…`) + pista parcial. El mapa huella→token de los actores
sospechosos se guarda aparte en `sensitive/token_map.json` (permisos 0600, carpeta 0700) porque es necesario para
la revocación (acción de contención).

Corroboración (opcional): una fuente de ownership de la aplicación (`forensics/corroboration.py`) es lo único que
puede convertir la hipótesis en impacto confirmado.
"""

from __future__ import annotations

import json
import os
import stat
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import polars as pl

from idor_ir.config import Settings
from idor_ir.detection import registered, traffic_metrics
from idor_ir.detection.base import DetectionResult
from idor_ir.detection.features import with_automation_flag
from idor_ir.forensics.corroboration import OwnershipError, load_ownership
from idor_ir.forensics.custody_intake import CustodyIntakeError, is_read_only, load_intake
from idor_ir.forensics.evidence import build_evidence, iocs_to_csv
from idor_ir.forensics.integrity import CustodyLog, FileFingerprint, IntegrityManifest, atomic_write_text, sha256_file
from idor_ir.ingestion import DatasetProfile, enrich, profile_dataset, scan_logs
from idor_ir.ingestion.autoprofile import infer_profile, object_labels, scope_label
from idor_ir.profile import IncidentProfile
from idor_ir.redaction import fingerprint_token, token_hint

STAGED_COLUMNS = ["ts", "status", "path", "http_user_agent", "source_ip", "invoice_id_num", "site_id", "authtoken"]
TOP_IPS_IN_REPORT = 50
SENSITIVE_LEVELS = {"critico", "alto", "medio"}


class AnalysisError(RuntimeError):
    """Error controlado del pipeline (mensaje seguro para mostrar)."""


@dataclass
class AnalysisResult:
    run_id: str
    run_dir: Path
    source: FileFingerprint
    profile: DatasetProfile
    artifacts: list[str] = field(default_factory=list)
    timings: dict[str, float] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)


def new_run_id() -> str:
    return datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]


ProgressFn = Callable[[str, str], None]


def _noop(stage: str, detail: str) -> None:
    return None


def resolve_incident_profile(source: Path, settings: Settings) -> tuple[IncidentProfile, dict[str, Any]]:
    """Perfil del incidente de esta ejecución.

    - `profile_mode=auto` (defecto): se deduce del dataset y luego se aplican los campos que el analista fijó
      explícitamente (web/CLI). Si se cambia el endpoint o el parámetro del objeto sin nombrar los objetos, los
      nombres se recalculan para que los textos sigan siendo coherentes.
    - `profile_mode=fixed`: los valores de `.env` + los campos explícitos, sin detección.
    """
    overrides = dict(settings.profile_overrides)
    if settings.profile_mode == "fixed":
        return settings.profile(), {"mode": "fijo (.env)", "overrides": overrides}
    inference = infer_profile(scan_logs(source, settings.csv_separator), settings.profile())
    data = inference.profile.as_dict()
    mapped = {("endpoint" if k == "target_endpoint" else k): v for k, v in overrides.items()}
    data.update(mapped)
    if ({"endpoint", "object_param"} & set(mapped)) and not ({"object_label", "object_label_plural"} & set(mapped)):
        data["object_label"], data["object_label_plural"] = object_labels(data["endpoint"], data["object_param"])
    if "scope_param" in mapped and "scope_label" not in mapped and data["scope_param"]:
        data["scope_label"] = scope_label(data["scope_param"])
    inference.overrides = overrides
    return IncidentProfile(**data), inference.as_dict()


def restrict(path: Path, directory: bool = False) -> None:
    """Solo el dueño: 0700 para carpetas sensibles, 0600 para archivos (en Windows no aplica: se ignora)."""
    try:
        os.chmod(path, stat.S_IRWXU if directory else stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def run_analysis(
    source: Path,
    settings: Settings,
    detect: bool = True,
    on_progress: ProgressFn | None = None,
    ownership: Path | None = None,
) -> AnalysisResult:
    run_id = new_run_id()
    run_dir = settings.output_dir / run_id
    custody = CustodyLog(settings.output_dir / "custody_log.jsonl")
    timings: dict[str, float] = {}
    progress = on_progress or _noop

    custody.append("run_started", {"run_id": run_id, "file": source.name, "detect": detect})

    progress("hash", "Calculando SHA-256 del archivo original")
    t = time.perf_counter()
    fingerprint = FileFingerprint.of(source)
    timings["hash_s"] = round(time.perf_counter() - t, 2)
    custody.append(
        "source_hashed", {"run_id": run_id, "sha256": fingerprint.sha256, "size_bytes": fingerprint.size_bytes}
    )

    # Acta de cadena de custodia (archivos cargados por la web): el hash al recibirlo debe coincidir con el actual.
    try:
        intake = load_intake(source)
    except CustodyIntakeError as exc:
        custody.append("custody_intake_invalid", {"run_id": run_id, "file": source.name})
        raise AnalysisError(str(exc)) from exc
    if intake is not None:
        received_sha = intake["automatic"]["sha256"]
        if received_sha != fingerprint.sha256:
            custody.append(
                "custody_hash_mismatch",
                {"run_id": run_id, "evidence_id": intake["intake"].get("evidence_id"),
                 "received_sha256": received_sha, "current_sha256": fingerprint.sha256},
            )  # fmt: skip
            raise AnalysisError(
                "El archivo no coincide con el SHA-256 registrado al recibirlo: cadena de custodia rota; no se analiza."
            )
        custody.append(
            "custody_intake_verified",
            {"run_id": run_id, "evidence_id": intake["intake"].get("evidence_id"), "sha256": received_sha},
        )

    progress("incident", "Detectando endpoint, parámetros y objetos expuestos")
    t = time.perf_counter()
    incident, inference = resolve_incident_profile(source, settings)
    timings["incident_profile_s"] = round(time.perf_counter() - t, 2)
    custody.append(
        "incident_profile",
        {"run_id": run_id, "profile": incident.as_dict(), "mode": inference["mode"],
         "confidence": inference.get("confidence")},
    )  # fmt: skip

    progress("profile", "Validando esquema y perfilando el dataset")
    profile = profile_dataset(
        source,
        separator=settings.csv_separator,
        timestamp_format=settings.timestamp_format,
        profile=incident,
    )
    timings["profile_s"] = profile.elapsed_seconds

    manifest = IntegrityManifest(
        run_id=run_id,
        source=fingerprint,
        parameters={
            "csv_separator": settings.csv_separator,
            "timestamp_format": settings.timestamp_format,
            "target_endpoint": settings.target_endpoint,
            "incident_profile": incident.as_dict(),
            "incident_profile_inference": inference,
            "detection_date": settings.detection_date.isoformat() if settings.detection_date else None,
            "source_read_only": is_read_only(source),
            "custody_intake": (
                {
                    "evidence_id": intake["intake"].get("evidence_id"),
                    "case_id": intake["intake"].get("case_id"),
                    "received_sha256_match": True,
                }
                if intake
                else None
            ),
        },
    )
    result = AnalysisResult(run_id=run_id, run_dir=run_dir, source=fingerprint, profile=profile, timings=timings)
    _write_json(run_dir / "profile.json", asdict(profile), manifest, result)
    if intake is not None:
        _write_json(run_dir / "custody_intake.json", intake, manifest, result)

    if detect:
        _run_detection(source, settings, run_dir, manifest, result, progress, incident, inference, ownership, custody)

    progress("verify", "Re-verificando el hash del original")
    if sha256_file(source) != fingerprint.sha256:
        custody.append("source_changed_during_analysis", {"run_id": run_id})
        raise AnalysisError("El archivo cambió durante el análisis; resultados descartados.")

    manifest.parameters["pipeline_seconds"] = round(sum(timings.values()), 2)
    manifest.save(run_dir / "manifest.json")
    custody.append("analysis_completed", {"run_id": run_id, "artifacts": [a.model_dump() for a in manifest.artifacts]})
    return result


def _run_detection(
    source: Path,
    settings: Settings,
    run_dir: Path,
    manifest: IntegrityManifest,
    result: AnalysisResult,
    progress: ProgressFn = _noop,
    incident: IncidentProfile | None = None,
    inference: dict[str, Any] | None = None,
    ownership: Path | None = None,
    custody: CustodyLog | None = None,
) -> None:
    # 1) Staging columnar (streaming CSV -> Parquet).
    progress("staging", "Convirtiendo el CSV a Parquet (streaming)")
    t = time.perf_counter()
    staged = run_dir / "work" / "parsed.parquet"
    staged.parent.mkdir(parents=True, exist_ok=True)
    incident = incident or settings.profile()
    parsed = enrich(scan_logs(source, settings.csv_separator), settings.timestamp_format, incident).select(
        STAGED_COLUMNS
    )
    # La regex de automatización se evalúa sobre los user agents ÚNICOS (decenas) y se une por
    # hash join, en vez de evaluarla 4.5 M veces (medido en 2 vCPU: staging de 21,9 s a 7,9 s).
    # Igual con las credenciales: se calcula la huella de cada token ÚNICO y el Parquet guarda solo la huella.
    ua_unique, tok_unique = pl.collect_all(
        [parsed.select("http_user_agent").unique(), parsed.select("authtoken").drop_nulls().unique()],
        engine="streaming",
    )
    ua_flags = with_automation_flag(ua_unique.lazy()).collect()
    raw_tokens = tok_unique["authtoken"].to_list()
    fps = [fingerprint_token(t) for t in raw_tokens]
    token_hints = {fp: token_hint(raw) for fp, raw in zip(fps, raw_tokens, strict=True)}
    raw_by_fp = dict(zip(fps, raw_tokens, strict=True))
    tok_df = pl.DataFrame(
        {"authtoken": raw_tokens, "authtoken_fp": fps}, schema={"authtoken": pl.String, "authtoken_fp": pl.String}
    )
    (
        parsed.join(ua_flags.lazy(), on="http_user_agent", how="left", nulls_equal=True)
        .join(tok_df.lazy(), on="authtoken", how="left")
        .drop("authtoken")
        .rename({"authtoken_fp": "authtoken"})
        .sink_parquet(staged)
    )
    restrict(staged.parent, directory=True)
    restrict(staged)
    manifest.add_artifact(staged, base=run_dir)
    result.artifacts.append(str(staged.relative_to(run_dir)))
    result.timings["staging_s"] = round(time.perf_counter() - t, 2)

    lf = pl.scan_parquet(staged)

    # 2) Métricas generales [R3].
    progress("metrics", "Calculando métricas de tráfico")
    t = time.perf_counter()
    metrics = traffic_metrics(lf)
    result.timings["metrics_s"] = round(time.perf_counter() - t, 2)
    _write_json(run_dir / "metrics.json", metrics, manifest, result)

    # 3) Detectores registrados [R2, R5].
    progress("detection", "Detección IDOR y risk scoring (z-score + Isolation Forest)")
    t = time.perf_counter()
    detections = {name: det.run(lf, incident) for name, det in registered().items()}
    result.timings["detection_s"] = round(time.perf_counter() - t, 2)
    manifest.parameters["detectors"] = {name: d.parameters for name, d in detections.items()}

    report, token_map = _detection_report(detections, token_hints, raw_by_fp)
    _write_json(run_dir / "detection.json", report, manifest, result)
    if token_map:
        (run_dir / "sensitive").mkdir(parents=True, exist_ok=True)
        restrict(run_dir / "sensitive", directory=True)
        _write_json(run_dir / "sensitive" / "token_map.json", token_map, manifest, result)
        restrict(run_dir / "sensitive" / "token_map.json")

    # Corroboración opcional con una fuente de ownership de la aplicación.
    own_df: pl.DataFrame | None = None
    own_meta: dict[str, Any] | None = None
    if ownership is not None:
        try:
            own_df = load_ownership(ownership, incident)
        except OwnershipError as exc:
            raise AnalysisError(str(exc)) from exc
        own_fp = FileFingerprint.of(ownership)
        own_meta = {"name": own_fp.name, "sha256": own_fp.sha256, "rows": own_df.height}
        manifest.parameters["ownership_source"] = own_meta
        if custody is not None:
            custody.append("ownership_source_used", {"run_id": result.run_id, **own_meta})
    result.summary = {name: rep["summary"] for name, rep in report["detectors"].items()}

    # 4) Evidencia forense [R6, R7, R12] a partir del detector IDOR.
    if "idor" in detections:
        progress("evidence", "Generando evidencia forense, IOCs y timeline")
        t = time.perf_counter()
        idor = detections["idor"]
        evidence = build_evidence(
            lf,
            idor.actors["source_ip"],
            idor.actors["authtoken"],
            dataset_start=result.profile.first_timestamp,
            dataset_end=result.profile.last_timestamp,
            detection_date=settings.detection_date,
            profile=incident,
            token_hints=token_hints,
            ownership=own_df,
            ownership_meta=own_meta,
        )
        evidence["metadata"] = {
            "run_id": result.run_id,
            "source_file": result.source.name,
            "source_sha256": result.source.sha256,
            "source_size_bytes": result.source.size_bytes,
            "dataset_range": [str(result.profile.first_timestamp), str(result.profile.last_timestamp)],
            "total_records": result.profile.total_rows,
            "profile": incident.as_dict(),
            "profile_inference": inference or {},
            "detection_date": settings.detection_date.isoformat() if settings.detection_date else None,
        }
        result.timings["evidence_s"] = round(time.perf_counter() - t, 2)
        _write_json(run_dir / "evidence.json", evidence, manifest, result)
        iocs_csv = run_dir / "iocs.csv"
        atomic_write_text(iocs_csv, iocs_to_csv(evidence["iocs"]))
        manifest.add_artifact(iocs_csv, base=run_dir)
        result.artifacts.append("iocs.csv")
        manifest.parameters["assumptions"] = evidence["assumptions"]


def _detection_report(
    detections: dict[str, DetectionResult],
    token_hints: dict[str, str] | None = None,
    raw_by_fp: dict[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Convierte los DataFrames puntuados en JSON. Los actores `authtoken` ya son huellas (staging)."""
    hints = token_hints or {}
    raws = raw_by_fp or {}
    token_map: dict[str, str] = {}
    out: dict[str, Any] = {"detectors": {}}
    for name, det in detections.items():
        tables: dict[str, Any] = {}
        summary: dict[str, Any] = {}
        for key, df in det.actors.items():
            levels = {r["risk_level"]: int(r["len"]) for r in df.group_by("risk_level").len().iter_rows(named=True)}
            rows = df.head(TOP_IPS_IN_REPORT) if key == "source_ip" else df
            records = [_actor_record(r) for r in rows.iter_rows(named=True)]
            if key == "authtoken":
                for rec, value in zip(records, rows["actor"].to_list(), strict=True):
                    fp = value if value in hints else fingerprint_token(value)
                    raw = raws.get(fp, value)
                    rec["actor"] = fp
                    rec["token_hint"] = hints.get(fp) or token_hint(raw)
                    if rec["risk_level"] in SENSITIVE_LEVELS:
                        token_map[fp] = raw
            tables[key] = {"total_actors": df.height, "levels": levels, "actors": records}
            summary[key] = {"total": df.height, **levels}
        out["detectors"][name] = {"parameters": det.parameters, "summary": summary, "tables": tables}
    return out, token_map


_RECORD_FIELDS = (
    "actor", "risk_score", "risk_level", "reasons", "requests", "unique_invoices", "unique_sites", "unique_ips",
    "unique_tokens", "unique_user_agents", "success", "client_errors", "count_401", "count_403", "success_ratio",
    "automation_ratio", "invoice_density", "requests_per_source_day", "invoices_per_source_day", "z_requests",
    "z_unique_invoices", "if_score", "possible_bot", "first_seen", "last_seen", "first_success", "active_days",
)  # fmt: skip


def _actor_record(row: dict[str, Any]) -> dict[str, Any]:
    rec: dict[str, Any] = {}
    for key in _RECORD_FIELDS:
        value = row.get(key)
        if isinstance(value, float):
            value = round(value, 4)
        elif isinstance(value, datetime):
            value = value.isoformat()
        rec[key] = value
    return rec


def _write_json(path: Path, data: Any, manifest: IntegrityManifest, result: AnalysisResult) -> None:
    atomic_write_text(path, json.dumps(data, indent=2, ensure_ascii=False, default=str))
    manifest.add_artifact(path, base=result.run_dir)
    result.artifacts.append(str(path.relative_to(result.run_dir)))


def verify_run(run_dir: Path, output_dir: Path, source: Path | None = None) -> list[dict[str, Any]]:
    """Re-verifica un run: hashes de artefactos (análisis, agentes y enriquecimiento TI), cadena de custodia
    y, opcionalmente, el archivo original. Devuelve comprobaciones `{check, ok}` (las usan la CLI y la web)."""
    checks: list[dict[str, Any]] = []
    manifest = IntegrityManifest.model_validate_json((run_dir / "manifest.json").read_text(encoding="utf-8"))
    bases = (
        (run_dir, ""),
        (run_dir / "agents", "agents/"),
        (run_dir / "agents" / "chats", "agents/chats/"),
        (run_dir / "enrichment", "enrichment/"),
    )
    for base, prefix in bases:
        path = base / "manifest.json"
        if not path.is_file():
            continue
        for artifact in IntegrityManifest.model_validate_json(path.read_text(encoding="utf-8")).artifacts:
            target = (base / artifact.name).resolve()
            # Un manifiesto manipulado no debe poder hacer leer archivos fuera del run.
            ok = target.is_relative_to(base.resolve()) and target.is_file() and sha256_file(target) == artifact.sha256
            checks.append({"check": f"artefacto {prefix}{artifact.name}", "ok": ok})
    checks.append({"check": "cadena de custodia", "ok": CustodyLog(output_dir / "custody_log.jsonl").verify()})
    if source is not None:
        ok = sha256_file(source) == manifest.source.sha256
        checks.append({"check": f"original {source.name} (SHA-256 {manifest.source.sha256[:16]}…)", "ok": ok})
    return checks
