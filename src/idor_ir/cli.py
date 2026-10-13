"""Interfaz de línea de comandos.

Comandos:
  ingest  --file RUTA     Valida esquema, SHA-256, perfil en streaming, manifiesto y custodia.
  analyze --file RUTA     Además: métricas de tráfico, detección IDOR y risk scoring.
  agents  --run RUN_ID [--approve interactive|all|none] [--no-llm]
                          Triage -> Forensic -> Response (LangGraph + Ollama), aprobación humana y dry-run.
  llm-check               Diagnóstico de Ollama: conectividad y esquemas aceptados.
  enrich  --run RUN_ID [--sources a,b] [--yes]
                          Reputación de las IPs públicas del Top 20 vía el servidor MCP ti-gateway (VirusTotal, OTX,
                          AbuseIPDB, GreyNoise, IPinfo, Shodan, abuse.ch). Claves en TI_<ID>_API_KEY.
  serve [--host --port]   Interfaz web en http://127.0.0.1:8000
  verify  --run RUN_ID [--file RUTA]
                          Re-verifica artefactos, cadena de custodia y (opcional) el archivo original.
  validate-detector [--seeds N] [--target-fpr F] [--no-campaigns]
                          Precisión, recall y falsos positivos del detector en un banco sintético etiquetado.

Uso:  python -m idor_ir analyze --file data/three_months.csv
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from idor_ir.config import RUN_PROFILE_FIELDS, Settings, get_settings
from idor_ir.ingestion import SchemaError
from idor_ir.logging_setup import configure_logging
from idor_ir.pipeline import AnalysisError, AnalysisResult, run_analysis, verify_run
from idor_ir.profile import IncidentProfile

logger = logging.getLogger("idor_ir.cli")

# Lista blanca de extensiones: solo el formato documentado en el reto [Reto §2].
ALLOWED_SUFFIXES = {".csv"}

EXIT_OK, EXIT_ERROR, EXIT_INPUT = 0, 1, 2


class InputError(ValueError):
    """Error atribuible a la entrada del usuario (mensaje seguro para mostrar)."""


def _validate_input_file(raw: str) -> Path:
    path = Path(raw).expanduser().resolve()
    if not path.is_file():
        raise InputError("El archivo no existe o no es un archivo regular.")
    if path.suffix.lower() not in ALLOWED_SUFFIXES:
        raise InputError(f"Extensión no soportada. Permitidas: {', '.join(sorted(ALLOWED_SUFFIXES))}")
    return path


def _run_settings(args: argparse.Namespace, settings: Settings) -> Settings:
    """Perfil del incidente y fecha de detección de esta ejecución (flags > .env > valores por defecto)."""
    overrides = {k: getattr(args, k, None) for k in ("detection_date", *RUN_PROFILE_FIELDS)}
    try:
        return settings.for_run(overrides)
    except ValueError as exc:
        raise InputError(str(exc)) from exc


def _add_run_options(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group(
        "perfil del incidente (opcional: por defecto se DETECTA del dataset; estos flags fijan campos concretos)"
    )
    g.add_argument("--detection-date", dest="detection_date", help="Fecha de detección ISO (AAAA-MM-DD) para TTD")
    g.add_argument("--endpoint", dest="target_endpoint", help="Endpoint analizado, p. ej. /orders/search")
    g.add_argument("--object-param", dest="object_param", help="Parámetro con el ID del objeto, p. ej. order_id")
    g.add_argument("--scope-param", dest="scope_param", help="Parámetro de ámbito/tenant ('' si no existe)")
    g.add_argument("--token-param", dest="token_param", help="Parámetro con la credencial, p. ej. token")
    g.add_argument("--object-label", dest="object_label", help="Nombre del objeto en singular, p. ej. pedido")
    g.add_argument("--object-label-plural", dest="object_label_plural", help="Plural, p. ej. pedidos")
    g.add_argument("--scope-label", dest="scope_label", help="Nombre del ámbito, p. ej. cliente")


def cmd_ingest(args: argparse.Namespace, settings: Settings) -> int:
    source = _validate_input_file(args.file)
    logger.info("Inicio de ingesta", extra={"file": source.name})
    result = run_analysis(source, _run_settings(args, settings), detect=False)
    _print_profile(result)
    return EXIT_OK


def cmd_analyze(args: argparse.Namespace, settings: Settings) -> int:
    source = _validate_input_file(args.file)
    logger.info("Inicio de análisis", extra={"file": source.name})
    ownership = _validate_input_file(args.ownership) if getattr(args, "ownership", None) else None
    result = run_analysis(source, _run_settings(args, settings), detect=True, ownership=ownership)
    _print_profile(result)
    _print_detection(result)
    return EXIT_OK


def _resolve_run(run: str, settings: Settings) -> Path:
    output_root = settings.output_dir.resolve()
    run_dir = (settings.output_dir / run).resolve()
    # Evita path traversal (p. ej. --run ..\..\Windows): el run debe quedar dentro de output_dir.
    if not run_dir.is_relative_to(output_root) or not run_dir.is_dir():
        raise InputError("Run inexistente.")
    return run_dir


def _interactive_decider(payload: dict[str, object]) -> dict[str, str]:
    """Intervención humana en consola: aprobar (a) o rechazar (r) cada acción pendiente."""
    decisions: dict[str, str] = {}
    pending = payload.get("pending_actions", [])
    automatic = payload.get("automatic_actions", [])
    print("\n=== Aprobación humana requerida (dry-run) ===")
    if isinstance(automatic, list) and automatic:
        print("\nSe ejecutan sin aprobación (reversibles, riesgo de falso positivo bajo e impacto de negocio bajo):")
        for action in automatic:
            print(f"  [{action['action_id']}] {action['action_type']}: {action['target']}")
        print("\nRequieren su decisión:")
    for action in pending if isinstance(pending, list) else []:
        print(f"\n[{action['action_id']}] {action['action_type']} ({action['phase']}, prioridad {action['priority']})")
        print(f"  Objetivo: {action['target']}")
        print(f"  Motivo: {action['rationale']}")
        print(f"  Riesgo FP: {action['false_positive_risk']}  | Impacto de negocio: {action['business_impact']}")
        answer = input("  ¿Aprobar? [a]probar / [r]echazar (por defecto r): ").strip().lower()
        decisions[action["action_id"]] = "approve" if answer in {"a", "aprobar", "s", "si", "sí", "y"} else "reject"
    return decisions


def cmd_agents(args: argparse.Namespace, settings: Settings) -> int:
    from idor_ir.agents.llm import OllamaLLM
    from idor_ir.agents.service import approve_all, reject_all, run_agents

    run_dir = _resolve_run(args.run, settings)
    if not (run_dir / "evidence.json").is_file():
        raise InputError("El run no tiene evidence.json; ejecute primero 'analyze'.")
    llm = None
    if not args.no_llm:
        llm = OllamaLLM(str(settings.ollama_base_url), settings.ollama_model)
        if not llm.health():
            print(f"Aviso: Ollama no responde en {settings.ollama_base_url}; se usa la lógica determinista.")
            llm = None
        else:
            print(f"Usando {llm.name}. Generación en CPU: puede tardar algunos minutos...")
            print("Fuente de cada agente (llm / fallback) y errores: agents/decision_log.jsonl")
    decide = {"all": approve_all, "none": reject_all}.get(args.approve, _interactive_decider)
    import getpass

    operator = {"user": getpass.getuser(), "role": "cli"}
    decider = operator if args.approve == "interactive" else {**operator, "mode": f"--approve {args.approve}"}
    report = run_agents(run_dir, settings, llm, decide, started_by=operator, decided_by=lambda: decider)
    _print_agents(report, run_dir)
    return EXIT_OK


def cmd_llm_check(args: argparse.Namespace, settings: Settings) -> int:
    """Diagnóstico rápido: conectividad y aceptación de los 3 esquemas como gramática en Ollama."""
    from idor_ir.agents.llm import OllamaLLM
    from idor_ir.agents.schemas import ForensicDraft, ResponseDraft, TextFix, TriageDraft

    llm = OllamaLLM(str(settings.ollama_base_url), settings.ollama_model)
    if not llm.health():
        print(f"Ollama NO responde en {settings.ollama_base_url}")
        return EXIT_ERROR
    print(f"Ollama responde. Modelo: {settings.ollama_model}")
    results = llm.check_formats([TriageDraft, ForensicDraft, ResponseDraft, TextFix])
    for name, status in results.items():
        print(f"  {name:<15} {status}")
    return EXIT_OK if all(v == "aceptado" for v in results.values()) else EXIT_ERROR


def cmd_eval(args: argparse.Namespace, settings: Settings) -> int:
    """Banco de evaluación (mejora O13): mide al modelo local y compara modelos con el mismo run."""
    from idor_ir.agents.evaluation import compare_table, evaluate
    from idor_ir.agents.llm import OllamaLLM

    run_dir = _resolve_run(args.run, settings)
    if not (run_dir / "evidence.json").is_file():
        raise InputError("El run no tiene evidencia; ejecute 'analyze' primero.")
    models = [m.strip() for m in (args.models or settings.ollama_model).split(",") if m.strip()]
    url = str(settings.ollama_base_url)
    reports = []
    for model in models:
        llm = OllamaLLM(url, model)
        if not llm.health():
            print(f"Ollama NO responde en {url}")
            return EXIT_ERROR
        print(f"\n=== Evaluando {model} (puede tardar varios minutos en CPU) ===")
        report = evaluate(
            run_dir, settings, llm, chat_eval=not args.no_chat, agents_eval=not args.no_agents, limit=args.limit,
            progress=lambda kind, msg: print(f"  [{kind}] {msg}", flush=True),
        )  # fmt: skip
        reports.append(report)
        print(f"  Puntaje global: {report['score']}")
    print("\n" + compare_table(reports))
    print(f"\nReportes en {run_dir / 'evaluation'}")
    return EXIT_OK


def _print_agents(report: dict[str, Any], run_dir: Path) -> None:
    tri = report["triage"] if isinstance(report["triage"], dict) else {}
    fo = report["forensic"] if isinstance(report["forensic"], dict) else {}
    ro = report["response"] if isinstance(report["response"], dict) else {}
    print(f"\n=== Agentes ({report['llm']}, {report['agents_seconds']} s) ===")
    for entry in report.get("decision_log_summary", []):
        err = f" — {entry['error']}" if entry.get("error") else ""
        if entry.get("unverified_numbers"):
            err += f" — cifras no verificadas en los datos: {', '.join(entry['unverified_numbers'])}"
        print(f"  [{entry['node']}] fuente={entry['source']} {entry.get('latency_s', '')} s{err}")
    print(f"Triage: severidad {tri.get('severity')} — {tri.get('attack_type')}")
    for h in tri.get("hypotheses", []):
        print(f"  · {h}")
    print("Forense:")
    for r in fo.get("reasoning", []):
        print(f"  → {r}")
    print("  MITRE: " + ", ".join(f"{m['technique_id']} {m['name']}" for m in fo.get("mitre_attack", [])))
    executed = (
        {e["action_id"] for e in report.get("executed", [])} if isinstance(report.get("executed"), list) else set()
    )
    print("Respuesta:")
    for a in ro.get("actions", []):
        mode = "APROBACIÓN" if a["requires_human_approval"] else "auto"
        done = (
            "CONDICIONADA (evidencia insuficiente)"
            if a.get("blocked_reason")
            else "EJECUTADA (dry-run, no aplicada)"
            if a["action_id"] in executed
            else "-"
        )
        print(f"  {a['action_id']} {a['action_type']:<13} {mode:<10} {done}")
    est = report.get("response_time_estimates", {})
    if isinstance(est, dict) and est:
        bt = est.get("detection_backtest", {})
        print(
            f"TTR manual {est['manual']['ttr_hours']} h → automatizado {est['automated']['ttr_hours']} h; "
            f"TTC {est['manual']['ttc_hours']} h → {est['automated']['ttc_hours']} h"
        )
        for rule in bt.values():
            print(
                f"  Backtest: '{rule['rule']}' habría alertado el {rule['would_alert_on']} "
                f"(otros tokens alertados: {rule['other_tokens_alerted']})"
            )
    print(f"\nArtefactos en {run_dir / 'agents'}: agents_report.json, decision_log.jsonl, playbook.md, actions/\n")


def cmd_enrich(args: argparse.Namespace, settings: Settings) -> int:
    from idor_ir.enrichment.gateway_client import GatewayError
    from idor_ir.enrichment.ti import TIError, enrich_run, select_ips
    from idor_ir.web.ti_runtime import TIRuntime

    run_dir = _resolve_run(args.run, settings)
    runtime = TIRuntime(settings)  # claves desde TI_<ID>_API_KEY (o IRP_VT_API_KEY / IRP_OTX_API_KEY)
    try:
        catalog = {s["id"]: s for s in runtime.refresh_catalog()}
    except GatewayError as exc:
        raise InputError(str(exc)) from exc
    requested = [s.strip() for s in args.sources.split(",") if s.strip()] if args.sources else None
    if requested and (unknown := [s for s in requested if s not in catalog]):
        raise InputError(f"Fuentes desconocidas: {', '.join(unknown)}. Disponibles: {', '.join(catalog)}")
    sources = [s for s in (requested or catalog) if runtime.configured(s)]
    if requested and (missing := [s for s in requested if s not in sources]):
        raise InputError(f"Sin clave para: {', '.join(missing)} (defina TI_<ID>_API_KEY)")
    if not sources:
        raise InputError("Ninguna fuente tiene clave: defina TI_<ID>_API_KEY (p. ej. TI_VIRUSTOTAL_API_KEY).")
    targets, skipped = select_ips(json.loads((run_dir / "evidence.json").read_text(encoding="utf-8")))
    labels = ", ".join(catalog[s]["label"] for s in sources)
    print(f"Se consultarán {len(targets)} IPs públicas en: {labels} ({len(skipped)} omitidas por privadas).")
    for s in sources:
        if catalog[s]["publishes_queries"]:
            print(f"  ! {catalog[s]['label']}: {catalog[s]['terms_note']}")
    if not args.yes and input("¿Confirmar el envío? [s/N]: ").strip().lower() not in {"s", "si", "sí", "y"}:
        print("Cancelado.")
        return EXIT_OK

    def progress(kind: str, data: dict[str, Any]) -> None:
        if kind == "ip_done":
            print(f"  [{data['n']:>2}/{data['total']}] {data['ip']:<16} {data['verdict']}")

    import getpass

    consent = {"confirmed": True, "via": "cli", "sources": sources, "by": {"user": getpass.getuser(), "role": "cli"}}
    try:
        report = enrich_run(
            run_dir, settings, runtime.launch(sources, client="idor-ir-cli"), sources, consent, progress
        )
    except TIError as exc:
        raise InputError(str(exc)) from exc
    print(f"Resumen: {report['summary']}  ({report['stats']['seconds']} s)")
    for source, error in report["stats"]["stopped"].items():
        print(f"  ! {source}: {error}")
    print(f"Nota: {report['caveat']}")
    print(f"Artefacto: {run_dir / 'enrichment' / 'ti_enrichment.json'}")
    return EXIT_OK


def cmd_verify(args: argparse.Namespace, settings: Settings) -> int:
    run_dir = _resolve_run(args.run, settings)
    source = _validate_input_file(args.file) if args.file else None
    checks = verify_run(run_dir, settings.output_dir, source)
    for c in checks:
        print(f"[{'OK ' if c['ok'] else 'FALLA'}] {c['check']}")
    return EXIT_OK if all(c["ok"] for c in checks) else EXIT_ERROR


def _print_profile(result: AnalysisResult) -> None:
    fp, data = result.source, asdict(result.profile)
    print(f"\nRun: {result.run_id}   ->  {result.run_dir}")
    print(f"Archivo: {fp.name}  ({fp.size_bytes:,} bytes)")
    print(f"SHA-256: {fp.sha256}")
    print(f"Registros: {data['total_rows']:,}   IPs únicas: {data['unique_source_ips']:,}")
    print(f"Rango temporal: {data['first_timestamp']}  ->  {data['last_timestamp']}")
    print(
        f"Timestamps no parseados: {data['unparsed_timestamps']:,}   status no numéricos: {data['unparsed_status']:,}"
    )
    print(
        f"Peticiones a {data['target_endpoint']}: {data['target_endpoint_rows']:,}   "
        f"con ID de objeto: {data['rows_with_invoice_id']:,} (numérico: {data['rows_with_numeric_invoice_id']:,})"
    )
    print(f"HTTP status: {data['status_counts']}")
    print(f"Métodos: {data['method_counts']}")
    dates = list(data["raw_date_counts"])
    if dates:
        print(
            f"Fechas distintas: {len(dates)}  (primera '{dates[0]}', última '{dates[-1]}')  "
            f"rangos campo2/campo3: {data['date_field_ranges']}  -> formato probable: {data['date_order_hint']}"
        )
    if data["unparsed_timestamps"]:
        print(
            "ADVERTENCIA: hay timestamps sin interpretar. Revise IRP_TIMESTAMP_FORMAT "
            "(formato probable según los datos: " + str(data["date_order_hint"]) + ")."
        )
    print(f"Tiempo de procesamiento (perfil): {data['elapsed_seconds']} s")


def _print_detection(result: AnalysisResult) -> None:
    report = json.loads((result.run_dir / "detection.json").read_text(encoding="utf-8"))
    idor = report["detectors"]["idor"]["tables"]
    print("\n=== Detección IDOR (risk score 0-100) ===")
    for key, title in (("source_ip", "IPs"), ("authtoken", "Tokens")):
        table = idor[key]
        print(f"\n{title}: {table['total_actors']:,} actores  niveles={table['levels']}")
        for rec in [r for r in table["actors"] if r["risk_level"] != "bajo"][:20]:
            label = rec.get("token_hint", rec["actor"])
            print(
                f"  {rec['risk_score']:5.1f} {rec['risk_level']:<7} {label:<22} req={rec['requests']:>7,} "
                f"ids={rec['unique_invoices']:>6,} bot={rec['automation_ratio']:.0%} 2xx={rec['success_ratio']:.0%}"
            )
    _print_evidence(result)
    print(f"\nTiempos: {result.timings}")
    print(f"Artefactos: {', '.join(result.artifacts)}\n")


def _print_evidence(result: AnalysisResult) -> None:
    path = result.run_dir / "evidence.json"
    if not path.is_file():
        return
    ev = json.loads(path.read_text(encoding="utf-8"))
    a = ev["incident_answers"]
    prof = IncidentProfile.from_evidence(ev)
    if "summary" in a:
        print(f"\n=== Evidencia ===\n{a['summary']}")
        return
    print("\n=== Evidencia forense (respuestas sección 3.1) ===")
    assess = ev.get("assessment", {})
    if assess:
        print(f"Nivel de evidencia: {assess.get('level')} — {assess.get('statement')}")
    ini = a.get("1_inicio") or a.get("1_inicio_explotacion", {})
    first = ini.get("primera_actividad_sospechosa") or ini.get("primera_actividad_maliciosa")
    print(
        f"1. Actividad sospechosa desde {'≤ ' if ini.get('inicio_censurado') else ''}{first}; "
        f"primer acceso 2xx desde {ini['primer_acceso_exitoso_2xx']}. {ini['nota']}"
    )
    print(f"2. Evidencia IDOR: {a['2_evidencia_idor']['respuesta']}. {a['2_evidencia_idor']['fundamento']}")
    scope3 = a.get("3_alcance_exposicion") or a.get("3_facturas_accedidas_indebidamente", {})
    confirmed = scope3.get("accesos_indebidos_confirmados")
    print(
        f"3. {prof.object_label_plural.capitalize()} con 2xx (exposición potencial, únicas): "
        f"{scope3['unique_invoices_2xx']:,}"
        + (f" · accesos indebidos confirmados: {confirmed:,}" if confirmed is not None else " · sin corroborar")
    )
    print(f"4. Secuencial: {a['4_patron_secuencial']['respuesta']}. {a['4_patron_secuencial']['fundamento']}")
    print(f"5. Automatizado: {a['5_automatizado']['respuesta']}. {a['5_automatizado']['fundamento']}")
    camp = a["6_campanas"]
    print(
        f"6. Campañas: {camp.get('corroboradas', 0)} corroborada(s), "
        f"{camp.get('alta_confianza', camp.get('confirmadas', 0))} de alta confianza, "
        f"{camp.get('por_validar', 0)} por validar"
    )
    for c in ev["campaigns"]:
        fases = " | ".join(
            f"{p['start']}→{p['end']}: {p['median_per_day']:.0f}/día, éxito {p['success_ratio']:.0%}"
            for p in c["phases"]
        )
        label = c.get("status_label", c["status"])
        print(f"   {c['campaign_id']} [{label}] {len(c['ips'])} IPs, {len(c['tokens'])} tokens · {fases}")
    aff = a.get("7_titulares_potencialmente_expuestos") or a.get("7_usuarios_potencialmente_afectados", {})
    by_scope = f"  por {prof.scope_label}: {aff['por_site_id']}" if prof.scope_param else ""
    print(
        f"7. Titulares potencialmente expuestos (límite superior, sin confirmar): {aff['limite_superior']:,}{by_scope}"
    )
    rm = ev["response_metrics"]
    if rm.get("ttd_reference"):
        ref = (
            f"detección indicada: {rm.get('detection_date')}"
            if not rm.get("ttd_is_estimate")
            else f"ESTIMADO hasta el último registro del log {rm.get('ttd_reference')}; use --detection-date"
        )
        print(
            f"TTD: {rm.get('ttd_from_first_malicious_request_days')} días desde la primera actividad, "
            f"{rm.get('ttd_from_first_successful_access_days')} desde el primer acceso ({ref})"
        )
    inf = ev.get("metadata", {}).get("profile_inference") or {}
    if inf:
        print(f"\nPerfil del incidente ({inf.get('mode')}, confianza {inf.get('confidence')}): {prof.request_template}")
        for line in inf.get("evidence", []):
            print(f"  · {line}")


def cmd_serve(args: argparse.Namespace, settings: Settings) -> int:
    """Levanta la interfaz web. Por defecto SOLO en 127.0.0.1 (no expuesta a la red)."""
    import uvicorn

    from idor_ir.web.app import create_app

    problem = serve_preflight(args.host, settings, bool(args.ssl_certfile))
    if problem:
        print(f"Error: {problem}", file=sys.stderr)
        return EXIT_INPUT
    if bool(args.ssl_certfile) != bool(args.ssl_keyfile):
        print("Error: --ssl-certfile y --ssl-keyfile van juntos.", file=sys.stderr)
        return EXIT_INPUT
    scheme = "https" if args.ssl_certfile else "http"
    shown = "127.0.0.1" if args.host == "0.0.0.0" else args.host  # noqa: S104
    print(f"IR Platform en {scheme}://{shown}:{args.port}")
    proxies = settings.trusted_proxies.strip()
    uvicorn.run(
        create_app(settings), host=args.host, port=args.port, log_level="warning", server_header=False,
        ssl_certfile=args.ssl_certfile, ssl_keyfile=args.ssl_keyfile,
        proxy_headers=bool(proxies), forwarded_allow_ips=proxies or None,
    )  # fmt: skip
    return EXIT_OK


LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def serve_preflight(host: str, settings: Settings, tls: bool) -> str | None:
    """Fail-closed: fuera de 127.0.0.1 la plataforma NO arranca sin autenticación fuerte.

    Devuelve el motivo del rechazo, o None si se puede arrancar."""
    from idor_ir.web.security import MIN_TOKEN_LENGTH

    if host in LOOPBACK:
        return None
    access = settings.access_token.get_secret_value() if settings.access_token else ""
    approver = settings.approver_token.get_secret_value() if settings.approver_token else ""
    if not access:
        return (
            f"escuchar en {host} exige IRP_ACCESS_TOKEN (la interfaz quedaría abierta en la red). Defínalo en .env "
            "o use --host 127.0.0.1."
        )
    for name, value in (("IRP_ACCESS_TOKEN", access), ("IRP_APPROVER_TOKEN", approver)):
        if value and len(value) < MIN_TOKEN_LENGTH:
            return f"{name} debe tener al menos {MIN_TOKEN_LENGTH} caracteres para escuchar fuera de 127.0.0.1."
    if approver and approver == access:
        return "IRP_APPROVER_TOKEN debe ser distinto de IRP_ACCESS_TOKEN."
    if not tls and not settings.trusted_proxies.strip() and settings.cookie_secure is not True:
        logger.warning(
            "Servicio en %s sin TLS: use --ssl-certfile/--ssl-keyfile o un proxy TLS (IRP_TRUSTED_PROXIES) "
            "si se accede desde otra máquina.", host,
        )  # fmt: skip
    return None


def cmd_validate_detector(args: argparse.Namespace, settings: Settings) -> int:
    """Mide el detector contra un banco etiquetado y deja un reporte JSON en output/validation/."""
    import tempfile
    from datetime import UTC, datetime

    from idor_ir.detection.validation import validate

    with tempfile.TemporaryDirectory(prefix="irp-validate-") as tmp:
        report = validate(
            seeds=args.seeds, users=args.users, target_fpr=args.target_fpr,
            workdir=None if args.no_campaigns else Path(tmp),
        )  # fmt: skip
    out_dir = settings.output_dir / "validation"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"detector_validation_{datetime.now(tz=UTC):%Y%m%dT%H%M%SZ}.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Banco sintético etiquetado · {args.seeds} semilla(s) · umbral de señal = nivel medio (score >= 30)")
    for key, variants in report["summary_at_medio"].items():
        print(f"\nActor: {key}")
        head = f"  {'variante':<24} {'precisión':>10} {'recall':>8} {'FPR':>8}"
        print(f"{head}  umbral con FPR<={args.target_fpr} por semilla")
        for name, v in variants.items():
            p, r, f = v["precision_at_medio"]["mean"], v["recall_at_medio"]["mean"], v["fpr_at_medio"]["mean"]
            cal = ", ".join(
                "ninguno" if t is None else f"{t['threshold']:g} (recall {_num(t['recall'])})"
                for t in v["calibrated_thresholds"]
            )
            print(f"  {name:<24} {_num(p):>10} {_num(r):>8} {_num(f):>8}  {cal}")
    camp = report.get("campaign_layer")
    if camp:
        print("\nCapa de campañas (lo que guía la respuesta):")
        print(f"  precisión de campañas priorizadas: {_num(camp['priority_precision_mean'])}")
        print(f"  estilos de ataque en campaña priorizada por semilla: {camp['styles_in_priority_campaign_per_seed']} "
              f"de {camp['attack_styles']}")  # fmt: skip
        print(f"  estilos no detectados en ninguna campaña: {camp['styles_missed_entirely'] or 'ninguno'}")
        print(f"  campañas falsas (cola por validar) por semilla: {camp['false_campaigns_per_seed']}")
    print(f"\nReporte: {path}")
    for line in report["limitations"]:
        print(f"  · {line}")
    return EXIT_OK


def _num(x: float | None) -> str:
    return "—" if x is None else f"{x:.3f}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="idor-ir", description="Investigación de incidente IDOR")
    sub = parser.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="Validar, hashear y perfilar un dataset")
    ingest.add_argument("--file", required=True, help="Ruta al CSV de logs")
    _add_run_options(ingest)
    ingest.set_defaults(func=cmd_ingest)

    analyze = sub.add_parser("analyze", help="Ingesta + métricas + detección IDOR + risk scoring")
    analyze.add_argument("--file", required=True, help="Ruta al CSV de logs")
    analyze.add_argument(
        "--ownership",
        help="CSV opcional de la aplicación (objeto → titular) para CORROBORAR el IDOR: "
        "columnas <object_param>, [<scope_param>], owner",
    )
    _add_run_options(analyze)
    analyze.set_defaults(func=cmd_analyze)

    agents = sub.add_parser("agents", help="Ejecutar los 3 agentes sobre un run analizado")
    agents.add_argument("--run", required=True, help="ID del run (carpeta en output/)")
    agents.add_argument(
        "--approve",
        choices=["interactive", "all", "none"],
        default="interactive",
        help="Intervención humana simulada: interactiva, aprobar todo o rechazar todo",
    )
    agents.add_argument("--no-llm", action="store_true", help="Forzar lógica determinista (sin Ollama)")
    agents.set_defaults(func=cmd_agents)

    check = sub.add_parser("llm-check", help="Diagnosticar conexión con Ollama y aceptación de los esquemas")
    check.set_defaults(func=cmd_llm_check)

    ev = sub.add_parser("eval", help="Evaluar el modelo local con el banco de preguntas del run y comparar modelos")
    ev.add_argument("--run", required=True, help="ID del run (carpeta en output/)")
    ev.add_argument("--models", help="Modelos de Ollama separados por coma (por defecto IRP_OLLAMA_MODEL)")
    ev.add_argument("--limit", type=int, help="Solo las primeras N preguntas del chat (prueba rápida)")
    ev.add_argument("--no-chat", action="store_true", help="Evaluar solo los agentes")
    ev.add_argument("--no-agents", action="store_true", help="Evaluar solo el chat")
    ev.set_defaults(func=cmd_eval)

    enrich = sub.add_parser("enrich", help="Reputación de IPs del Top 20 vía el servidor MCP ti-gateway")
    enrich.add_argument("--run", required=True, help="ID del run (carpeta en output/)")
    enrich.add_argument(
        "--sources", help="IDs separados por coma (p. ej. virustotal,abuseipdb); por defecto, todas con clave"
    )
    enrich.add_argument("--yes", action="store_true", help="Confirmar el envío sin preguntar")
    enrich.set_defaults(func=cmd_enrich)

    serve = sub.add_parser("serve", help="Interfaz web")
    serve.add_argument("--host", default="127.0.0.1", help="Interfaz de escucha (por defecto solo localhost)")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--ssl-certfile", help="Certificado TLS (PEM) para servir por HTTPS")
    serve.add_argument("--ssl-keyfile", help="Clave privada TLS (PEM)")
    serve.set_defaults(func=cmd_serve)

    verify = sub.add_parser("verify", help="Verificar integridad de un run")
    verify.add_argument("--run", required=True, help="ID del run (carpeta en output/)")
    verify.add_argument("--file", help="Ruta al archivo original para re-verificar su hash")
    verify.set_defaults(func=cmd_verify)

    val = sub.add_parser("validate-detector", help="Precisión/recall/FP del detector en un banco sintético etiquetado")
    val.add_argument("--seeds", type=int, default=3, help="Repeticiones con semillas distintas (por defecto 3)")
    val.add_argument("--users", type=int, default=400, help="Usuarios normales por ventana (por defecto 400)")
    val.add_argument("--target-fpr", type=float, default=0.01, help="FPR objetivo para calibrar el umbral")
    val.add_argument("--no-campaigns", action="store_true", help="No ejecutar la tubería completa (más rápido)")
    val.set_defaults(func=cmd_validate_detector)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    configure_logging(settings.log_level)
    from idor_ir.agents.providers import configure_egress
    from idor_ir.config import export_env_passthrough

    export_env_passthrough()  # TI_ALLOWED_HOSTS del .env (anti-SSRF de TI)
    configure_egress(settings)  # lista blanca de salida de los clientes LLM (anti-SSRF)
    try:
        return int(args.func(args, settings))
    except (InputError, SchemaError, AnalysisError) as exc:
        # Errores de entrada: mensaje controlado, sin traceback.
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_INPUT
    except Exception:
        # Errores inesperados: mensaje genérico al usuario + id de correlación; detalle en el log.
        error_id = uuid.uuid4().hex[:8]
        logger.exception("Error inesperado", extra={"error_id": error_id})
        print(f"Error inesperado (id {error_id}). Revise el log.", file=sys.stderr)
        return EXIT_ERROR
