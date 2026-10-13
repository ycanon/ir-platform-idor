"""Aplicación web FastAPI: la misma lógica que la CLI, expuesta como UI + API.

La web no reimplementa el análisis: llama a `pipeline.run_analysis`, `agents.service.run_agents` y
`pipeline.verify_run`. Lo propio de esta capa es la experiencia (pestañas, progreso en vivo, aprobación
humana con botones) y los controles de seguridad de una aplicación web.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import unquote

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field, ValidationError

from idor_ir import __version__
from idor_ir.config import RUN_PROFILE_FIELDS, Settings, get_settings
from idor_ir.forensics.custody_intake import (
    CustodyIntake,
    build_record,
    is_read_only,
    make_read_only,
    sidecar_path,
    write_sidecar,
)
from idor_ir.forensics.integrity import CustodyLog, IntegrityManifest
from idor_ir.ingestion import SchemaError, validate_header
from idor_ir.logging_setup import configure_logging
from idor_ir.pipeline import run_analysis, verify_run
from idor_ir.web import observability as obs
from idor_ir.web.jobs import Job, JobManager
from idor_ir.web.llm_runtime import LLMRuntime
from idor_ir.web.security import (
    CSRF_COOKIE,
    ROLE_ANALYST,
    ROLE_APPROVER,
    ROLE_SINGLE,
    SESSION_COOKIE,
    AuthMiddleware,
    Principal,
    SecurityHeadersMiddleware,
    SessionSigner,
    clean_user,
    is_https,
    new_csrf_token,
    principal_of,
    require_approver,
    require_csrf,
    set_cookie,
)
from idor_ir.web.ti_runtime import TIRuntime

HERE = Path(__file__).parent
RUN_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{6}$")
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_-]")
# Artefactos descargables desde la web. Nunca: sensitive/token_map.json ni el Parquet.
DOWNLOADS = {
    "evidence.json": "application/json",
    "iocs.csv": "text/csv",
    "metrics.json": "application/json",
    "detection.json": "application/json",
    "manifest.json": "application/json",
    "profile.json": "application/json",
    "custody_intake.json": "application/json",
    "agents/agents_report.json": "application/json",
    "agents/playbook.md": "text/markdown",
    "agents/decision_log.jsonl": "application/x-ndjson",
    "agents/chats/triage.jsonl": "application/x-ndjson",
    "agents/chats/forensic.jsonl": "application/x-ndjson",
    "agents/chats/response.jsonl": "application/x-ndjson",
    "enrichment/ti_enrichment.json": "application/json",
}
# Artefactos dry-run de las acciones de respuesta (agents/actions/A1_rate_limit.txt…): patrón cerrado.
ACTION_ARTIFACT_RE = re.compile(r"^agents/actions/A\d{1,2}_[a-z_]{2,40}\.txt$")
MAX_CUSTODY_HEADER = 8192


def parse_custody_header(raw: str) -> CustodyIntake:
    """Acta de cadena de custodia enviada como JSON codificado en URL en `X-Custody-Metadata`."""
    if not raw:
        raise HTTPException(400, "Diligencie los datos de cadena de custodia antes de cargar el archivo")
    if len(raw) > MAX_CUSTODY_HEADER:
        raise HTTPException(400, "Los datos de cadena de custodia exceden el tamaño permitido")
    try:
        data = json.loads(unquote(raw))
        if not isinstance(data, dict):
            raise ValueError
        return CustodyIntake.model_validate(data)
    except ValidationError as exc:
        fields = ", ".join(sorted({str(e["loc"][0]) for e in exc.errors() if e.get("loc")}))
        raise HTTPException(400, f"Cadena de custodia: revise los campos {fields}") from None
    except ValueError:
        raise HTTPException(400, "Cadena de custodia: formato inválido") from None


class StartAnalysis(BaseModel):
    dataset: str = Field(min_length=1, max_length=200)
    # Perfil del incidente y fecha de detección de ESTA ejecución (opcionales; vacío = valor configurado).
    # Validación final en Settings.for_run / IncidentProfile (patrones estrictos).
    detection_date: str | None = Field(default=None, max_length=40)
    # auto = el perfil se deduce del dataset (los campos de abajo se ignoran); manual = se usan los campos enviados.
    profile_mode: Literal["auto", "manual"] = "auto"
    target_endpoint: str | None = Field(default=None, max_length=200)
    object_param: str | None = Field(default=None, max_length=40)
    scope_param: str | None = Field(default=None, max_length=40)
    token_param: str | None = Field(default=None, max_length=40)
    object_label: str | None = Field(default=None, max_length=30)
    object_label_plural: str | None = Field(default=None, max_length=30)
    scope_label: str | None = Field(default=None, max_length=30)
    # Fuente de corroboración (CSV de ownership objeto → titular) dentro de la misma lista blanca de data/.
    ownership: str | None = Field(default=None, max_length=200)


class StartEvaluation(BaseModel):
    # Modelos de Ollama (red local) a comparar con el banco de preguntas del run [mejora O13, puntos 10-11].
    models: list[Annotated[str, Field(max_length=120)]] = Field(min_length=1, max_length=4)
    chat: bool = True
    agents: bool = True
    limit: int | None = Field(default=None, ge=1, le=30)


EVAL_FILE_RE = re.compile(r"^\d{8}T\d{6}_[A-Za-z0-9._-]{1,60}\.(json|md)$")


class StartAgents(BaseModel):
    use_llm: bool = True
    # Consentimiento explícito del analista cuando el proveedor activo está fuera de la red local.
    cloud_consent: bool = False


class ChatMessage(BaseModel):
    agent: str = Field(pattern=r"^(triage|forensic|response)$")
    message: str = Field(min_length=1, max_length=2000)
    cloud_consent: bool = False


class LLMUpdate(BaseModel):
    provider: str = Field(min_length=1, max_length=40)
    base_url: str | None = Field(default=None, max_length=300)
    model: str | None = Field(default=None, max_length=120)
    # str (no SecretStr) solo en tránsito: se valida y se envuelve en SecretStr en LLMRuntime.update.
    # Los errores de validación nunca devuelven el valor recibido (ver manejador más abajo).
    api_key: str | None = Field(default=None, max_length=512, repr=False)
    clear_key: bool = False
    activate: bool = False


class ProviderRef(BaseModel):
    provider: str = Field(min_length=1, max_length=40)
    model: str | None = Field(default=None, max_length=120)  # para probar un modelo distinto (conversación)


class ChatLLMUpdate(BaseModel):
    provider: str | None = Field(default=None, max_length=40)  # vacío/None = el mismo de los agentes
    model: str | None = Field(default=None, max_length=120)  # vacío = el modelo configurado en ese proveedor


SourceId = Annotated[str, Field(pattern=r"^[a-z0-9]{2,30}$")]


class TIUpdate(BaseModel):
    # Claves en tránsito (str): se validan y se guardan como SecretStr en TIRuntime; el 422 no las devuelve.
    keys: dict[SourceId, Annotated[str, Field(max_length=512)]] = Field(default_factory=dict, max_length=20, repr=False)
    clear: list[SourceId] = Field(default_factory=list, max_length=20)
    per_minute: dict[SourceId, Annotated[int, Field(ge=1, le=10_000)]] = Field(default_factory=dict, max_length=20)
    quota: dict[SourceId, Annotated[int, Field(ge=0, le=10_000_000)]] = Field(default_factory=dict, max_length=20)
    # URL de fuentes autoalojadas (MISP). "" = olvidarla. Validada en TIRuntime (https o http a IP privada).
    urls: dict[SourceId, Annotated[str, Field(max_length=300)]] = Field(default_factory=dict, max_length=20)
    # Certificado PEM de la instancia o de su CA (no es secreto). "" = quitarlo.
    ca_pems: dict[SourceId, Annotated[str, Field(max_length=30_000)]] = Field(default_factory=dict, max_length=5)
    # true = NO verificar el certificado TLS (solo fuentes autoalojadas con URL interna; queda en la custodia).
    tls_insecure: dict[SourceId, bool] = Field(default_factory=dict, max_length=5)


class TISource(BaseModel):
    source: SourceId


class StartEnrichment(BaseModel):
    sources: list[SourceId] = Field(min_length=1, max_length=20)
    # Algunas fuentes (VirusTotal) publican lo consultado: confirmación explícita del analista, validada aquí.
    consent: bool = False


class Approvals(BaseModel):
    decisions: dict[str, str] = Field(default_factory=dict, max_length=20)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    token = settings.access_token.get_secret_value() if settings.access_token else None
    approver = settings.approver_token.get_secret_value() if settings.approver_token else None
    if token and approver and hmac.compare_digest(token.encode(), approver.encode()):
        raise ValueError("IRP_APPROVER_TOKEN debe ser distinto de IRP_ACCESS_TOKEN")
    signer = SessionSigner(settings.session_hours) if (token or approver) else None
    from idor_ir.agents.providers import configure_egress
    from idor_ir.config import export_env_passthrough

    export_env_passthrough()  # TI_ALLOWED_HOSTS del .env (anti-SSRF de TI)
    configure_egress(settings)  # lista blanca de salida de los clientes LLM (anti-SSRF)

    # Swagger UI/ReDoc desactivados: cargan scripts de un CDN externo con JS inline (incompatible con la CSP).
    # El esquema queda disponible en /openapi.json, detrás del mismo control de acceso.
    app = FastAPI(title="IR Platform — IDOR", version=__version__, docs_url=None, redoc_url=None)
    metrics_token = settings.metrics_token.get_secret_value() if settings.metrics_token else None
    app.add_middleware(AuthMiddleware, signer=signer, metrics_token=metrics_token)
    app.add_middleware(SecurityHeadersMiddleware)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")  # autoescape activado para .html
    jobs = JobManager()
    data_dir = settings.data_dir.resolve()
    output_dir = settings.output_dir.resolve()
    custody = CustodyLog(settings.output_dir / "custody_log.jsonl")  # quién inicia sesión, aprueba o autoriza

    @app.middleware("http")
    async def count_requests(request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        route = request.scope.get("route")
        obs.HTTP_REQUESTS.labels(getattr(route, "path", "otra"), str(response.status_code)).inc()
        return response

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Mensaje genérico + id de correlación; el detalle queda en el log del servidor.
        error_id = uuid.uuid4().hex[:8]
        import logging

        logging.getLogger("idor_ir.web").exception("Error no controlado", extra={"error_id": error_id})
        return JSONResponse({"detail": f"Error interno (id {error_id})"}, status_code=500)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError) -> JSONResponse:
        # El manejador por defecto de FastAPI devuelve el valor recibido ('input'): podría ser una API key.
        errors = [
            {"loc": list(e.get("loc", [])), "msg": e.get("msg", ""), "type": e.get("type", "")} for e in exc.errors()
        ]
        return JSONResponse({"detail": errors[:5]}, status_code=422)

    llm_runtime = LLMRuntime(settings)
    ti_runtime = TIRuntime(settings)

    # ------------------------------------------------------------------ helpers
    def datasets() -> dict[str, Path]:
        """Lista blanca de datasets: solo CSV dentro de data/ y data/uploads/ (no rutas arbitrarias)."""
        found: dict[str, Path] = {}
        for folder, prefix in ((data_dir, ""), (data_dir / "uploads", "uploads/")):
            if folder.is_dir():
                for p in sorted(folder.glob("*.csv")):
                    if p.is_file():
                        found[prefix + p.name] = p
        return found

    def run_dir_of(run_id: str) -> Path:
        if not RUN_ID_RE.fullmatch(run_id):
            raise HTTPException(404, "Run inexistente")
        path = (output_dir / run_id).resolve()
        if not path.is_relative_to(output_dir) or not path.is_dir():
            raise HTTPException(404, "Run inexistente")
        return path

    def read_json(path: Path) -> Any:
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None

    def read_jsonl(path: Path) -> list[Any]:
        if not path.is_file():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    # ------------------------------------------------------------------ páginas
    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> Response:
        csrf = request.cookies.get(CSRF_COOKIE) or new_csrf_token()
        who = principal_of(request)
        response = templates.TemplateResponse(
            request,
            "index.html",
            {"csrf_token": csrf, "version": __version__, "auth": signer is not None, "who": who},
        )
        set_cookie(response, CSRF_COOKIE, csrf, http_only=False, secure=secure_cookie(request))
        return response

    def secure_cookie(request: Request) -> bool:
        return bool(settings.cookie_secure) or is_https(request)

    def role_for(candidate: str) -> str | None:
        """Rol del token presentado (comparación en tiempo constante contra ambos)."""
        is_approver = bool(approver) and hmac.compare_digest(candidate.encode(), (approver or "").encode())
        is_analyst = bool(token) and hmac.compare_digest(candidate.encode(), (token or "").encode())
        if is_approver:
            return ROLE_APPROVER
        if is_analyst:
            return ROLE_ANALYST if approver else ROLE_SINGLE
        return None

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> Response:
        if signer is None:
            return Response(status_code=303, headers={"Location": "/"})
        return templates.TemplateResponse(request, "login.html", {"error": None, "roles": bool(approver)})

    @app.post("/login", response_class=HTMLResponse)
    async def login(
        request: Request, access_token: str = Form(max_length=256), user: str = Form(default="", max_length=120)
    ) -> Response:
        if signer is None:
            return Response(status_code=303, headers={"Location": "/"})
        name = clean_user(user)
        role = role_for(access_token)
        if role is None or name is None:
            await asyncio.sleep(1)  # frena la fuerza bruta
            error = "Token inválido" if role is None else "Indique su nombre o usuario (2-60 caracteres)"
            return templates.TemplateResponse(
                request, "login.html", {"error": error, "roles": bool(approver)}, status_code=401
            )
        principal = Principal(name, role)
        custody.append("session_started", principal.audit())
        response = Response(status_code=303, headers={"Location": "/"})
        set_cookie(
            response, SESSION_COOKIE, signer.issue(principal), http_only=True, secure=secure_cookie(request),
            max_age=settings.session_hours * 3600,
        )  # fmt: skip
        return response

    @app.post("/logout", dependencies=[Depends(require_csrf)])
    async def logout() -> Response:
        response = Response(status_code=204)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    # ------------------------------------------------------------------ API: estado general
    @app.get("/api/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/config")
    async def config(request: Request) -> dict[str, Any]:
        # Solo valores no sensibles.
        return {
            "version": __version__,
            "target_endpoint": settings.target_endpoint,
            "timestamp_format": settings.timestamp_format,
            "detection_date": settings.detection_date.isoformat() if settings.detection_date else None,
            # Perfil del incidente: se detecta del dataset (auto) o se usan estos valores (fixed / respaldo).
            "profile_mode": settings.profile_mode,
            "profile": {k: getattr(settings, k) for k in RUN_PROFILE_FIELDS},
            "max_upload_mb": settings.max_upload_mb,
            "auth_enabled": signer is not None,
            "separate_approver": bool(approver),
            "user": principal_of(request).user,
            "role": principal_of(request).role,
            "can_approve": principal_of(request).can_approve,
        }

    # ------------------------------------------------------------------ API: proveedor LLM (Configuración)
    @app.get("/api/llm")
    async def llm_state() -> dict[str, Any]:
        return llm_runtime.public()

    @app.post("/api/llm/config", dependencies=[Depends(require_csrf), Depends(require_approver)])
    async def llm_update(body: LLMUpdate) -> dict[str, Any]:
        try:
            llm_runtime.update(
                body.provider,
                base_url=body.base_url,
                model=body.model,
                api_key=body.api_key,
                clear_key=body.clear_key,
                activate=body.activate,
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return llm_runtime.public()

    def provider_config(provider: str) -> Any:
        try:
            return llm_runtime.get(provider)
        except KeyError as exc:
            raise HTTPException(404, "Proveedor desconocido") from exc

    @app.post("/api/llm/chat", dependencies=[Depends(require_csrf), Depends(require_approver)])
    async def llm_chat_update(body: ChatLLMUpdate) -> dict[str, Any]:
        """Proveedor y modelo de la conversación con los agentes (iguales o distintos a los de los agentes)."""
        try:
            llm_runtime.set_chat(body.provider, body.model)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return llm_runtime.public()

    @app.post("/api/llm/models", dependencies=[Depends(require_csrf)])
    async def llm_models(body: ProviderRef) -> dict[str, Any]:
        from idor_ir.agents.llm import LLMError
        from idor_ir.agents.providers import list_models

        cfg = provider_config(body.provider)
        try:
            models = await asyncio.to_thread(list_models, cfg)
        except LLMError as exc:
            raise HTTPException(502, str(exc)) from exc
        return {"provider": body.provider, "models": models}

    @app.post("/api/llm/test", dependencies=[Depends(require_csrf)])
    async def llm_test(body: ProviderRef) -> dict[str, Any]:
        """Prueba real: Ollama → servidor + gramática de los 3 esquemas; nube → generación mínima estructurada."""
        from idor_ir.agents.llm import LLMError, OllamaLLM
        from idor_ir.agents.providers import Ping, build_client
        from idor_ir.agents.schemas import ForensicDraft, ResponseDraft, TextFix, TriageDraft
        from idor_ir.web.llm_runtime import MODEL_RE

        cfg = provider_config(body.provider)
        if body.model:
            if not MODEL_RE.fullmatch(body.model.strip()):
                raise HTTPException(400, "Nombre de modelo inválido")
            cfg = cfg.model_copy(update={"model": body.model.strip()})
        try:
            client = build_client(cfg)
        except LLMError as exc:
            return {"ok": False, "checks": [{"check": str(exc), "ok": False}]}
        started = time.perf_counter()
        if isinstance(client, OllamaLLM):
            if not await asyncio.to_thread(client.health):
                return {"ok": False, "checks": [{"check": f"Servidor no accesible en {cfg.base_url}", "ok": False}]}
            formats = await asyncio.to_thread(
                client.check_formats, [TriageDraft, ForensicDraft, ResponseDraft, TextFix]
            )
            checks = [{"check": "Servidor accesible", "ok": True}] + [
                {"check": f"Esquema {name}: {result}", "ok": result == "aceptado"} for name, result in formats.items()
            ]
        else:
            try:
                await asyncio.to_thread(
                    client.generate,
                    "Eres una prueba de conectividad.",
                    'Responde exactamente con {"status": "ok"}.',
                    Ping,
                    64,
                )
                checks = [{"check": f"Clave, modelo y salida estructurada OK ({cfg.model})", "ok": True}]
            except LLMError as exc:
                checks = [{"check": str(exc), "ok": False}]
        return {
            "ok": all(c["ok"] for c in checks),
            "checks": checks,
            "seconds": round(time.perf_counter() - started, 1),
        }

    @app.get("/api/llm/status")
    async def llm_status() -> dict[str, Any]:
        """Estado del proveedor ACTIVO para la barra superior. Solo hace red con Ollama (llamada gratuita)."""
        from idor_ir.agents.llm import OllamaLLM

        cfg = llm_runtime.active()
        spec = cfg.spec
        ready = bool(cfg.model) and (not spec.needs_key or cfg.api_key is not None)
        reachable = None
        if spec.kind == "ollama" and ready:
            reachable = await asyncio.to_thread(OllamaLLM(cfg.base_url, cfg.model).health)
        return {
            "provider": spec.id,
            "label": spec.label,
            "model": cfg.model,
            "ready": ready,
            "reachable": reachable,
            "off_lan": cfg.off_lan(),
        }

    # ------------------------------------------------------------------ API: inteligencia de amenazas (MCP)
    # Toda consulta a fuentes externas pasa por el servidor MCP ti-gateway (subproceso stdio).
    async def ti_public() -> dict[str, Any]:
        from idor_ir.enrichment.gateway_client import GatewayError

        try:
            await asyncio.to_thread(ti_runtime.refresh_catalog)  # catálogo + consumo actual desde el gateway
        except GatewayError as exc:
            raise HTTPException(502, str(exc)) from exc
        return ti_runtime.public()

    @app.get("/api/ti")
    async def ti_state() -> dict[str, Any]:
        return await ti_public()

    @app.post("/api/ti/config", dependencies=[Depends(require_csrf), Depends(require_approver)])
    async def ti_update(body: TIUpdate) -> dict[str, Any]:
        try:
            ti_runtime.update(
                keys=body.keys,
                clear=body.clear,
                per_minute=body.per_minute,
                quota=body.quota,
                urls=body.urls,
                ca_pems=body.ca_pems,
                tls_insecure=body.tls_insecure,
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        if body.tls_insecure:  # excepción de seguridad: queda en la cadena de custodia
            CustodyLog(settings.output_dir / "custody_log.jsonl").append(
                "ti_tls_verification_changed",
                {"sources": {s: ("sin verificar" if on else "verificado") for s, on in body.tls_insecure.items()}},
            )
        return await ti_public()

    @app.post("/api/ti/test", dependencies=[Depends(require_csrf)])
    async def ti_test(body: TISource) -> dict[str, Any]:
        from idor_ir.enrichment.gateway_client import GatewayError, GatewaySession, run_with_gateway

        if body.source not in ti_runtime.known_sources():
            raise HTTPException(404, "Fuente desconocida")

        async def check(gw: GatewaySession) -> dict[str, Any]:
            return await gw.check_source(body.source)

        try:  # el gateway recibe SOLO la clave de la fuente que se valida
            return await asyncio.to_thread(run_with_gateway, ti_runtime.launch([body.source]), check)
        except GatewayError as exc:
            return {"source": body.source, "ok": False, "detail": str(exc)}

    @app.post("/api/runs/{run_id}/enrich", dependencies=[Depends(require_csrf)])
    async def start_enrichment(
        run_id: str, body: StartEnrichment, who: Annotated[Principal, Depends(require_approver)]
    ) -> dict[str, Any]:
        """Envía IPs a terceros: decisión del rol aprobador, con consentimiento auditado (plataforma y gateway)."""
        from idor_ir.enrichment.ti import enrich_run

        d = run_dir_of(run_id)
        if not (d / "evidence.json").is_file():
            raise HTTPException(400, "El run no tiene evidencia; ejecute el análisis completo")
        if not body.consent:
            raise HTTPException(400, "Confirme el envío de las IPs públicas del Top 20 a las fuentes seleccionadas")
        sources = list(dict.fromkeys(body.sources))
        if not ti_runtime.known_sources():
            await ti_public()
        unknown = [s for s in sources if s not in ti_runtime.known_sources()]
        if unknown:
            raise HTTPException(400, f"Fuentes desconocidas: {', '.join(unknown)}")
        missing = [s for s in sources if not ti_runtime.configured(s)]
        if missing:
            raise HTTPException(400, f"Falta la API key o la URL de: {', '.join(missing)}")
        consent = {
            "confirmed": True,
            "at": datetime.now(UTC).isoformat(timespec="seconds"),
            "sources": sources,
            "note": "Solo IPs públicas del Top 20; VirusTotal agrega los indicadores consultados a su dataset público",
            "by": who.audit(),
        }
        custody.append("ti_enrichment_authorized", {"run_id": run_id, "sources": sources, "by": who.audit()})
        launch = ti_runtime.launch(sources)  # solo las claves de las fuentes elegidas

        def work(job: Job) -> dict[str, Any]:
            def on_progress(kind: str, data: dict[str, Any]) -> None:
                if kind == "lookup":
                    msg = f"Consultando {data['ip']} ({data['n']}/{data['total']})"
                else:
                    msg = f"{data['ip']}: {data['verdict']} ({data['n']}/{data['total']})"
                job.emit(kind, msg, data)

            report = enrich_run(d, settings, launch, sources, consent, on_progress)
            return {"run_id": run_id, "summary": report["summary"], "seconds": report["stats"]["seconds"]}

        try:
            job = jobs.start("enrich", work)
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"job_id": job.id}

    @app.get("/metrics")
    async def metrics() -> Response:
        return Response(generate_latest(obs.REGISTRY), media_type=CONTENT_TYPE_LATEST)

    # ------------------------------------------------------------------ API: datasets
    @app.get("/api/datasets")
    async def list_datasets() -> list[dict[str, Any]]:
        return [
            {
                "name": name,
                "size_bytes": p.stat().st_size,
                "modified": datetime.fromtimestamp(p.stat().st_mtime, tz=UTC).isoformat(),
                "custody": sidecar_path(p).is_file(),
                "read_only": is_read_only(p),
            }
            for name, p in datasets().items()
        ]

    @app.post("/api/datasets/upload", dependencies=[Depends(require_csrf)])
    async def upload(request: Request) -> dict[str, Any]:
        """Carga por streaming (cuerpo crudo) con lista blanca de extensión, límite de tamaño, nombre
        generado en el servidor y validación del encabezado (OWASP File Upload CS). Exige el acta de cadena
        de custodia, calcula el SHA-256 mientras recibe, deja el archivo en solo lectura y registra la
        recepción en la cadena de custodia."""
        original = request.headers.get("x-filename", "")
        if not original.lower().endswith(".csv"):
            obs.UPLOADS.labels("rejected").inc()
            raise HTTPException(400, "Solo se aceptan archivos .csv")
        try:
            intake = parse_custody_header(request.headers.get("x-custody-metadata", ""))
        except HTTPException:
            obs.UPLOADS.labels("rejected").inc()
            raise
        stem = SAFE_NAME_RE.sub("_", Path(unquote(original)).stem)[:40] or "dataset"
        target_dir = data_dir / "uploads"
        target_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(tz=UTC)
        suffix = uuid.uuid4().hex[:6]
        target = target_dir / f"{stamp:%Y%m%dT%H%M%S}_{stem}_{suffix}.csv"
        limit = settings.max_upload_mb * 1024 * 1024
        written = 0
        digest = hashlib.sha256()
        try:
            with target.open("xb") as handle:
                async for chunk in request.stream():
                    written += len(chunk)
                    if written > limit:
                        raise HTTPException(413, f"Archivo mayor que el límite ({settings.max_upload_mb} MB)")
                    digest.update(chunk)
                    handle.write(chunk)
            await asyncio.to_thread(validate_header, target, settings.csv_separator)
            sha256 = digest.hexdigest()
            if intake.source_sha256 and intake.source_sha256 != sha256:
                raise HTTPException(
                    400, "El SHA-256 del archivo recibido no coincide con el informado en origen; carga rechazada"
                )
        except SchemaError as exc:
            target.unlink(missing_ok=True)
            obs.UPLOADS.labels("rejected").inc()
            raise HTTPException(400, str(exc)) from exc
        except BaseException:
            target.unlink(missing_ok=True)
            obs.UPLOADS.labels("rejected").inc()
            raise
        read_only = await asyncio.to_thread(make_read_only, target)
        evidence_id = intake.evidence_id or f"EV-{stamp:%Y%m%dT%H%M%S}-{suffix}"
        record = build_record(
            intake, original_filename=unquote(original), stored_name=target.name, size_bytes=written,
            sha256=sha256, tool=f"idor-ir {__version__}", evidence_id=evidence_id, read_only=read_only,
        )  # fmt: skip
        await asyncio.to_thread(write_sidecar, target, record)
        CustodyLog(output_dir / "custody_log.jsonl").append(
            "evidence_received",
            {
                "evidence_id": evidence_id, "case_id": intake.case_id or None, "file": target.name,
                "sha256": sha256, "size_bytes": written, "collected_by": intake.collected_by,
                "source_system": intake.source_system, "source_hash_match": record["automatic"]["source_hash_match"],
                "read_only": read_only,
            },
        )  # fmt: skip
        obs.UPLOADS.labels("accepted").inc()
        return {
            "name": f"uploads/{target.name}", "size_bytes": written, "sha256": sha256,
            "evidence_id": evidence_id, "read_only": read_only,
            "source_hash_match": record["automatic"]["source_hash_match"],
        }  # fmt: skip

    # ------------------------------------------------------------------ API: runs
    @app.get("/api/runs")
    async def list_runs() -> list[dict[str, Any]]:
        runs = []
        if output_dir.is_dir():
            for d in sorted(output_dir.iterdir(), reverse=True):
                if d.is_dir() and RUN_ID_RE.fullmatch(d.name) and (d / "manifest.json").is_file():
                    m = IntegrityManifest.model_validate_json((d / "manifest.json").read_text(encoding="utf-8"))
                    runs.append(
                        {
                            "run_id": d.name,
                            "created": m.created_utc,
                            "source": m.source.name,
                            "sha256": m.source.sha256,
                            "size_bytes": m.source.size_bytes,
                            "has_evidence": (d / "evidence.json").is_file(),
                            "has_agents": (d / "agents" / "agents_report.json").is_file(),
                        }
                    )
        return runs

    @app.get("/api/runs/{run_id}")
    async def run_summary(run_id: str) -> dict[str, Any]:
        d = run_dir_of(run_id)
        detection = read_json(d / "detection.json")
        tables = (detection or {}).get("detectors", {}).get("idor", {}).get("tables", {})
        return {
            "run_id": run_id,
            "manifest": read_json(d / "manifest.json"),
            "profile": read_json(d / "profile.json"),
            "metrics": read_json(d / "metrics.json"),
            "detection": {
                k: {"levels": v["levels"], "total": v["total_actors"], "actors": v["actors"][:50]}
                for k, v in tables.items()
            },
            "evidence": read_json(d / "evidence.json"),
            "agents": read_json(d / "agents" / "agents_report.json"),
            "decision_log": read_jsonl(d / "agents" / "decision_log.jsonl"),
            "enrichment": read_json(d / "enrichment" / "ti_enrichment.json"),
            "custody_intake": read_json(d / "custody_intake.json"),
        }

    @app.get("/api/runs/{run_id}/download/{artifact:path}")
    async def download(run_id: str, artifact: str) -> FileResponse:
        if artifact in DOWNLOADS:
            media = DOWNLOADS[artifact]
        elif ACTION_ARTIFACT_RE.fullmatch(artifact):
            media = "text/plain; charset=utf-8"
        else:
            raise HTTPException(404, "Artefacto no disponible")
        d = run_dir_of(run_id)
        path = (d / artifact).resolve()
        if not path.is_relative_to(d) or not path.is_file():
            raise HTTPException(404, "Artefacto no disponible")
        return FileResponse(path, media_type=media, filename=f"{run_id}_{Path(artifact).name}")

    @app.post("/api/runs/{run_id}/verify", dependencies=[Depends(require_csrf)])
    async def verify(run_id: str) -> dict[str, Any]:
        d = run_dir_of(run_id)
        manifest = IntegrityManifest.model_validate_json((d / "manifest.json").read_text(encoding="utf-8"))
        source = next((p for p in datasets().values() if p.name == manifest.source.name), None)
        checks = await asyncio.to_thread(verify_run, d, output_dir, source)
        return {"ok": all(c["ok"] for c in checks), "checks": checks, "source_checked": source is not None}

    # ------------------------------------------------------------------ API: trabajos
    @app.post("/api/analyses", dependencies=[Depends(require_csrf)])
    async def start_analysis(body: StartAnalysis) -> dict[str, Any]:
        available = datasets()
        source = available.get(body.dataset)
        if source is None:
            raise HTTPException(404, "Dataset no encontrado")
        ownership: Path | None = None
        if body.ownership:
            ownership = available.get(body.ownership)
            if ownership is None:
                raise HTTPException(404, "Fuente de ownership no encontrada")
            if ownership == source:
                raise HTTPException(422, "La fuente de ownership no puede ser el mismo log analizado")
        try:
            fields = body.model_dump(exclude={"dataset", "profile_mode", "ownership"})
            if body.profile_mode == "auto":
                fields = {"detection_date": fields["detection_date"]}
            run_settings = settings.for_run(fields)
        except ValueError as exc:
            # Mensajes propios (no repiten el valor recibido).
            raise HTTPException(422, str(exc)) from exc

        def work(job: Job) -> dict[str, Any]:
            started = time.perf_counter()
            try:
                result = run_analysis(
                    source, run_settings, detect=True, on_progress=lambda s, m: job.emit(s, m), ownership=ownership
                )
            except Exception:
                obs.ANALYSES.labels("failed").inc()
                raise
            obs.ANALYSES.labels("ok").inc()
            obs.ANALYSIS_SECONDS.observe(time.perf_counter() - started)
            return {"run_id": result.run_id, "timings": result.timings}

        try:
            job = jobs.start("analysis", work)
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"job_id": job.id}

    # ------------------------------------------------------------------ API: conversación con los agentes
    def chat_agent(agent: str) -> str:
        from idor_ir.agents.chat import AGENTS

        if agent not in AGENTS:
            raise HTTPException(404, "Agente desconocido")
        return agent

    @app.get("/api/runs/{run_id}/chat/{agent}")
    async def chat_history(run_id: str, agent: str) -> dict[str, Any]:
        from idor_ir.agents.chat import AGENTS, load_records

        d = run_dir_of(run_id)
        agent = chat_agent(agent)
        return {
            "agent": agent,
            "label": AGENTS[agent]["label"],
            "suggestions": AGENTS[agent]["suggestions"],
            "has_agents_output": (d / "agents" / "agents_report.json").is_file(),
            "records": load_records(d, agent),
        }

    @app.post("/api/runs/{run_id}/chat/{agent}/new", dependencies=[Depends(require_csrf)])
    async def chat_new(run_id: str, agent: str) -> dict[str, Any]:
        from idor_ir.agents.chat import new_conversation

        d = run_dir_of(run_id)
        if not (d / "evidence.json").is_file():
            raise HTTPException(400, "El run no tiene evidencia")
        await asyncio.to_thread(new_conversation, d, settings, chat_agent(agent))
        return {"ok": True}

    @app.post("/api/runs/{run_id}/chat", dependencies=[Depends(require_csrf)])
    async def chat_ask(run_id: str, body: ChatMessage, request: Request) -> dict[str, Any]:
        from idor_ir.agents import providers
        from idor_ir.agents.chat import ChatError, ask
        from idor_ir.agents.data_answers import is_data_question
        from idor_ir.agents.llm import LLMError

        d = run_dir_of(run_id)
        if not (d / "evidence.json").is_file():
            raise HTTPException(400, "El run no tiene evidencia; ejecute el análisis completo")
        cfg = llm_runtime.chat_config()  # proveedor/modelo de la conversación (pueden diferir de los agentes)
        # Preguntas de dato: se responden desde la evidencia, sin modelo ni salida de datos (punto 8).
        data_only = is_data_question(body.message)
        off_lan = cfg.off_lan() and not data_only
        if off_lan and not body.cloud_consent:
            raise HTTPException(
                400, f"{cfg.spec.label} está fuera de la red local: confirme el envío del contexto agregado"
            )
        who = principal_of(request)
        if off_lan and not who.can_approve:  # salida de datos fuera de la red: decisión del rol aprobador
            raise HTTPException(403, "Enviar contexto a un proveedor fuera de la red local requiere el rol aprobador")
        llm: Any = None
        try:
            llm = providers.build_client(cfg)
        except LLMError as exc:
            if not data_only:
                raise HTTPException(400, f"{exc}. Configure el proveedor en la pestaña Configuración") from exc
        meta = {
            "provider": cfg.provider,
            "off_lan": off_lan,
            "consent": body.cloud_consent if off_lan else None,
            "consent_by": who.audit() if off_lan else None,
        }

        def work(job: Job) -> dict[str, Any]:
            buffer: list[str] = []
            last = [time.monotonic()]

            def flush() -> None:
                if buffer:
                    job.emit("delta", "".join(buffer))
                    buffer.clear()
                last[0] = time.monotonic()

            def on_delta(text: str) -> None:  # agrupa fragmentos: menos eventos SSE
                buffer.append(text)
                if time.monotonic() - last[0] > 0.25:
                    flush()

            try:
                record = ask(d, settings, body.agent, body.message, llm, meta, on_delta)
            except (ChatError, LLMError) as exc:
                raise RuntimeError(str(exc)) from exc
            flush()
            obs.CHAT_TURNS.labels(body.agent, record.get("source", "modelo")).inc()
            obs.CHAT_SECONDS.observe(float(record.get("seconds") or 0))
            for issue in (record.get("review") or {}).get("issues", []):
                obs.REVIEW_ISSUES.labels(issue.get("kind", "otra")).inc()
            return record

        try:
            job = jobs.start("chat", work)
        except RuntimeError as exc:
            raise HTTPException(409, "El agente está respondiendo otra pregunta; espere a que termine") from exc
        return {"job_id": job.id}

    # ------------------------------------------------------------------ API: evaluación del modelo local (O13)
    @app.get("/api/runs/{run_id}/evaluations")
    async def evaluations(run_id: str) -> dict[str, Any]:
        from idor_ir.agents.evaluation import list_reports, summary_row

        reports = list_reports(run_dir_of(run_id))
        return {
            "reports": [summary_row(r) | {"file": r["file"]} for r in reports],
            "latest": reports[-1] if reports else None,
        }

    @app.get("/api/runs/{run_id}/evaluations/{name}")
    async def evaluation_file(run_id: str, name: str) -> FileResponse:
        if not EVAL_FILE_RE.fullmatch(name):
            raise HTTPException(404, "Reporte no disponible")
        d = run_dir_of(run_id)
        path = (d / "evaluation" / name).resolve()
        if not path.is_relative_to(d) or not path.is_file():
            raise HTTPException(404, "Reporte no disponible")
        media = "application/json" if name.endswith(".json") else "text/markdown"
        return FileResponse(path, media_type=media, filename=f"{run_id}_{name}")

    @app.post("/api/runs/{run_id}/evaluations", dependencies=[Depends(require_csrf)])
    async def start_evaluation(run_id: str, body: StartEvaluation) -> dict[str, Any]:
        from idor_ir.agents.llm import OllamaLLM
        from idor_ir.web.llm_runtime import MODEL_RE

        d = run_dir_of(run_id)
        if not (d / "evidence.json").is_file():
            raise HTTPException(400, "El run no tiene evidencia; ejecute el análisis completo")
        models = [m.strip() for m in body.models if m.strip()]
        if not models or any(not MODEL_RE.fullmatch(m) for m in models):
            raise HTTPException(400, "Nombre de modelo inválido")
        if not (body.chat or body.agents):
            raise HTTPException(400, "Elija evaluar el chat, los agentes o ambos")
        base_url = llm_runtime.get("ollama").base_url  # siempre el Ollama local: no sale contexto de la LAN

        def work(job: Job) -> dict[str, Any]:
            from idor_ir.agents.evaluation import evaluate, summary_row

            rows = []
            for model in models:
                job.emit("model", f"Evaluando {model}")
                report = evaluate(
                    d, settings, OllamaLLM(base_url, model), chat_eval=body.chat, agents_eval=body.agents,
                    limit=body.limit, progress=lambda kind, msg: job.emit(kind, msg),
                )  # fmt: skip
                rows.append(summary_row(report))
            return {"reports": rows}

        try:
            job = jobs.start("evaluation", work)
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"job_id": job.id}

    @app.post("/api/runs/{run_id}/agents", dependencies=[Depends(require_csrf)])
    async def start_agents(run_id: str, body: StartAgents, request: Request) -> dict[str, Any]:
        from idor_ir.agents.llm import LLMError
        from idor_ir.agents.providers import build_client

        d = run_dir_of(run_id)
        if not (d / "evidence.json").is_file():
            raise HTTPException(400, "El run no tiene evidencia; ejecute el análisis completo")
        cfg = llm_runtime.active()  # copia: cambios posteriores en Configuración no afectan este trabajo
        off_lan = body.use_llm and cfg.off_lan()
        if off_lan and not body.cloud_consent:
            raise HTTPException(
                400, f"{cfg.spec.label} está fuera de la red local: confirme el envío del contexto agregado"
            )
        who = principal_of(request)
        if off_lan and not who.can_approve:  # salida de datos fuera de la red: decisión del rol aprobador
            raise HTTPException(403, "Enviar contexto a un proveedor fuera de la red local requiere el rol aprobador")
        llm_meta = {
            "provider": cfg.provider if body.use_llm else None,
            "model": cfg.model if body.use_llm else None,
            "off_lan": off_lan,
            "consent": body.cloud_consent if off_lan else None,
            "consent_at": datetime.now(UTC).isoformat(timespec="seconds") if off_lan else None,
            "consent_by": who.audit() if off_lan else None,
        }

        def work(job: Job) -> dict[str, Any]:
            from idor_ir.agents.service import run_agents

            llm = None
            if body.use_llm:
                try:
                    candidate = build_client(cfg)
                except LLMError as exc:
                    job.emit("info", f"{exc}: se usa la lógica determinista")
                else:
                    if candidate.health():
                        llm = candidate
                        hint = " (CPU: varios minutos)" if cfg.provider == "ollama" else ""
                        job.emit("info", f"Usando {candidate.name}{hint}")
                    else:
                        job.emit("info", f"{cfg.spec.label} no responde: se usa la lógica determinista")

            def on_event(node: str, data: dict[str, Any]) -> None:
                if node == "awaiting_approval":
                    return  # lo emite Job.wait_for_approval
                source = data.get("source", "code")
                obs.AGENT_NODES.labels(node, source).inc()
                if node == "human_review":
                    for decision in (data.get("approvals") or {}).values():
                        obs.APPROVALS.labels(decision).inc()
                job.emit(node, data.get("decision", node), data)

            started = time.perf_counter()
            meta = {**llm_meta, "used": llm is not None}
            report = run_agents(
                d, settings, llm, job.wait_for_approval, on_event=on_event, llm_meta=meta,
                started_by=who.audit(), decided_by=lambda: job.approver,
            )  # fmt: skip
            obs.AGENT_SECONDS.observe(time.perf_counter() - started)
            for agent in ("triage", "forensic", "response"):
                checks = (report.get(agent) or {}).get("checks") or {}
                for kind, key in (("corregidas", "corrections"), ("observaciones", "issues"),
                                  ("fijadas_por_codigo", "code_additions")):  # fmt: skip
                    obs.AGENT_CHECKS.labels(agent, kind).inc(len(checks.get(key) or []))
            return {"run_id": run_id, "llm": report["llm"], "seconds": report["agents_seconds"]}

        try:
            job = jobs.start("agents", work)
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"job_id": job.id}

    @app.get("/api/jobs/{job_id}")
    async def job_status(job_id: str) -> dict[str, Any]:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "Trabajo inexistente")
        return job.public()

    @app.post("/api/jobs/{job_id}/approvals", dependencies=[Depends(require_csrf)])
    async def approvals(
        job_id: str, body: Approvals, who: Annotated[Principal, Depends(require_approver)]
    ) -> dict[str, Any]:
        job = jobs.get(job_id)
        if job is None or job.status != "awaiting_approval":
            raise HTTPException(409, "El trabajo no espera aprobación")
        valid = {a["action_id"] for a in job.pending_actions}
        decisions = {k: v for k, v in body.decisions.items() if k in valid and v in {"approve", "reject"}}
        job.submit_approvals(decisions, who.audit())
        return {"accepted": decisions, "decided_by": who.audit()}

    @app.get("/api/jobs/{job_id}/events")
    async def job_events(job_id: str, request: Request) -> StreamingResponse:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "Trabajo inexistente")

        async def stream() -> AsyncIterator[str]:
            sent = 0
            while True:
                if await request.is_disconnected():
                    break
                pending = [e for e in job.events if e["seq"] >= sent]
                for event in pending:
                    sent = event["seq"] + 1
                    yield f"data: {json.dumps(event, ensure_ascii=False, default=str)}\n\n"
                if job.status in {"completed", "failed"} and not [e for e in job.events if e["seq"] >= sent]:
                    yield f"event: end\ndata: {json.dumps({'status': job.status})}\n\n"
                    break
                await asyncio.sleep(0.5)

        return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-store"})

    return app
