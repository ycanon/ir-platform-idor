"""Detección automática del perfil del incidente a partir del propio dataset.

Objetivo: que el analista NO tenga que saber de antemano qué endpoint ni qué parámetros revisar. Con los mismos
8 campos del log [Reto §2] se deduce:

- el **endpoint** objetivo: entre las rutas con parámetros, la que tiene un identificador de objeto numérico y
  donde una misma credencial (o IP) consulta más objetos distintos (la señal de un IDOR);
- el **parámetro del objeto**: valores numéricos y muchos distintos (p. ej. `invoice_id`, `order_id`);
- el **parámetro de la credencial**: nombre tipo token/auth/session/key o valores largos y opacos;
- el **parámetro de ámbito/tenant** (opcional): pocos valores distintos que se repiten (p. ej. `site_id`);
- cómo llamar a los objetos y al ámbito en los textos ("facturas", "pedidos", "sitio", "cliente"...).

Todo se calcula con Polars en modo streaming (una pasada para la estructura y, si hay varios candidatos, otra
para la señal IDOR); solo se materializan agregados. El resultado incluye la confianza y la evidencia usada, que
quedan en el manifiesto del run (trazabilidad: el analista puede ver por qué se eligió cada parámetro).

Límite conocido: el identificador debe viajar como parámetro de la query (`?id=...`). Si se detectan rutas con el
ID dentro de la ruta (`/invoices/123`) se informa en la evidencia de la detección.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

import polars as pl

from idor_ir.profile import LABEL_RE, PARAM_RE, IncidentProfile

# Segmentos numéricos / UUID / hex largos dentro de la ruta → {id} (agrupa /invoices/123 y /invoices/456).
_UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
# Sin lookahead (el motor regex de Polars no lo soporta): se captura el separador siguiente y se repone con ${2}.
_ID_SEGMENT = rf"/(\d+|{_UUID}|[0-9a-fA-F]{{24,}})(/|$)"
_ID_REPL = "/{id}${2}"


def _norm_path() -> pl.Expr:
    """Ruta sin query, con los segmentos de ID como {id} (dos pasadas: IDs consecutivos como /1/2)."""
    path = pl.col("http_uri").str.extract(r"^([^?#]*)", 1)
    return path.str.replace_all(_ID_SEGMENT, _ID_REPL).str.replace_all(_ID_SEGMENT, _ID_REPL)


TOKEN_HINT = re.compile(r"(token|auth|session|sess|sid|jwt|bearer|api_?key|apikey|access|key|credential)", re.I)
OBJECT_HINT = re.compile(r"(^id$|_id$|id$|^id_|number|num$|_no$|code$)", re.I)
SCOPE_HINT = re.compile(
    r"(site|tenant|org|organization|company|account|store|shop|region|country|branch|client|customer|merchant|"
    r"workspace|project|team|domain|market)",
    re.I,
)
MIN_PRESENCE = 0.3  # el parámetro debe aparecer en al menos el 30 % de las peticiones con query de esa ruta
MIN_OBJECT_DISTINCT = 20
MAX_CANDIDATES = 5

# Sustantivo (inglés o español) → (singular, plural) en español. Fallback: objeto/objetos.
_NOUNS: dict[str, tuple[str, str]] = {
    "invoice": ("factura", "facturas"), "factura": ("factura", "facturas"),
    "order": ("pedido", "pedidos"), "pedido": ("pedido", "pedidos"),
    "user": ("usuario", "usuarios"), "usuario": ("usuario", "usuarios"),
    "account": ("cuenta", "cuentas"), "cuenta": ("cuenta", "cuentas"),
    "document": ("documento", "documentos"), "documento": ("documento", "documentos"),
    "doc": ("documento", "documentos"),
    "payment": ("pago", "pagos"), "pago": ("pago", "pagos"),
    "customer": ("cliente", "clientes"), "client": ("cliente", "clientes"), "cliente": ("cliente", "clientes"),
    "transaction": ("transacción", "transacciones"), "transfer": ("transferencia", "transferencias"),
    "file": ("archivo", "archivos"), "attachment": ("adjunto", "adjuntos"),
    "report": ("reporte", "reportes"), "statement": ("extracto", "extractos"), "receipt": ("recibo", "recibos"),
    "ticket": ("ticket", "tickets"), "product": ("producto", "productos"), "item": ("ítem", "ítems"),
    "policy": ("póliza", "pólizas"), "claim": ("reclamación", "reclamaciones"), "loan": ("préstamo", "préstamos"),
    "card": ("tarjeta", "tarjetas"), "message": ("mensaje", "mensajes"), "record": ("registro", "registros"),
    "profile": ("perfil", "perfiles"), "contract": ("contrato", "contratos"), "shipment": ("envío", "envíos"),
    "booking": ("reserva", "reservas"), "reservation": ("reserva", "reservas"), "patient": ("paciente", "pacientes"),
    "employee": ("empleado", "empleados"), "bill": ("cuenta de cobro", "cuentas de cobro"),
    "credit": ("crédito", "créditos"), "quote": ("cotización", "cotizaciones"), "case": ("caso", "casos"),
}  # fmt: skip
_SCOPES: dict[str, str] = {
    "site": "sitio", "tenant": "tenant", "org": "organización", "organization": "organización",
    "company": "empresa", "account": "cuenta", "store": "tienda", "shop": "tienda", "region": "región",
    "country": "país", "branch": "sucursal", "client": "cliente", "customer": "cliente", "merchant": "comercio",
    "workspace": "espacio de trabajo", "project": "proyecto", "team": "equipo", "domain": "dominio",
    "market": "mercado",
}  # fmt: skip
_GENERIC_SEGMENTS = {
    "api", "rest", "v1", "v2", "v3", "v4", "search", "find", "get", "list", "query", "view", "detail", "details",
    "download", "export", "public", "private", "internal", "admin", "app", "web", "service", "services", "{id}",
    "show", "fetch", "read", "lookup", "buscar", "consulta", "consultar", "ver", "index",
}  # fmt: skip


@dataclass
class ParamStats:
    key: str
    n: int
    distinct: int
    numeric_ratio: float
    mean_len: float


@dataclass
class EndpointCandidate:
    endpoint: str
    requests: int
    object_param: str
    token_param: str = ""
    scope_param: str = ""
    max_objects_per_actor: int = 0
    params: list[ParamStats] = field(default_factory=list)


@dataclass
class ProfileInference:
    profile: IncidentProfile
    detected: bool  # False = no se encontró un endpoint con ID de objeto; se usan los valores configurados
    confidence: str  # alta | media | baja
    evidence: list[str] = field(default_factory=list)
    candidates: list[dict[str, Any]] = field(default_factory=list)
    overrides: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "mode": "automático",
            "detected": self.detected,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "candidates": self.candidates,
            "overrides": self.overrides,
        }


# --------------------------------------------------------------------------- utilidades de nombres
def _words(name: str) -> list[str]:
    spaced = re.sub(r"([a-z])([A-Z])", r"\1 \2", name)
    return [w.lower() for w in re.split(r"[^A-Za-z0-9áéíóúñ]+", spaced) if w]


def _singular(word: str) -> str:
    for suffix, repl in (("ies", "y"), ("ses", "s"), ("s", "")):
        if word.endswith(suffix) and len(word) > len(suffix) + 2:
            return word[: -len(suffix)] + repl
    return word


def object_labels(endpoint: str, object_param: str) -> tuple[str, str]:
    """Nombre de los objetos: primero el sustantivo del parámetro (order_id → pedido), luego la ruta."""
    words = [w for w in _words(object_param) if w not in {"id", "ids", "no", "num", "number", "code"}]
    segments = [s for s in endpoint.strip("/").split("/") if s.lower() not in _GENERIC_SEGMENTS]
    for raw in [*words, *(w for s in reversed(segments) for w in reversed(_words(s)))]:
        noun = _singular(raw)
        if noun in _NOUNS:
            return _NOUNS[noun]
    for raw in [*words, *(w for s in reversed(segments) for w in _words(s))]:
        if raw.isalpha() and len(raw) >= 3 and raw not in _GENERIC_SEGMENTS:
            sing = _singular(raw)
            plural = raw if raw != sing else f"{raw}s"
            if LABEL_RE.fullmatch(sing) and LABEL_RE.fullmatch(plural):
                return sing, plural
    return "objeto", "objetos"


def scope_label(scope_param: str) -> str:
    for raw in _words(scope_param):
        if _singular(raw) in _SCOPES:
            return _SCOPES[_singular(raw)]
    return "ámbito"


# --------------------------------------------------------------------------- inferencia
def _structure(lf: pl.LazyFrame) -> tuple[pl.DataFrame, pl.DataFrame]:
    """Una pasada sobre el CSV: peticiones por ruta normalizada y estadísticas de cada parámetro de la query.

    Las dos agregaciones se ejecutan juntas (`collect_all`) para que Polars lea el archivo una sola vez.
    """
    base = lf.select(
        path=_norm_path(),
        query=pl.col("http_uri").str.extract(r"\?([^#]*)", 1),
    )
    paths_q = base.group_by("path").agg(n=pl.len(), with_query=pl.col("query").is_not_null().sum())
    params_q = (
        base.filter(pl.col("query").is_not_null())
        .select("path", kv=pl.col("query").str.split("&"))
        .explode("kv", empty_as_null=True)
        .select(
            "path",
            key=pl.col("kv").str.extract(r"^([^=]*)", 1),
            val=pl.col("kv").str.extract(r"=(.*)$", 1),
        )
        .filter(pl.col("key").is_not_null() & (pl.col("key") != ""))
        .group_by("path", "key")
        .agg(
            n=pl.len(),
            distinct=pl.col("val").n_unique(),
            numeric_ratio=pl.col("val").str.contains(r"^\d+$").fill_null(False).mean(),
            mean_len=pl.col("val").str.len_chars().mean(),
        )
    )
    paths, params = pl.collect_all([paths_q, params_q], engine="streaming")
    paths = paths.sort("n", descending=True)
    return paths, params


def _roles(path: str, with_query: int, params: pl.DataFrame) -> EndpointCandidate | None:
    stats = [
        ParamStats(r["key"], r["n"], r["distinct"], float(r["numeric_ratio"] or 0), float(r["mean_len"] or 0))
        for r in params.filter(pl.col("path") == path).iter_rows(named=True)
        if PARAM_RE.fullmatch(r["key"] or "") and r["n"] >= MIN_PRESENCE * with_query
    ]
    objects = [s for s in stats if s.numeric_ratio >= 0.9 and s.distinct >= MIN_OBJECT_DISTINCT]
    if not objects:
        return None
    obj = max(objects, key=lambda s: (bool(OBJECT_HINT.search(s.key)), s.distinct))
    rest = [s for s in stats if s.key != obj.key]
    tokens = [s for s in rest if TOKEN_HINT.search(s.key) or (s.mean_len >= 16 and s.numeric_ratio < 0.5)]
    tok = max(tokens, key=lambda s: (bool(TOKEN_HINT.search(s.key)), s.mean_len), default=None)
    rest = [s for s in rest if tok is None or s.key != tok.key]
    scopes = [s for s in rest if 1 <= s.distinct <= 1000 and s.distinct * 10 <= obj.distinct]
    scope = max(scopes, key=lambda s: (bool(SCOPE_HINT.search(s.key)), s.n, -s.distinct), default=None)
    return EndpointCandidate(
        endpoint=path,
        requests=with_query,
        object_param=obj.key,
        token_param=tok.key if tok else "",
        scope_param=scope.key if scope else "",
        params=stats,
    )


def _idor_signal(lf: pl.LazyFrame, candidates: list[EndpointCandidate]) -> None:
    """Segunda pasada (solo si hay varios candidatos): máximo de objetos distintos consultados por un mismo actor
    (credencial o, si no hay, IP). Es la señal de un IDOR: un usuario legítimo ve pocos objetos propios."""
    path_expr = _norm_path()
    frames = []
    for c in candidates:
        obj = pl.col("http_uri").str.extract(rf"[?&]{re.escape(c.object_param)}=([^&#]*)", 1)
        actor = (
            pl.col("http_uri").str.extract(rf"[?&]{re.escape(c.token_param)}=([^&#]*)", 1)
            if c.token_param
            else pl.col("source_ip")
        )
        frames.append(
            lf.filter(path_expr == c.endpoint)
            .select(actor=actor, obj=obj)
            .drop_nulls()
            .group_by("actor")
            .agg(objs=pl.col("obj").n_unique())
            .select(pl.lit(c.endpoint).alias("endpoint"), pl.col("objs").max().alias("max_objs"))
        )
    result = pl.concat(frames).collect(engine="streaming")
    best = {r["endpoint"]: int(r["max_objs"] or 0) for r in result.iter_rows(named=True)}
    for c in candidates:
        c.max_objects_per_actor = best.get(c.endpoint, 0)


def infer_profile(lf: pl.LazyFrame, fallback: IncidentProfile) -> ProfileInference:
    """Deduce el perfil del incidente. `lf` es el escaneo crudo (`scan_logs`)."""
    paths, params = _structure(lf)
    total = int(paths["n"].sum()) if paths.height else 0
    candidates = [
        c
        for r in paths.filter(pl.col("with_query") > 0).head(20).iter_rows(named=True)
        if (c := _roles(r["path"], int(r["with_query"]), params)) is not None and ENDPOINT_OK.fullmatch(c.endpoint)
    ]
    path_ids = paths.filter(pl.col("path").str.contains(r"\{id\}"))
    evidence: list[str] = []
    if path_ids.height:
        top_pid = path_ids.row(0, named=True)
        evidence.append(
            f"Hay rutas con el identificador dentro de la ruta (p. ej. {top_pid['path']}, {top_pid['n']:,} "
            "peticiones): este análisis cubre IDs en parámetros de la query; revíselas aparte."
        )
    if not candidates:
        evidence.insert(
            0,
            "No se encontró una ruta con un identificador numérico en la query; se usan los valores configurados "
            "(.env). Revise el perfil manualmente.",
        )
        return ProfileInference(fallback, detected=False, confidence="baja", evidence=evidence)

    candidates = sorted(candidates, key=lambda c: -c.requests)[:MAX_CANDIDATES]
    if len(candidates) > 1:
        _idor_signal(lf, candidates)
        chosen = max(candidates, key=lambda c: (c.max_objects_per_actor, c.requests))
    else:
        chosen = candidates[0]
    singular, plural = object_labels(chosen.endpoint, chosen.object_param)
    profile = IncidentProfile(
        endpoint=chosen.endpoint,
        object_param=chosen.object_param,
        scope_param=chosen.scope_param,
        token_param=chosen.token_param or fallback.token_param,
        object_label=singular,
        object_label_plural=plural,
        scope_label=scope_label(chosen.scope_param) if chosen.scope_param else fallback.scope_label,
    )
    by_key = {s.key: s for s in chosen.params}
    obj = by_key[chosen.object_param]
    share = chosen.requests / total if total else 0
    evidence[:0] = [
        f"Endpoint {chosen.endpoint}: {chosen.requests:,} peticiones con parámetros ({share:.0%} del log)"
        + (
            f"; una misma credencial/IP consultó hasta {chosen.max_objects_per_actor:,} objetos distintos"
            if chosen.max_objects_per_actor
            else ""
        )
        + ".",
        f"ID de objeto: {obj.key} ({obj.numeric_ratio:.0%} numérico, {obj.distinct:,} valores distintos) → «{plural}».",
    ]
    if chosen.token_param:
        tok = by_key[chosen.token_param]
        why = "nombre de credencial" if TOKEN_HINT.search(tok.key) else "valores largos y opacos"
        evidence.append(
            f"Credencial: {tok.key} ({why}; {tok.distinct:,} valores distintos, longitud media {tok.mean_len:.0f})."
        )
    else:
        evidence.append(
            f"No se identificó un parámetro de credencial; se usa «{profile.token_param}» y los actores se "
            "analizan por IP. Si la credencial viaja en cabeceras, no aparece en este log."
        )
    if chosen.scope_param:
        sc = by_key[chosen.scope_param]
        evidence.append(f"Ámbito/tenant: {sc.key} ({sc.distinct:,} valores distintos) → «{profile.scope_label}».")
    others = [c for c in candidates if c is not chosen]
    if others:
        evidence.append(
            "Otros endpoints con identificadores de objeto: "
            + "; ".join(f"{c.endpoint} ({c.object_param}, {c.requests:,} pet.)" for c in others)
            + ". Para analizarlos, ajuste el perfil manualmente."
        )
    confidence = "alta" if chosen.token_param and (obj.distinct >= 100) else "media"
    return ProfileInference(
        profile,
        detected=True,
        confidence=confidence,
        evidence=evidence,
        candidates=[
            {k: v for k, v in asdict(c).items() if k != "params"} for c in sorted(candidates, key=lambda c: -c.requests)
        ],
    )


ENDPOINT_OK = re.compile(r"^/[A-Za-z0-9_\-/.]*$")  # mismo patrón que IncidentProfile (descarta rutas con {id})
