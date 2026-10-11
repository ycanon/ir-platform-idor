"""Features de comportamiento por actor (IP, token o subred /24).

Un "actor" es la entidad sobre la que se agregan las peticiones. El reto exige analizar por IP
[R2 "volumen anómalo por IP", R6 "Top 20 IPs"]; además se agrega por token y por subred porque
la muestra mostró que un mismo atacante puede repartir peticiones entre IPs y tokens [SPECS §1.2].

Todas las agregaciones se ejecutan sobre el LazyFrame en modo streaming: la salida es una fila
por actor (miles de filas), nunca los 4.5 M registros.
"""

from __future__ import annotations

from typing import Literal

import polars as pl

ActorKey = Literal["source_ip", "authtoken", "subnet24"]

# Firmas de clientes no-navegador. Lista genérica de herramientas de automatización/scraping y
# clientes de API conocidos (no derivada del dataset). Cada categoría se reporta por separado
# para no confundir un crawler con una herramienta de pruebas de API.
AUTOMATION_SIGNATURES: dict[str, str] = {
    "crawler_scraper": r"(?i)(crawler|spider|scrapy|bot\b|crawler4j|nutch|heritrix)",
    "cli_http_client": (
        r"(?i)(^wget|^curl|python-requests|python-urllib|go-http-client|libwww-perl|okhttp|java/|httpclient|aiohttp)"
    ),
    "api_testing_tool": r"(?i)(postman|insomnia|httpie|paw/|soapui)",
}
# Una sola regex con todas las firmas. El flag (?i) va UNA vez al inicio: se quita de cada patrón
# y se antepone al conjunto (si se omitiera, "Scrapy" con mayúscula no coincidiría; lo detectó un test).
AUTOMATION_ANY = "(?i)" + "|".join(f"(?:{p.removeprefix('(?i)')})" for p in AUTOMATION_SIGNATURES.values())


def with_automation_flag(lf: pl.LazyFrame) -> pl.LazyFrame:
    """Agrega `is_automation` (bool). Se calcula una sola vez (en el staging) porque la regex
    sin distinción de mayúsculas sobre 4.5 M user agents es la operación más costosa."""
    return lf.with_columns(is_automation=pl.col("http_user_agent").str.contains(AUTOMATION_ANY))


def _is_2xx() -> pl.Expr:
    return pl.col("status").is_between(200, 299)


def with_subnet(lf: pl.LazyFrame) -> pl.LazyFrame:
    """Agrega `subnet24` (p. ej. 181.88.192.0/24) para IPv4; null si no es IPv4."""
    return lf.with_columns(
        subnet24=pl.col("source_ip").str.extract(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$", 1) + ".0/24"
    )


def actor_features(lf: pl.LazyFrame, key: ActorKey) -> pl.DataFrame:
    """Devuelve una fila por actor con las features usadas por reglas y modelo.

    Columnas principales:
    - requests, unique_invoices, unique_sites, unique_ips, unique_tokens, unique_user_agents
    - success_ratio (2xx), client_error_ratio (4xx), count_401, count_403
    - automation_ratio: fracción de peticiones con user agent de automatización
    - requests_per_source_day / invoices_per_source_day: intensidad normalizada (ver abajo)
    - invoice_density: fracción de invoice_id cuyo vecino (id+1) también fue consultado por el
      mismo actor. Mide enumeración de un rango contiguo de IDs, aunque las peticiones no lleguen
      en orden (el timestamp tiene resolución de minuto y las filas no están ordenadas).
    - first_seen, last_seen, active_days, first_success
    """
    if key == "subnet24":
        lf = with_subnet(lf)
    if "is_automation" not in lf.collect_schema().names():
        lf = with_automation_flag(lf)

    target = lf.filter(pl.col(key).is_not_null())

    base = target.group_by(key).agg(
        requests=pl.len(),
        unique_invoices=pl.col("invoice_id_num").n_unique(),
        unique_sites=pl.col("site_id").n_unique(),
        unique_ips=pl.col("source_ip").n_unique(),
        unique_tokens=pl.col("authtoken").n_unique(),
        unique_user_agents=pl.col("http_user_agent").n_unique(),
        success=_is_2xx().sum(),
        client_errors=pl.col("status").is_between(400, 499).sum(),
        count_401=(pl.col("status") == 401).sum(),
        count_403=(pl.col("status") == 403).sum(),
        automation_requests=pl.col("is_automation").sum(),
        first_seen=pl.col("ts").min(),
        last_seen=pl.col("ts").max(),
        first_success=pl.col("ts").filter(_is_2xx()).min(),
        active_days=pl.col("ts").dt.date().n_unique(),
    )

    # Densidad de enumeración: pares únicos (actor, invoice) y semi-join con (actor, invoice - 1).
    pairs = target.select(key, "invoice_id_num").drop_nulls().unique()
    neighbors = (
        pairs.join(
            pairs.with_columns(pl.col("invoice_id_num") - 1),
            on=[key, "invoice_id_num"],
            how="semi",
        )
        .group_by(key)
        .agg(neighbor_hits=pl.len())
    )

    base_df, neighbors_df = pl.collect_all([base, neighbors], engine="streaming")

    return (
        base_df.join(neighbors_df, on=key, how="left")
        .with_columns(
            neighbor_hits=pl.col("neighbor_hits").fill_null(0),
            success_ratio=pl.col("success") / pl.col("requests"),
            client_error_ratio=pl.col("client_errors") / pl.col("requests"),
            automation_ratio=pl.col("automation_requests") / pl.col("requests"),
            # Intensidad normalizada por "fuente-día" (IPs distintas x días activos). Evita que una IP
            # legítima activa 2 meses parezca el doble de anómala que una activa 1 mes, y que una
            # subred con cientos de IPs normales parezca un solo actor gigante.
            requests_per_source_day=pl.col("requests") / (pl.col("unique_ips") * pl.col("active_days")),
            invoices_per_source_day=pl.col("unique_invoices") / (pl.col("unique_ips") * pl.col("active_days")),
        )
        .with_columns(
            invoice_density=pl.when(pl.col("unique_invoices") > 0)
            .then(pl.col("neighbor_hits") / pl.col("unique_invoices"))
            .otherwise(0.0),
        )
        .rename({key: "actor"})
        .sort("requests", descending=True)
    )


def automation_breakdown(lf: pl.LazyFrame, actors: list[str], key: ActorKey) -> dict[str, dict[str, int]]:
    """Peticiones por categoría de automatización para un conjunto pequeño de actores (evidencia)."""
    if not actors:
        return {}
    if key == "subnet24":
        lf = with_subnet(lf)
    exprs = [
        pl.col("http_user_agent").str.contains(pattern).sum().alias(name)
        for name, pattern in AUTOMATION_SIGNATURES.items()
    ]
    df = lf.filter(pl.col(key).is_in(actors)).group_by(key).agg(exprs).collect(engine="streaming")
    return {row[key]: {name: int(row[name]) for name in AUTOMATION_SIGNATURES} for row in df.iter_rows(named=True)}
