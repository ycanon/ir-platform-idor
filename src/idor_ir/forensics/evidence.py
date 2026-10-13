"""Evidencia forense del incidente [R6, R7, R12, R14-TTD].

Parte de las tablas de actores puntuadas por el detector IDOR y del Parquet de staging, y produce:
- Campañas: componentes conexos del grafo IP<->token sobre el "tráfico de ataque".
- Por campaña: patient zero, inicio de explotación (primer 2xx), fases, automatización, impacto.
- Top 20 IPs con evidencia, IOCs (IPs, user agents, tokens, patrones de enumeración), timeline.
- Respuestas con datos a las 7 preguntas del reto (sección 3.1) y TTD.

Definiciones (decisiones técnicas documentadas en SPECS §5.4):
- Escala de evidencia (`assessment.py`): señal → hipótesis → corroboración → impacto confirmado. El log HTTP no
  trae propietario del objeto ni decisión de autorización: sin una fuente de la aplicación, todo queda en HIPÓTESIS.
- IP sospechosa (señal): nivel de riesgo >= medio. El user agent NO es requisito (es solo una de las features).
- Tráfico atribuido: dentro de cada IP sospechosa, los segmentos cuyo user agent está CONCENTRADO en actores
  sospechosos (>= 80 % de sus peticiones vienen de ellos; se calcula del propio dataset, sin lista fija). Si una IP
  sospechosa no tiene ningún segmento concentrado (p. ej. un atacante con navegador común), se le atribuye TODO su
  tráfico y se marca así. La lista de firmas de herramientas solo etiqueta la categoría del user agent.
- Campaña (hipótesis): componente conexo del grafo IP↔credencial del tráfico atribuido. «Alta confianza» si tiene una
  IP de nivel crítico y al menos dos señales concordantes; si no, «por validar». «Corroborada» SOLO con una fuente
  de ownership que muestre objetos entregados a quien no era su titular (`corroboration.py`).
- Alcance: objetos únicos con respuesta 2xx = EXPOSICIÓN POTENCIAL (límite superior), no accesos indebidos.
- Textos con el perfil del incidente (endpoint, parámetros y nombre de los objetos): `profile.IncidentProfile`.
  Las claves JSON conservan los nombres internos (`unique_invoices_*`) por compatibilidad.
"""

from __future__ import annotations

import statistics
from collections import Counter
from datetime import datetime, timedelta
from typing import Any

import polars as pl

from idor_ir.detection.features import AUTOMATION_SIGNATURES
from idor_ir.forensics.assessment import (
    CORROBORATION_SOURCES,
    EVIDENCE_SCALE,
    LOG_LIMITATIONS,
    STATUS_CORROBORATED,
    STATUS_HIGH,
    STATUS_PENDING,
    STATUS_REFUTED,
    is_priority,
    status_label,
)
from idor_ir.forensics.corroboration import corroborate
from idor_ir.profile import IncidentProfile
from idor_ir.redaction import fingerprint_token, token_hint

SUSPICIOUS_LEVELS = ("critico", "alto", "medio")
PIVOT_TOKEN_LEVELS = ("critico", "alto")
# Señales "ancla" (riesgo crítico del actor): una basta como ancla; las demás deben sumar >= 2 concordantes.
ANCHOR_SIGNALS = ("ip_nivel_critico", "credencial_nivel_critico")
CHANGE_RATIO = 2.0  # cambio de régimen: la mediana diaria se duplica (o cae a la mitad)
SAMPLE_REQUESTS = 3
UA_CONCENTRATION = 0.8  # un UA es «del atacante» si >= 80 % de sus peticiones vienen de actores sospechosos

Hints = dict[str, str]


def _mask(token: str | None, hints: Hints | None = None) -> dict[str, str] | None:
    """Huella + pista. El staging ya guarda la huella (no el token): si viene en `hints`, se usa tal cual."""
    if token is None:
        return None
    if hints and token in hints:
        return {"fingerprint": token, "hint": hints[token]}
    return {"fingerprint": fingerprint_token(token), "hint": token_hint(token)}


def _iso(value: Any) -> Any:
    return value.isoformat() if isinstance(value, datetime) else value


def id_ranges(ids: set[int] | list[int], max_gap: int = 100) -> list[list[int]]:
    """Agrupa IDs en rangos [inicio, fin] tolerando huecos <= max_gap (enumeración con saltos pequeños)."""
    ordered = sorted(set(ids))
    if not ordered:
        return []
    ranges = [[ordered[0], ordered[0]]]
    for value in ordered[1:]:
        if value - ranges[-1][1] <= max_gap:
            ranges[-1][1] = value
        else:
            ranges.append([value, value])
    return ranges


def _ua_category(ua: str | None) -> str:
    if not ua:
        return "desconocido"
    for name, pattern in AUTOMATION_SIGNATURES.items():
        if pl.Series([ua]).str.contains(pattern)[0]:
            return name
    return "navegador_u_otro"


# ---------------------------------------------------------------------------------------------
# Campañas
# ---------------------------------------------------------------------------------------------


def _components(edges: list[tuple[str, str]]) -> list[tuple[set[str], set[str]]]:
    """Componentes conexos de un grafo bipartito IP-token (union-find simple)."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for ip, tok in edges:
        parent[find("ip:" + ip)] = find("tok:" + tok)

    groups: dict[str, tuple[set[str], set[str]]] = {}
    for node in list(parent):
        ips, toks = groups.setdefault(find(node), (set(), set()))
        (ips if node.startswith("ip:") else toks).add(node.split(":", 1)[1])
    return list(groups.values())


def _phases(daily: pl.DataFrame) -> list[dict[str, Any]]:
    """Segmenta la serie diaria en fases cuando la mediana cambia >= CHANGE_RATIO de forma sostenida."""
    days = daily["day"].to_list()
    counts = daily["requests"].to_list()
    cuts = [0]
    for i in range(1, len(counts)):
        prev = statistics.median(counts[max(cuts[-1], i - 7) : i])
        following = counts[i : i + 3]
        if prev == 0 and max(following) == 0:
            continue
        # Cambio sostenido: los 3 días siguientes TODOS superan (o quedan bajo) el umbral.
        up = (min(following) + 1e-9) / (prev + 1e-9) >= CHANGE_RATIO
        down = (max(following) + 1e-9) / (prev + 1e-9) <= 1 / CHANGE_RATIO
        if (up or down) and i - cuts[-1] >= 3:
            cuts.append(i)
    cuts.append(len(counts))
    phases = []
    for n, (a, b) in enumerate(zip(cuts[:-1], cuts[1:], strict=True), start=1):
        seg = daily.slice(a, b - a)
        phases.append(
            {
                "phase": n,
                "start": str(days[a]),
                "end": str(days[b - 1]),
                "days": b - a,
                "requests": int(seg["requests"].sum()),
                "median_per_day": float(statistics.median(counts[a:b])),
                "constant_daily_volume": len(set(counts[a:b])) == 1,
                "success_2xx": int(seg["success"].sum()),
                "success_ratio": round(int(seg["success"].sum()) / max(int(seg["requests"].sum()), 1), 3),
            }
        )
    return phases


def _campaign_detail(
    cid: str, rows: pl.DataFrame, baseline_invoices: set[int], hints: Hints | None = None
) -> dict[str, Any]:
    is_2xx = pl.col("status").is_between(200, 299)
    first = rows.sort("ts").row(0, named=True)
    ok = rows.filter(is_2xx)
    first_ok = ok.sort("ts").row(0, named=True) if ok.height else None
    ok_invoices = set(ok["invoice_id_num"].drop_nulls().to_list())
    novel = ok_invoices - baseline_invoices

    daily = (
        rows.group_by(day=pl.col("ts").dt.date())
        .agg(requests=pl.len(), success=is_2xx.sum())
        .sort("day")
        .upsample(time_column="day", every="1d")
        .with_columns(pl.col("requests", "success").fill_null(0))
    )
    ua_first = rows.group_by("http_user_agent").agg(first=pl.col("ts").min(), n=pl.len()).sort("first")
    by_site = ok.group_by("site_id").agg(unique_invoices=pl.col("invoice_id_num").n_unique()).sort("site_id")
    beyond = rows.filter(~pl.col("invoice_id_num").is_in(sorted(baseline_invoices)))
    status = rows.group_by("status").len().sort("status")

    has_token = pl.col("authtoken").is_not_null() & (pl.col("authtoken").str.len_chars() > 0)
    ok_with_token = ok.filter(has_token).height

    return {
        "campaign_id": cid,
        "ips": sorted(rows["source_ip"].unique().to_list()),
        "tokens": [_mask(t, hints) for t in sorted(rows["authtoken"].drop_nulls().unique().to_list())],
        "requests": rows.height,
        "first_seen": _iso(first["ts"]),
        "last_seen": _iso(rows["ts"].max()),
        "patient_zero": {
            "ts": _iso(first["ts"]),
            "source_ip": first["source_ip"],
            "token": _mask(first["authtoken"], hints),
            "invoice_id": first["invoice_id_num"],
            "site_id": first["site_id"],
            "status": first["status"],
            "user_agent": first["http_user_agent"],
        },
        "exploitation_start": None
        if first_ok is None
        else {
            "ts": _iso(first_ok["ts"]),
            "source_ip": first_ok["source_ip"],
            "token": _mask(first_ok["authtoken"], hints),
            "invoice_id": first_ok["invoice_id_num"],
            "status": first_ok["status"],
        },
        "status_counts": {str(r["status"]): int(r["len"]) for r in status.iter_rows(named=True)},
        "user_agents": [
            {
                "user_agent": r["http_user_agent"],
                "category": _ua_category(r["http_user_agent"]),
                "requests": int(r["n"]),
                "first_seen": _iso(r["first"]),
            }
            for r in ua_first.iter_rows(named=True)
        ],
        "phases": _phases(daily),
        "impact": {
            "success_responses_2xx": ok.height,
            # Autenticación medida en los datos (no supuesta): 2xx con y sin credencial en la petición.
            "success_2xx_with_token": ok_with_token,
            "success_2xx_without_token": ok.height - ok_with_token,
            "unique_invoices_2xx": len(ok_invoices),
            "unique_invoices_2xx_outside_baseline": len(novel),
            "invoice_site_pairs_2xx": ok.select("invoice_id_num", "site_id").unique().height,
            "unique_invoices_2xx_by_site": {
                r["site_id"]: int(r["unique_invoices"]) for r in by_site.iter_rows(named=True)
            },
            "invoice_id_ranges_2xx": id_ranges(ok_invoices),
            "invoice_id_ranges_outside_baseline": id_ranges(novel),
            "first_request_outside_baseline": _iso(beyond["ts"].min()) if beyond.height else None,
        },
        "daily": [
            {"day": str(r["day"]), "requests": int(r["requests"]), "success": int(r["success"])}
            for r in daily.iter_rows(named=True)
        ],
    }


# ---------------------------------------------------------------------------------------------
# Construcción de la evidencia
# ---------------------------------------------------------------------------------------------


def build_evidence(
    lf: pl.LazyFrame,
    ip_table: pl.DataFrame,
    token_table: pl.DataFrame,
    dataset_start: datetime | None,
    detection_date: datetime | None,
    profile: IncidentProfile | None = None,
    dataset_end: datetime | None = None,
    token_hints: Hints | None = None,
    ownership: pl.DataFrame | None = None,
    ownership_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    profile = profile or IncidentProfile()
    hints = token_hints or {}
    # 1) Señales: IPs con nivel de riesgo >= medio (el user agent no es requisito).
    suspicious = ip_table.filter(pl.col("risk_level").is_in(SUSPICIOUS_LEVELS))
    suspicious_ips = suspicious["actor"].to_list()
    ip_level = dict(zip(ip_table["actor"].to_list(), ip_table["risk_level"].to_list(), strict=True))

    # 2) Atribución del tráfico sin lista fija de user agents: concentración del UA en actores sospechosos.
    ua_stats = (
        lf.group_by("http_user_agent")
        .agg(total=pl.len(), suspicious=pl.col("source_ip").is_in(suspicious_ips).sum())
        .collect(engine="streaming")
    )
    concentrated = sorted(
        ua_stats.filter((pl.col("suspicious") / pl.col("total")) >= UA_CONCENTRATION)["http_user_agent"]
        .drop_nulls()
        .to_list()
    )
    has_segment = (
        lf.filter(pl.col("source_ip").is_in(suspicious_ips))
        .group_by("source_ip")
        .agg(seg=pl.col("http_user_agent").is_in(concentrated).any())
        .collect(engine="streaming")
    )
    whole_ip = sorted(has_segment.filter(~pl.col("seg"))["source_ip"].to_list())
    # Pivote por credencial: todo lo hecho con una credencial de riesgo >= alto es tráfico atribuido, aunque venga
    # de IPs que por sí solas no destacan (atacante que rota IPs; la validación etiquetada mostró ese punto ciego).
    token_level = dict(zip(token_table["actor"].to_list(), token_table["risk_level"].to_list(), strict=True))
    pivot_tokens = sorted(t for t, lv in token_level.items() if lv in PIVOT_TOKEN_LEVELS)
    is_attack = (
        pl.col("source_ip").is_in(suspicious_ips)
        & (pl.col("http_user_agent").is_in(concentrated) | pl.col("source_ip").is_in(whole_ip))
    ) | pl.col("authtoken").is_in(pivot_tokens)
    attack = lf.filter(is_attack).collect(engine="streaming")
    baseline_df = lf.filter(~is_attack).select(pl.col("invoice_id_num").unique()).collect(engine="streaming")
    baseline_invoices = set(baseline_df["invoice_id_num"].drop_nulls().to_list())
    baseline_ranges = id_ranges(baseline_invoices)
    ua_totals = {r["http_user_agent"]: int(r["total"]) for r in ua_stats.iter_rows(named=True)}

    # 3) Hipótesis: campañas = componentes del grafo IP-credencial del tráfico atribuido.
    edges = [
        (r["source_ip"], r["authtoken"])
        for r in attack.select("source_ip", "authtoken").drop_nulls().unique().iter_rows(named=True)
    ]
    comps = sorted(_components(edges), key=lambda c: (-len(c[0]), sorted(c[0])))
    campaigns: list[dict[str, Any]] = []
    ip_to_campaign: dict[str, str] = {}
    for n, (ips, _toks) in enumerate(comps, start=1):
        cid = f"C{n}"
        rows = attack.filter(pl.col("source_ip").is_in(sorted(ips)))
        detail = _campaign_detail(cid, rows, baseline_invoices, hints)
        levels = [ip_level.get(ip, "bajo") for ip in ips]
        signals = _campaign_signals(detail, rows, levels, ua_totals, token_level)
        concordant = sum(v for k, v in signals.items() if k not in ANCHOR_SIGNALS)
        anchored = signals["ip_nivel_critico"] or signals["credencial_nivel_critico"]
        detail["signals"] = signals
        detail["status"] = STATUS_HIGH if anchored and concordant >= 2 else STATUS_PENDING
        detail["max_ip_level"] = "critico" if "critico" in levels else ("alto" if "alto" in levels else "medio")
        detail["attribution"] = {
            "method": "ip_completa" if any(ip in whole_ip for ip in ips) else "segmentos_ua_concentrados",
            "user_agents_concentrados": sorted(
                {u for u in rows["http_user_agent"].unique().to_list() if u in concentrated}
            ),
            "ips_atribuidas_completas": sorted(ip for ip in ips if ip in whole_ip),
        }
        # 4) Corroboración (opcional): solo una fuente de ownership puede convertir la hipótesis en impacto.
        detail["corroboration"] = {"status": "pendiente", "sources_needed": CORROBORATION_SOURCES}
        if ownership is not None:
            result = corroborate(rows.filter(pl.col("status").is_between(200, 299)), ownership)
            detail["corroboration"] = {"status": "evaluada", "source": ownership_meta or {}, **result}
            if result["unauthorized_2xx"] > 0:
                detail["status"] = STATUS_CORROBORATED
            elif result["checked_2xx"] > 0 and result["unknown_owner_2xx"] == 0:
                detail["status"] = STATUS_REFUTED
        detail["status_label"] = status_label(detail["status"])
        campaigns.append(detail)
        ip_to_campaign.update({ip: cid for ip in ips})
    order = {STATUS_CORROBORATED: 0, STATUS_HIGH: 1, STATUS_PENDING: 2, STATUS_REFUTED: 3}
    campaigns.sort(key=lambda c: (order.get(c["status"], 9), -c["requests"]))
    renumber = {c["campaign_id"]: f"C{n}" for n, c in enumerate(campaigns, start=1)}
    for c in campaigns:
        c["campaign_id"] = renumber[c["campaign_id"]]
    ip_to_campaign = {ip: renumber[cid] for ip, cid in ip_to_campaign.items()}

    attributed = {"concentrated": set(concentrated), "whole_ip": set(whole_ip)}
    top20 = _top_ips(lf, ip_table.head(20), ip_to_campaign, set(suspicious_ips), attributed, hints)
    iocs = _iocs(lf, attack, campaigns, suspicious, token_table, baseline_ranges, profile, hints)
    priority = [c for c in campaigns if is_priority(c)]
    metrics = _response_metrics(priority, detection_date, dataset_end)
    answers = _answers(campaigns, priority, dataset_start, metrics, profile)
    timeline = _timeline(campaigns, dataset_start, detection_date, profile)
    p = profile
    corroborated = [c for c in campaigns if c["status"] == STATUS_CORROBORATED]

    return {
        "assessment": {
            "scale": EVIDENCE_SCALE,
            "level": "impacto confirmado" if corroborated else ("hipótesis" if priority else "señal"),
            "statement": (
                f"IDOR corroborado con fuente de ownership en {len(corroborated)} campaña(s)."
                if corroborated
                else "Patrón compatible con enumeración y abuso de autorización a nivel de objeto (IDOR). "
                "Hipótesis de alta confianza: NO demostrada, porque el log no permite saber a quién pertenece "
                "cada objeto."
                if priority
                else "Solo señales: no hay una campaña con evidencia concordante."
            ),
            "limitations": [] if corroborated else LOG_LIMITATIONS,
            "to_confirm": [] if corroborated else CORROBORATION_SOURCES,
            "corroboration_source": ownership_meta,
        },
        "assumptions": {
            "detection_date": detection_date.isoformat() if detection_date else None,
            "affected_users_definition": f"Exposición potencial (límite superior): {p.object_param} únicos con 2xx "
            "en campañas priorizadas"
            + (f", desglosado por {p.scope_param}" if p.scope_param else "")
            + f" (1 {p.object_label} = 1 titular potencial). Solo con ownership se cuentan accesos indebidos.",
            "suspicious_ip_definition": "Señal: nivel de riesgo >= medio (el user agent es una feature, no un "
            "requisito).",
            "attack_traffic_definition": (
                "Tráfico atribuido: segmentos de IPs sospechosas cuyo user agent está concentrado (>= "
                f"{UA_CONCENTRATION:.0%}) en actores sospechosos; si una IP no tiene ninguno, todo su tráfico. "
                "Además, todo el tráfico de credenciales con riesgo >= alto (pivote por credencial: cubre la "
                "rotación de IPs)."
            ),
            "pivot_credentials": [_mask(t, hints) for t in pivot_tokens],
            "user_agents_concentrated": concentrated,
            "ips_attributed_whole": whole_ip,
        },
        "incident_answers": answers,
        "response_metrics": metrics,
        "campaigns": campaigns,
        "top20_ips": top20,
        "iocs": iocs,
        "timeline": timeline,
    }


def _campaign_signals(
    detail: dict[str, Any],
    rows: pl.DataFrame,
    levels: list[str],
    ua_totals: dict[str, int],
    token_level: dict[str, str] | None = None,
) -> dict[str, bool]:
    """Señales concordantes que sostienen la hipótesis (ninguna sola basta)."""
    shared = (
        rows.select("authtoken", "source_ip")
        .drop_nulls()
        .unique()
        .group_by("authtoken")
        .len()
        .filter(pl.col("len") > 1)
    )
    ua_counts = rows.group_by("http_user_agent").len()
    exclusive = any(ua_totals.get(r["http_user_agent"]) == int(r["len"]) for r in ua_counts.iter_rows(named=True))
    return {
        "ip_nivel_critico": "critico" in levels,
        "credencial_nivel_critico": any(
            (token_level or {}).get(t) == "critico" for t in rows["authtoken"].drop_nulls().unique().to_list()
        ),
        "enumeracion_fuera_de_la_linea_base": detail["impact"]["unique_invoices_2xx_outside_baseline"] > 0,
        "credenciales_compartidas_entre_ips": shared.height > 0,
        "user_agents_exclusivos_de_la_campana": exclusive,
        "volumen_diario_constante": any(ph["constant_daily_volume"] and ph["days"] >= 3 for ph in detail["phases"]),
    }


def _top_ips(
    lf: pl.LazyFrame,
    top: pl.DataFrame,
    ip_to_campaign: dict[str, str],
    suspicious: set[str],
    attributed: dict[str, set[str]],
    hints: Hints | None = None,
) -> list[dict[str, Any]]:
    ips = top["actor"].to_list()
    rows = lf.filter(pl.col("source_ip").is_in(ips)).collect(engine="streaming")
    out = []
    for rank, rec in enumerate(top.iter_rows(named=True), start=1):
        ip = rec["actor"]
        sub = rows.filter(pl.col("source_ip") == ip)
        if ip in suspicious and ip not in attributed["whole_ip"]:
            evidence_rows = sub.filter(pl.col("http_user_agent").is_in(sorted(attributed["concentrated"])))
        else:
            evidence_rows = sub
        samples = evidence_rows.sort("ts").head(SAMPLE_REQUESTS)
        uas = Counter(sub["http_user_agent"].to_list()).most_common(3)
        out.append(
            {
                "rank": rank,
                "ip": ip,
                "risk_score": rec["risk_score"],
                "risk_level": rec["risk_level"],
                "campaign_id": ip_to_campaign.get(ip),
                "reasons": rec["reasons"],
                "requests": rec["requests"],
                "success_2xx": rec["success"],
                "unique_invoices": rec["unique_invoices"],
                "automation_ratio": round(rec["automation_ratio"], 3),
                "tokens_used": int(sub["authtoken"].n_unique()),
                "top_user_agents": [{"user_agent": ua, "requests": n} for ua, n in uas],
                "first_seen": _iso(rec["first_seen"]),
                "last_seen": _iso(rec["last_seen"]),
                "sample_requests": [
                    {
                        "ts": _iso(s["ts"]),
                        "status": s["status"],
                        "invoice_id": s["invoice_id_num"],
                        "site_id": s["site_id"],
                        "token": _mask(s["authtoken"], hints),
                        "user_agent": s["http_user_agent"],
                    }
                    for s in samples.iter_rows(named=True)
                ],
            }
        )
    return out


def _iocs(
    lf: pl.LazyFrame,
    attack: pl.DataFrame,
    campaigns: list[dict[str, Any]],
    suspicious: pl.DataFrame,
    token_table: pl.DataFrame,
    baseline_ranges: list[list[int]],
    profile: IncidentProfile,
    hints: Hints | None = None,
) -> dict[str, Any]:
    p = profile
    ip_campaign = {ip: c["campaign_id"] for c in campaigns for ip in c["ips"]}
    ip_iocs = [
        {
            "type": "ip",
            "value": r["actor"],
            "campaign_id": ip_campaign.get(r["actor"]),
            "risk_level": r["risk_level"],
            "risk_score": r["risk_score"],
            "first_seen": _iso(r["first_seen"]),
            "last_seen": _iso(r["last_seen"]),
        }
        for r in suspicious.iter_rows(named=True)
    ]

    # User agents: cuántas veces aparecen dentro y fuera del tráfico de ataque (exclusividad).
    attack_uas = attack.group_by("http_user_agent").len()
    totals = lf.group_by("http_user_agent").agg(total=pl.len()).collect(engine="streaming")
    ua_df = attack_uas.join(totals, on="http_user_agent", how="left")
    ua_iocs = [
        {
            "type": "user_agent",
            "value": r["http_user_agent"],
            "category": _ua_category(r["http_user_agent"]),
            "attack_requests": int(r["len"]),
            "other_requests": int(r["total"] - r["len"]),
            "exclusive_to_attack": int(r["total"]) == int(r["len"]),
        }
        for r in ua_df.sort("len", descending=True).iter_rows(named=True)
    ]

    token_iocs = [
        {
            "type": "token",
            **(_mask(r["actor"], hints) or {}),
            "risk_level": r["risk_level"],
            "risk_score": r["risk_score"],
            "unique_invoices": r["unique_invoices"],
            "unique_ips": r["unique_ips"],
        }
        for r in token_table.filter(pl.col("risk_level").is_in(SUSPICIOUS_LEVELS)).iter_rows(named=True)
    ]

    patterns = []
    for c in campaigns:
        imp = c["impact"]
        patterns.append(
            {
                "type": "enumeration_pattern",
                "campaign_id": c["campaign_id"],
                "endpoint": p.request_template,
                "description": (
                    f"[{status_label(c['status'])}] {len(c['tokens'])} credencial(es) ({p.token_param}) usadas desde "
                    f"{len(c['ips'])} IP(s) obtienen 2xx para {imp['unique_invoices_2xx']:,} {p.object_param} "
                    "distintos (exposición potencial) en los rangos "
                    + ", ".join(f"{a}–{b}" for a, b in imp["invoice_id_ranges_2xx"])
                ),
                "invoice_id_ranges_2xx": imp["invoice_id_ranges_2xx"],
                "invoice_id_ranges_outside_baseline": imp["invoice_id_ranges_outside_baseline"],
                "outside_baseline_ids": imp["unique_invoices_2xx_outside_baseline"],
                "baseline_invoice_id_ranges": baseline_ranges,
                "suggested_detection_rule": f"Alertar si un {p.token_param} consulta > 50 {p.object_param} distintos "
                f"por día o es usado desde > 3 IPs; bloquear UA de herramientas en {p.endpoint}.",
            }
        )
    return {"ips": ip_iocs, "user_agents": ua_iocs, "tokens": token_iocs, "enumeration_patterns": patterns}


def _response_metrics(
    confirmed: list[dict[str, Any]], detection: datetime | None, dataset_end: datetime | None = None
) -> dict[str, Any]:
    """Tiempos desde la primera actividad de las campañas priorizadas (corroboradas o de alta confianza)."""
    if not confirmed:
        return {"ttd": None, "note": "Sin campañas priorizadas (solo señales o hipótesis por validar)."}
    first_seen = min(datetime.fromisoformat(c["first_seen"]) for c in confirmed)
    starts = [c["exploitation_start"]["ts"] for c in confirmed if c["exploitation_start"]]
    first_ok = min(datetime.fromisoformat(s) for s in starts) if starts else None

    def days(delta: timedelta) -> float:
        return round(delta.total_seconds() / 86400, 1)

    # Referencia del TTD: la fecha de detección que indique el analista; si no la hay, el ÚLTIMO registro del log
    # (los logs se extraen para investigar lo detectado, así que el fin del log aproxima la detección). Se marca
    # como estimado para no presentarlo como un dato del incidente.
    reference = detection or dataset_end
    source = "analista" if detection else ("fin del log (estimado)" if dataset_end else None)
    return {
        "detection_date": detection.isoformat() if detection else None,
        "ttd_reference": reference.isoformat() if reference else None,
        "ttd_reference_source": source,
        "ttd_is_estimate": detection is None and reference is not None,
        "ttd_from_first_malicious_request_days": days(reference - first_seen) if reference else None,
        "ttd_from_first_successful_access_days": days(reference - first_ok) if reference and first_ok else None,
        "first_malicious_request": first_seen.isoformat(),
        "first_successful_access": first_ok.isoformat() if first_ok else None,
        "ttr_ttc": "Se estiman con supuestos explícitos en el Response Advisor (agentes).",
    }


def auth_statement(cid: str, imp: dict[str, Any], profile: IncidentProfile) -> str:
    """Hecho de autenticación DERIVADO DE LOS DATOS, en afirmativo y con cifras.

    Motivo: redactarlo como negación ("no hay evidencia de acceso sin autenticación") hizo que un modelo de 4B
    repitiera literalmente "acceso sin autenticación". Y fijarlo como texto sería falso en un incidente donde sí
    hubo respuestas exitosas sin credencial.
    """
    total = int(imp.get("success_responses_2xx", 0))
    without = int(imp.get("success_2xx_without_token", 0))
    with_token = int(imp.get("success_2xx_with_token", total - without))
    tp = profile.token_param
    if total == 0:
        return f"{cid}: ninguna respuesta 2xx."
    if without == 0:
        return (
            f"{cid}: las {with_token:,} respuestas 2xx correspondían a peticiones con {tp}: el acceso se hizo con "
            "credenciales y el servidor respondió con éxito. Si esas "
            f"{profile.object_label_plural} no pertenecían a los titulares de las credenciales (dato que el log no "
            "tiene y debe verificarse con ownership), la falla sería de AUTORIZACIÓN a nivel de objeto (IDOR), no de "
            "autenticación."
        )
    if with_token == 0:
        return (
            f"{cid}: las {without:,} respuestas 2xx correspondían a peticiones SIN {tp}: posible falla de "
            "AUTENTICACIÓN (el servidor respondió sin credencial); verificar antes de concluir."
        )
    return (
        f"{cid}: {with_token:,} respuestas 2xx con {tp} y {without:,} SIN {tp}: hay acceso con credencial (posible "
        "falla de autorización, a verificar con ownership) y además posible acceso sin credencial; verificar ambos."
    )


def _answers(
    campaigns: list[dict[str, Any]],
    priority: list[dict[str, Any]],
    dataset_start: datetime | None,
    metrics: dict[str, Any],
    profile: IncidentProfile,
) -> dict[str, Any]:
    if not priority:
        return {"summary": "Solo señales o hipótesis por validar: no hay una campaña con evidencia concordante."}
    p = profile
    main = priority[0]
    imp = main["impact"]
    corr = main.get("corroboration", {})
    corroborated = main["status"] == STATUS_CORROBORATED
    censored = dataset_start is not None and datetime.fromisoformat(main["first_seen"]) - dataset_start <= timedelta(
        hours=1
    )
    uas = [u for u in main["user_agents"] if u["category"] != "navegador_u_otro"]
    constant = [p for p in main["phases"] if p["constant_daily_volume"]]
    signals = [k.replace("_", " ") for k, v in main.get("signals", {}).items() if v]
    if corroborated:
        idor = {
            "respuesta": "Sí, corroborado",
            "nivel": "impacto confirmado",
            "fundamento": (
                f"La fuente de ownership muestra {corr['unauthorized_2xx']:,} respuestas 2xx a credenciales que NO "
                f"eran titulares ({corr['unique_objects_unauthorized']:,} {p.object_label_plural} distintas, "
                f"{corr['unique_owners_exposed']:,} titulares). " + auth_statement(main["campaign_id"], imp, p)
            ),
        }
    else:
        idor = {
            "respuesta": "Indicios fuertes, no demostrado",
            "nivel": "hipótesis de alta confianza",
            "fundamento": (
                f"{len(main['tokens'])} credenciales ({p.token_param}) obtuvieron respuesta 2xx para "
                f"{imp['unique_invoices_2xx']:,} {p.object_label_plural} distintas, "
                f"{imp['unique_invoices_2xx_outside_baseline']:,} de ellas fuera de lo que consulta el tráfico normal. "
                + auth_statement(main["campaign_id"], imp, p)
                + " Señales concordantes: "
                + ", ".join(signals)
                + ". Falta para demostrarlo: a quién pertenece cada objeto (ownership) y la identidad autenticada o la "
                "decisión de autorización de la aplicación."
            ),
        }
    return {
        "1_inicio": {
            "primera_actividad_sospechosa": main["first_seen"],
            "primer_acceso_exitoso_2xx": main["exploitation_start"]["ts"] if main["exploitation_start"] else None,
            "ip_primer_acceso": main["exploitation_start"]["source_ip"] if main["exploitation_start"] else None,
            # La primera actividad coincide con el primer registro del log: pudo empezar antes ("a más tardar").
            "inicio_censurado": censored,
            "nota": "Coincide con el inicio del log: la campaña pudo comenzar antes (dato censurado)."
            if censored
            else "La primera actividad es posterior al inicio del log.",
        },
        "2_evidencia_idor": idor,
        "3_alcance_exposicion": {
            "nivel": "impacto confirmado" if corroborated else "exposición potencial (límite superior)",
            "unique_invoices_2xx": imp["unique_invoices_2xx"],
            "invoice_site_pairs_2xx": imp["invoice_site_pairs_2xx"],
            "unique_invoices_2xx_outside_baseline": imp["unique_invoices_2xx_outside_baseline"],
            "accesos_indebidos_confirmados": corr.get("unique_objects_unauthorized") if corroborated else None,
            "nota": (
                f"{p.object_label_plural.capitalize()} distintas entregadas con 2xx a las credenciales de la campaña. "
                + (
                    "La fuente de ownership confirma cuáles eran de otro titular."
                    if corroborated
                    else "Sin ownership NO se sabe cuántas pertenecían a otro titular: es el máximo que pudo quedar "
                    "expuesto, no el número de accesos indebidos."
                )
            ),
        },
        "4_patron_secuencial": {
            "respuesta": "Sí, como cobertura de rangos contiguos (no como peticiones consecutivas +1)",
            "fundamento": (
                "Rangos consultados con éxito: "
                + ", ".join(f"{a}–{b}" for a, b in imp["invoice_id_ranges_2xx"])
                + "; fuera del rango del tráfico normal: "
                + (", ".join(f"{a}–{b}" for a, b in imp["invoice_id_ranges_outside_baseline"]) or "ninguno")
                + f" (primera consulta fuera de rango: {imp['first_request_outside_baseline']})."
            ),
        },
        "5_automatizado": {
            "respuesta": "Sí (alta probabilidad)" if uas or constant else "No concluyente",
            "fundamento": (
                ("User agents de herramientas: " + ", ".join(sorted({u["user_agent"] for u in uas})) if uas else "")
                + (f"; volumen diario exactamente constante en {len(constant)} fase(s)" if constant else "")
            ).strip("; "),
        },
        "6_campanas": {
            "corroboradas": sum(c["status"] == STATUS_CORROBORATED for c in campaigns),
            "alta_confianza": sum(c["status"] == STATUS_HIGH for c in campaigns),
            "por_validar": sum(c["status"] == STATUS_PENDING for c in campaigns),
            "descartadas": sum(c["status"] == STATUS_REFUTED for c in campaigns),
            "detalle": [
                {
                    "campaign_id": c["campaign_id"],
                    "status": c["status"],
                    "status_label": c["status_label"],
                    "ips": len(c["ips"]),
                    "tokens": len(c["tokens"]),
                    "fases": len(c["phases"]),
                    "inicio": c["first_seen"],
                    "fin": c["last_seen"],
                }
                for c in campaigns
            ],
        },
        "7_titulares_potencialmente_expuestos": {
            "limite_superior": imp["unique_invoices_2xx"],
            "por_site_id": imp["unique_invoices_2xx_by_site"],
            "confirmados": corr.get("unique_owners_exposed") if corroborated else None,
            "nota": f"Exposición potencial: supone 1 {p.object_label} = 1 titular; el número real puede ser menor y "
            "solo se confirma con ownership."
            + (
                f" La suma por {p.scope_label} supera el total si el mismo {p.object_param} se consultó en varios "
                f"{p.scope_param}."
                if p.scope_param
                else ""
            ),
        },
        "ttd_dias": metrics.get("ttd_from_first_malicious_request_days"),
    }


def _timeline(
    campaigns: list[dict[str, Any]],
    dataset_start: datetime | None,
    detection: datetime | None,
    profile: IncidentProfile,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if dataset_start:
        events.append({"ts": dataset_start.isoformat(), "event": "Inicio del periodo de logs disponible"})
    for c in campaigns:
        cid, tag = c["campaign_id"], c.get("status_label", c["status"])
        pz = c["patient_zero"]
        events.append(
            {
                "ts": c["first_seen"],
                "campaign_id": cid,
                "event": f"[{tag}] Primera petición (patient zero) desde {pz['source_ip']}, status {pz['status']}",
            }
        )
        for ph in c["phases"][1:]:
            events.append(
                {
                    "ts": ph["start"] + "T00:00:00",
                    "campaign_id": cid,
                    "event": f"[{tag}] Cambio de fase {ph['phase']}: mediana {ph['median_per_day']:.0f} pet./día, "
                    f"éxito {ph['success_ratio']:.0%}",
                }
            )
        if c["exploitation_start"]:
            es = c["exploitation_start"]
            events.append(
                {
                    "ts": es["ts"],
                    "campaign_id": cid,
                    "event": f"[{tag}] Primer acceso exitoso (status {es['status']}) desde {es['source_ip']}",
                }
            )
        for ua in c["user_agents"]:
            events.append(
                {
                    "ts": ua["first_seen"],
                    "campaign_id": cid,
                    "event": f"[{tag}] Primera aparición del UA '{ua['user_agent']}'",
                }
            )
        beyond = c["impact"]["first_request_outside_baseline"]
        if beyond:
            events.append(
                {
                    "ts": beyond,
                    "campaign_id": cid,
                    "event": f"[{tag}] Primera consulta de {profile.object_param} fuera del rango normal",
                }
            )
        events.append({"ts": c["last_seen"], "campaign_id": cid, "event": f"[{tag}] Última actividad registrada"})
    if detection:
        events.append(
            {"ts": detection.isoformat(), "event": "Detección del incidente (fecha indicada por el analista)"}
        )
    return sorted(events, key=lambda e: e["ts"])


def iocs_to_csv(iocs: dict[str, Any]) -> str:
    """Export plano de IOCs para WAF/SIEM. Los tokens van como huella, nunca en claro."""
    import csv
    import io

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["type", "value", "campaign_id", "risk_level", "detail"])
    for ip in iocs["ips"]:
        writer.writerow(["ip", ip["value"], ip["campaign_id"], ip["risk_level"], f"score={ip['risk_score']}"])
    for ua in iocs["user_agents"]:
        writer.writerow(
            ["user_agent", ua["value"], "", "", f"exclusive={ua['exclusive_to_attack']};category={ua['category']}"]
        )
    for tok in iocs["tokens"]:
        writer.writerow(["token_fingerprint", tok["fingerprint"], "", tok["risk_level"], f"hint={tok['hint']}"])
    for pat in iocs["enumeration_patterns"]:
        writer.writerow(["enumeration_pattern", pat["endpoint"], pat["campaign_id"], "", pat["description"]])
    return buffer.getvalue()
