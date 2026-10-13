"""Validación del detector con un banco SINTÉTICO etiquetado: precisión, recall, falsos positivos y umbrales.

Por qué existe: el log del reto no trae etiquetas (no se sabe qué actor era atacante), así que el score de riesgo
no puede medirse contra él. Este módulo genera tráfico con la verdad conocida y mide el detector igual que se
mediría con incidentes etiquetados o con un ejercicio de red team reproducido en el log:

- Normales (negativos): usuarios con navegador que consultan SUS objetos, NAT corporativas (muchos usuarios
  detrás de una IP), integraciones legítimas con cliente de API (python-requests) sobre bloques propios y
  monitores (curl) que consultan siempre el mismo objeto. Estos tres últimos son los falsos positivos típicos.
- Atacantes (positivos), varios estilos: herramienta rápida y secuencial, navegador lento ("low and slow"),
  IPs rotativas con una sola credencial, IDs aleatorios (no contiguos) con navegador y herramienta con muchos
  rechazos 403/404.

Se comparan cuatro variantes, a nivel de actor IP y de actor credencial:
- `produccion_en_muestra`: reglas + Isolation Forest ajustado y evaluado sobre el mismo log (lo que hace hoy el
  análisis forense de un único archivo; es un ranking relativo).
- `linea_base_separada`: mediana/MAD e Isolation Forest ajustados con OTRA ventana (otra semilla, sin ataque) y
  evaluados fuera de muestra (cómo debería operar la detección continua).
- `solo_reglas`: sin el término del modelo (peso 0).
- `solo_isolation_forest`: el if_score (0-100) como único criterio.

Para cada variante: TP/FP/FN/TN, precisión, recall, FPR y F1 por umbral (barrido de 5 en 5), los umbrales de
nivel (medio 30, alto 50, crítico 70), el umbral calibrado (el menor con FPR <= objetivo) y el recall por estilo
de ataque. Limitación declarada: un banco sintético valida la mecánica y expone puntos ciegos; NO estima la
precisión en producción. Esa calibración exige etiquetas reales (incidentes cerrados, red team, ownership).
"""

from __future__ import annotations

import json
import random
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import polars as pl

from idor_ir.detection.features import ActorKey, actor_features
from idor_ir.detection.scoring import ScoringParams, score_actors

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/87.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/14.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]
ATTACK_STYLES = (
    "herramienta_rapida_secuencial",
    "navegador_lento_secuencial",
    "ips_rotativas_un_token",
    "ids_aleatorios_navegador",
    "herramienta_con_rechazos",
)
NEGATIVE_KINDS = ("usuario", "nat_corporativa", "integracion_api", "monitor")
LEVEL_THRESHOLDS = {"medio": 30.0, "alto": 50.0, "critico": 70.0}
VARIANTS = ("produccion_en_muestra", "linea_base_separada", "solo_reglas", "solo_isolation_forest")
_START = datetime(2020, 10, 1, tzinfo=UTC).replace(tzinfo=None)
_OBJECT_SPACE = 2_000_000


@dataclass
class Benchmark:
    rows: pl.DataFrame
    labels: dict[ActorKey, dict[str, str]] = field(default_factory=dict)  # actor -> estilo o tipo normal


class _Gen:
    def __init__(self, seed: int, days: int) -> None:
        self.rng = random.Random(seed)  # noqa: S311 - datos sintéticos, no criptografía
        self.days = days
        self.rows: list[tuple[datetime, int, str, str, str, int, str]] = []
        self.ip_label: dict[str, str] = {}
        self.tok_label: dict[str, str] = {}
        self._ip = 0

    def ip(self, prefix: str = "10") -> str:
        self._ip += 1
        return f"{prefix}.{self._ip // 65536 % 256}.{self._ip // 256 % 256}.{self._ip % 256}"

    def ts(self, day: int | None = None) -> datetime:
        d = self.rng.randrange(self.days) if day is None else day
        return _START + timedelta(days=d, minutes=self.rng.randrange(1440))

    def add(self, ts: datetime, status: int, ip: str, token: str, ua: str, obj: int, site: str = "S1") -> None:
        self.rows.append((ts, status, ip, token, ua, obj, site))

    def owned(self, n: int, contiguous: bool = False) -> list[int]:
        if contiguous:
            start = self.rng.randrange(_OBJECT_SPACE - n)
            return list(range(start, start + n))
        return self.rng.sample(range(_OBJECT_SPACE), n)


def _normal_traffic(g: _Gen, users: int) -> None:
    rng = g.rng
    for u in range(users):  # usuarios con navegador, una IP cada uno
        ip, tok, ua = g.ip(), f"U{u}", rng.choice(BROWSERS)
        objs = g.owned(rng.randint(3, 40))
        for _ in range(rng.randint(10, 160)):
            g.add(g.ts(), rng.choices([200, 304, 404], [85, 12, 3])[0], ip, tok, ua, rng.choice(objs))
        g.ip_label[ip], g.tok_label[tok] = "usuario", "usuario"
    for n in range(max(2, users // 60)):  # NAT corporativa: 25 usuarios detrás de una IP
        ip = g.ip("172")
        g.ip_label[ip] = "nat_corporativa"
        for k in range(25):
            tok, ua = f"N{n}_{k}", rng.choice(BROWSERS)
            objs = g.owned(rng.randint(5, 40))
            for _ in range(rng.randint(30, 160)):
                g.add(g.ts(), rng.choices([200, 304], [88, 12])[0], ip, tok, ua, rng.choice(objs))
            g.tok_label[tok] = "nat_corporativa"
    for n in range(max(2, users // 50)):  # integración ERP: cliente de API sobre un bloque PROPIO contiguo
        ip, tok = g.ip("192"), f"API{n}"
        objs = g.owned(rng.randint(300, 900), contiguous=True)
        for _ in range(rng.randint(1500, 4000)):
            g.add(g.ts(), 200, ip, tok, "python-requests/2.25.1", rng.choice(objs))
        g.ip_label[ip], g.tok_label[tok] = "integracion_api", "integracion_api"
    for n in range(2):  # monitor de disponibilidad: curl al mismo objeto cada pocos minutos
        ip, tok, obj = g.ip("192"), f"MON{n}", g.owned(1)[0]
        for _ in range(rng.randint(2000, 3000)):
            g.add(g.ts(), 200, ip, tok, "curl/7.68.0", obj)
        g.ip_label[ip], g.tok_label[tok] = "monitor", "monitor"


def _attacks(g: _Gen) -> None:
    rng = g.rng

    def mark(ip: str, tok: str, style: str) -> None:
        g.ip_label[ip], g.tok_label[tok] = style, style

    # 1) herramienta rápida y secuencial: 3.000 IDs en 3 días
    ip, tok, start = g.ip("203"), "X1", rng.randrange(_OBJECT_SPACE - 5000)
    for i in range(3000):
        g.add(g.ts(rng.randrange(3)), rng.choices([200, 404], [80, 20])[0], ip, tok, "Scrapy/2.4.1", start + i)
    mark(ip, tok, ATTACK_STYLES[0])
    # 2) navegador lento: 40 IDs/día durante toda la ventana
    ip, tok, start, ua = g.ip("203"), "X2", rng.randrange(_OBJECT_SPACE - 5000), rng.choice(BROWSERS)
    for i in range(40 * g.days):
        g.add(g.ts(i // 40), 200, ip, tok, ua, start + i)
    mark(ip, tok, ATTACK_STYLES[1])
    # 3) 20 IPs rotativas, un solo token, ~60 IDs secuenciales cada una
    tok, start = "X3", rng.randrange(_OBJECT_SPACE - 5000)
    for k in range(20):
        ip, ua = g.ip("198"), rng.choice(BROWSERS)
        for i in range(60):
            g.add(g.ts(), 200, ip, tok, ua, start + k * 60 + i)
        mark(ip, tok, ATTACK_STYLES[2])
    # 4) IDs aleatorios (no contiguos) con navegador: 800 en 5 días
    ip, tok, ua = g.ip("203"), "X4", rng.choice(BROWSERS)
    for obj in g.owned(800):
        g.add(g.ts(rng.randrange(5)), rng.choices([200, 404], [70, 30])[0], ip, tok, ua, obj)
    mark(ip, tok, ATTACK_STYLES[3])
    # 5) herramienta con muchos rechazos (el endpoint a veces sí valida): 1.500 IDs, 60 % 403
    ip, tok, start = g.ip("203"), "X5", rng.randrange(_OBJECT_SPACE - 5000)
    for i in range(1500):
        g.add(g.ts(rng.randrange(7)), rng.choices([200, 403, 404], [30, 60, 10])[0], ip, tok,
              "python-requests/2.25.1", start + i)  # fmt: skip
    mark(ip, tok, ATTACK_STYLES[4])


def generate(seed: int = 7, users: int = 400, days: int = 28, attacks: bool = True) -> Benchmark:
    """Genera un log sintético con la verdad conocida (etiqueta por IP y por credencial)."""
    g = _Gen(seed, days)
    _normal_traffic(g, users)
    if attacks:
        _attacks(g)
    df = pl.DataFrame(
        g.rows,
        schema={"ts": pl.Datetime, "status": pl.Int64, "source_ip": pl.String, "authtoken": pl.String,
                "http_user_agent": pl.String, "invoice_id_num": pl.Int64, "site_id": pl.String},
        orient="row",
    )  # fmt: skip
    return Benchmark(rows=df, labels={"source_ip": g.ip_label, "authtoken": g.tok_label})


def _scores(bench: Benchmark, key: ActorKey, variant: str, reference: pl.DataFrame | None) -> pl.DataFrame:
    feats = actor_features(bench.rows.lazy(), key)
    if variant == "solo_reglas":
        scored = score_actors(feats, ScoringParams(weight_model=0))
    elif variant == "linea_base_separada":
        scored = score_actors(feats, reference=reference)
    else:
        scored = score_actors(feats)
    if variant == "solo_isolation_forest":
        scored = scored.with_columns(risk_score=(pl.col("if_score") * 100).round(1))
    return scored.select("actor", "risk_score")


def _confusion(scores: list[tuple[float, bool]], threshold: float) -> dict[str, Any]:
    tp = sum(1 for s, y in scores if y and s >= threshold)
    fp = sum(1 for s, y in scores if not y and s >= threshold)
    fn = sum(1 for s, y in scores if y and s < threshold)
    tn = sum(1 for s, y in scores if not y and s < threshold)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else 0.0
    return {
        "threshold": threshold, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": None if precision is None else round(precision, 3),
        "recall": None if recall is None else round(recall, 3),
        "fpr": round(fp / (fp + tn), 4) if fp + tn else None,
        "f1": round(f1, 3),
    }  # fmt: skip


def evaluate(
    seed: int = 7, baseline_seed: int = 1007, users: int = 400, days: int = 28, target_fpr: float = 0.01
) -> dict[str, Any]:
    """Mide el detector en un banco etiquetado. La línea base es otra ventana (otra semilla) SIN ataque."""
    bench = generate(seed, users, days)
    baseline = generate(baseline_seed, users, days, attacks=False)
    out: dict[str, Any] = {"seed": seed, "baseline_seed": baseline_seed, "rows": bench.rows.height, "keys": {}}
    for key in ("source_ip", "authtoken"):
        labels = bench.labels[key]
        reference = actor_features(baseline.rows.lazy(), key)
        positives = Counter(v for v in labels.values() if v in ATTACK_STYLES)
        res: dict[str, Any] = {
            "actors": len(labels), "positives": sum(positives.values()), "positives_by_style": dict(positives),
            "variants": {},
        }  # fmt: skip
        for variant in VARIANTS:
            scored = _scores(bench, key, variant, reference)
            pairs = [
                (float(r["risk_score"]), labels.get(r["actor"]) in ATTACK_STYLES) for r in scored.iter_rows(named=True)
            ]
            curve = [_confusion(pairs, float(t)) for t in range(5, 100, 5)]
            calibrated = next((c for c in curve if c["fpr"] is not None and c["fpr"] <= target_fpr), None)
            at_level = {lv: _confusion(pairs, t) for lv, t in LEVEL_THRESHOLDS.items()}
            by_style: dict[str, Any] = {}
            score_of = {r["actor"]: float(r["risk_score"]) for r in scored.iter_rows(named=True)}
            for style in ATTACK_STYLES:
                actors = [a for a, v in labels.items() if v == style]
                hit = sum(1 for a in actors if score_of.get(a, 0.0) >= LEVEL_THRESHOLDS["medio"])
                by_style[style] = {"actors": len(actors), "detected_at_medio": hit,
                                   "recall_at_medio": round(hit / len(actors), 3) if actors else None}  # fmt: skip
            fps = Counter(
                labels.get(a, "?") for a, s in score_of.items()
                if s >= LEVEL_THRESHOLDS["medio"] and labels.get(a) not in ATTACK_STYLES
            )  # fmt: skip
            res["variants"][variant] = {
                "at_level": at_level, "curve": curve, "calibrated": calibrated,
                "recall_by_style_at_medio": by_style, "false_positives_by_kind_at_medio": dict(fps),
            }  # fmt: skip
        out["keys"][key] = res
    return out


def validate(
    seeds: int = 3, users: int = 400, days: int = 28, target_fpr: float = 0.01, workdir: Path | None = None
) -> dict[str, Any]:
    """Repite la evaluación con varias semillas y resume (media y peor caso) en el umbral de nivel medio.

    Con `workdir` también ejecuta la tubería completa por semilla y mide la capa de campañas."""
    runs = [evaluate(seed=7 + i, baseline_seed=1007 + i, users=users, days=days, target_fpr=target_fpr)
            for i in range(seeds)]  # fmt: skip
    summary: dict[str, Any] = {}
    for key in ("source_ip", "authtoken"):
        summary[key] = {}
        for variant in VARIANTS:
            levels = [r["keys"][key]["variants"][variant]["at_level"]["medio"] for r in runs]
            cal = [r["keys"][key]["variants"][variant]["calibrated"] for r in runs]

            def stats(values: list[float | None]) -> dict[str, float | None]:
                v = [x for x in values if x is not None]
                return {"mean": round(sum(v) / len(v), 3) if v else None, "worst": None}

            prec = stats([lv["precision"] for lv in levels])
            rec = stats([lv["recall"] for lv in levels])
            fpr = stats([lv["fpr"] for lv in levels])
            prec["worst"] = min((lv["precision"] for lv in levels if lv["precision"] is not None), default=None)
            rec["worst"] = min((lv["recall"] for lv in levels if lv["recall"] is not None), default=None)
            fpr["worst"] = max((lv["fpr"] for lv in levels if lv["fpr"] is not None), default=None)
            summary[key][variant] = {
                "precision_at_medio": prec, "recall_at_medio": rec, "fpr_at_medio": fpr,
                "calibrated_thresholds": [
                    {"threshold": c["threshold"], "precision": c["precision"], "recall": c["recall"]} if c else None
                    for c in cal
                ],
            }  # fmt: skip
    campaign_runs = (
        [evaluate_campaigns(workdir / f"seed_{7 + i}", 7 + i, users, days) for i in range(seeds)] if workdir else []
    )
    campaigns_summary = None
    if campaign_runs:
        precisions = [r["priority_precision"] for r in campaign_runs if r["priority_precision"] is not None]
        campaigns_summary = {
            "priority_precision_mean": round(sum(precisions) / len(precisions), 3) if precisions else None,
            "styles_in_priority_campaign_per_seed": [
                len(r["attack_styles_in_priority_campaign"]) for r in campaign_runs
            ],
            "styles_missed_entirely": sorted({s for r in campaign_runs for s in r["attack_styles_missed"]}),
            "false_campaigns_per_seed": [len(r["false_campaigns"]) for r in campaign_runs],
            "false_campaigns_in_priority": sum(
                1
                for r in campaign_runs
                for c in r["false_campaigns"]
                if c["status"] in ("alta_confianza", "corroborada")
            ),
            "attack_styles": len(ATTACK_STYLES),
        }
    return {
        "benchmark": "sintetico_etiquetado/v1",
        "parameters": {
            "seeds": seeds,
            "users": users,
            "days": days,
            "target_fpr": target_fpr,
            "attack_styles": list(ATTACK_STYLES),
            "negative_kinds": list(NEGATIVE_KINDS),
            "level_thresholds": LEVEL_THRESHOLDS,
        },  # fmt: skip
        "summary_at_medio": summary,
        "campaign_layer": campaigns_summary,
        "runs": runs,
        "campaign_runs": campaign_runs,
        "limitations": [
            "Banco sintético: valida la mecánica del detector y expone puntos ciegos por estilo de ataque; no estima "
            "la precisión real en producción.",
            "La calibración real exige etiquetas: incidentes cerrados, ejercicios de red team reproducidos en el log o "
            "corroboración con ownership/logs de autorización.",
            "El umbral calibrado depende de la mezcla de tráfico; debe recalcularse por endpoint y revisarse "
            "periódicamente (deriva).",
        ],
    }


# ---------------------------------------------------------------------------------------------- capa de campañas
_CSV_HEADER = "timestamp,http_status,http_host,http_uri,http_method,http_referer,http_user_agent,source_ip"


def to_csv(bench: Benchmark, path: Path) -> Path:
    """Escribe el banco con el formato de log del reto (para ejecutar la tubería completa)."""
    df = bench.rows.select(
        timestamp=pl.col("ts").dt.strftime("%Y-%m-%d %H:%M:%S"),
        http_status=pl.col("status"),
        http_host=pl.lit("app.test"),
        http_uri=pl.format(
            "/invoices/search?invoice_id={}&site_id={}&authtoken={}", "invoice_id_num", "site_id", "authtoken"
        ),
        http_method=pl.lit("GET"),
        http_referer=pl.lit("-"),
        http_user_agent=pl.col("http_user_agent"),
        source_ip=pl.col("source_ip"),
    )
    df.write_csv(path)
    return path


def evaluate_campaigns(workdir: Path, seed: int = 7, users: int = 400, days: int = 28) -> dict[str, Any]:
    """Ejecuta la tubería completa y mide la capa que guía la respuesta: el estado de cada campaña.

    Una campaña es verdadera si la mayoría de sus IPs son atacantes. Se reporta qué estilos de ataque quedan en
    una campaña priorizada (hipótesis de alta confianza) y qué normales llegan a campaña (falsos positivos)."""
    from idor_ir.config import Settings  # import diferido: evita ciclo config → detección
    from idor_ir.pipeline import run_analysis

    bench = generate(seed, users, days)
    workdir.mkdir(parents=True, exist_ok=True)
    source = to_csv(bench, workdir / f"benchmark_{seed}.csv")
    settings = Settings(output_dir=workdir / "out", data_dir=workdir, timestamp_format="%Y-%m-%d %H:%M:%S")
    run = run_analysis(source, settings)
    evidence = json.loads((run.run_dir / "evidence.json").read_text(encoding="utf-8"))
    labels = bench.labels["source_ip"]
    campaigns = []
    for c in evidence.get("campaigns", []):
        kinds = Counter(labels.get(ip, "?") for ip in c["ips"])
        attack = sum(n for k, n in kinds.items() if k in ATTACK_STYLES)
        campaigns.append({
            "campaign_id": c["campaign_id"], "status": c["status"], "ips": len(c["ips"]),
            "composition": dict(kinds), "is_attack": attack * 2 > len(c["ips"]),
        })  # fmt: skip
    priority = [c for c in campaigns if c["status"] in ("alta_confianza", "corroborada")]
    styles_in_priority = sorted({k for c in priority for k in c["composition"] if k in ATTACK_STYLES})
    styles_any = sorted({k for c in campaigns for k in c["composition"] if k in ATTACK_STYLES})
    return {
        "seed": seed,
        "campaigns": campaigns,
        "priority_campaigns": len(priority),
        "priority_precision": round(sum(c["is_attack"] for c in priority) / len(priority), 3) if priority else None,
        "attack_styles_in_priority_campaign": styles_in_priority,
        "attack_styles_in_any_campaign": styles_any,
        "attack_styles_missed": sorted(set(ATTACK_STYLES) - set(styles_any)),
        "false_campaigns": [c for c in campaigns if not c["is_attack"]],
    }
