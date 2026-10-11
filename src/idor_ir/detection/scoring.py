"""Risk scoring explicable (0-100) por actor [R2, R5].

Cada punto del score tiene una razón legible, para que el analista (y el agente de triage)
sepa POR QUÉ un actor es sospechoso. Pesos:

| Señal (patrón IDOR del reto)                        | Puntos | Condición                                   |
|-----------------------------------------------------|--------|---------------------------------------------|
| Volumen anómalo                                     | 20     | z robusto de peticiones/fuente/día >= 3.5   |
| Enumeración masiva                                  | 20     | z robusto de IDs únicos/fuente/día >= 3.5   |
| Acceso a rango contiguo de IDs ("secuencial")       | 15     | enumeración + densidad >= 0.5 (>= 100 IDs)  |
| Automatización (bot)                                | 0-25   | proporcional a % de UA de herramientas      |
| Isolation Forest (combinación rara de features)     | 0-20   | proporcional al score normalizado           |

Los umbrales son parámetros (no constantes mágicas) y se registran en el manifiesto.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

import polars as pl

from idor_ir.anomaly.model import ROBUST_Z_THRESHOLD, add_model_columns, isolation_forest_scores


@dataclass(frozen=True)
class ScoringParams:
    z_threshold: float = ROBUST_Z_THRESHOLD
    density_threshold: float = 0.5
    min_invoices_for_density: int = 100
    automation_full_ratio: float = 0.5  # con >= 50 % de peticiones automatizadas se otorgan los 25 puntos
    automation_flag_ratio: float = 0.2  # desde 20 % se marca "posible automatización"
    weight_volume: float = 20
    weight_enumeration: float = 20
    weight_density: float = 15
    weight_automation: float = 25
    weight_model: float = 20

    def as_dict(self) -> dict[str, float | int]:
        return asdict(self)


def risk_level(score: float) -> str:
    if score >= 70:
        return "critico"
    if score >= 50:
        return "alto"
    if score >= 30:
        return "medio"
    return "bajo"


def score_actors(features: pl.DataFrame, params: ScoringParams | None = None) -> pl.DataFrame:
    """Agrega z-scores, score del modelo, puntos por regla, risk_score, nivel y razones."""
    p = params or ScoringParams()
    df = add_model_columns(features)
    df = df.with_columns(isolation_forest_scores(df))

    df = df.with_columns(
        rule_volume=pl.col("z_requests") >= p.z_threshold,
        rule_enumeration=pl.col("z_unique_invoices") >= p.z_threshold,
        # La contigüidad solo suma si además hay enumeración anómala: muchos IDs vecinos también
        # aparecen por azar cuando un actor legítimo consulta mucho durante meses.
        rule_contiguous=(pl.col("invoice_density") >= p.density_threshold)
        & (pl.col("unique_invoices") >= p.min_invoices_for_density)
        & (pl.col("z_unique_invoices") >= p.z_threshold),
        possible_bot=pl.col("automation_ratio") >= p.automation_flag_ratio,
    ).with_columns(
        risk_score=(
            pl.col("rule_volume").cast(pl.Float64) * p.weight_volume
            + pl.col("rule_enumeration").cast(pl.Float64) * p.weight_enumeration
            + pl.col("rule_contiguous").cast(pl.Float64) * p.weight_density
            + (pl.col("automation_ratio") / p.automation_full_ratio).clip(0, 1) * p.weight_automation
            + pl.col("if_score") * p.weight_model
        ).round(1)
    )

    reasons = [_reasons(row, p) for row in df.iter_rows(named=True)]
    return df.with_columns(
        risk_level=pl.col("risk_score").map_elements(risk_level, return_dtype=pl.String),
        reasons=pl.Series(reasons, dtype=pl.List(pl.String)),
    ).sort("risk_score", descending=True)


def _reasons(row: dict[str, object], p: ScoringParams) -> list[str]:
    """Explicaciones en lenguaje natural de los puntos obtenidos."""
    out: list[str] = []
    if row["rule_volume"]:
        per_day = float(row["requests_per_source_day"])  # type: ignore[arg-type]
        out.append(
            f"Volumen anómalo: {row['requests']:,} peticiones, {per_day:.1f} por fuente-día "
            f"(z robusto {row['z_requests']:.1f})"
        )
    if row["rule_enumeration"]:
        out.append(
            f"Enumeración masiva: {row['unique_invoices']:,} IDs de objeto distintos (z {row['z_unique_invoices']:.1f})"
        )
    if row["rule_contiguous"]:
        out.append(f"Rango contiguo de IDs: densidad {float(row['invoice_density']):.0%}")  # type: ignore[arg-type]
    if row["possible_bot"]:
        out.append(f"Posible automatización: {float(row['automation_ratio']):.0%} de peticiones con UA de herramienta")  # type: ignore[arg-type]
    if float(row["if_score"]) >= 0.6:  # type: ignore[arg-type]
        out.append(f"Isolation Forest: comportamiento atípico (score {float(row['if_score']):.2f})")  # type: ignore[arg-type]
    return out
