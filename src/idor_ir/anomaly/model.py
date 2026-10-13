"""Detección de anomalías: z-score robusto + Isolation Forest [R5].

Por qué esta combinación (criterio técnico, no complejidad):
- No hay etiquetas de "ataque" en los logs → se necesita un método NO supervisado.
- **z-score robusto (mediana/MAD)**: explicable feature por feature ("15× la mediana de peticiones").
  Usa mediana y MAD en vez de media y desviación estándar porque los propios atacantes inflarían
  la media y esconderían su anomalía. Umbral 3.5 (Iglewicz & Hoaglin, 1993).
- **Isolation Forest**: detecta combinaciones raras de varias features a la vez (p. ej. volumen
  moderado + user agent de herramienta + muchos IDs contiguos), que un umbral por feature no ve.
  Es barato (miles de actores, < 1 s) y no requiere escalar las variables.
El score final combina ambos con reglas explícitas (ver `detection/scoring.py`).
"""

from __future__ import annotations

import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest

ROBUST_Z_THRESHOLD = 3.5
_MAD_CONSTANT = 0.6745  # hace el MAD comparable con la desviación estándar en datos normales

# Features que alimentan el Isolation Forest. Conteos en log1p para reducir el efecto de la escala.
MODEL_FEATURES: tuple[str, ...] = (
    "log_requests_per_source_day",
    "log_invoices_per_source_day",
    "success_ratio",
    "client_error_ratio",
    "automation_ratio",
    "invoice_density",
    "log_unique_tokens",
    "log_unique_ips",
    "log_unique_user_agents",
)


def robust_z(values: pl.Series, reference: pl.Series | None = None) -> pl.Series:
    """z-score robusto. Si el MAD es 0 (datos casi constantes) usa la desviación media absoluta.

    Con `reference`, la mediana y el MAD salen de esa ventana (línea base) y no de los datos evaluados: así el
    atacante no participa en su propia normalización (validación fuera de muestra)."""
    x = values.cast(pl.Float64).fill_null(0.0).to_numpy()
    if x.size == 0:
        return pl.Series(values.name, [], dtype=pl.Float64)
    ref = x if reference is None else reference.cast(pl.Float64).fill_null(0.0).to_numpy()
    median = float(np.median(ref))
    deviation = np.abs(ref - median)
    mad = float(np.median(deviation))
    if mad > 0:
        z = _MAD_CONSTANT * (x - median) / mad
    else:
        mean_abs = float(deviation.mean())
        z = (x - median) / (1.2533 * mean_abs) if mean_abs > 0 else np.zeros_like(x)
    return pl.Series(values.name, z)


def add_model_columns(features: pl.DataFrame, reference: pl.DataFrame | None = None) -> pl.DataFrame:
    """Agrega columnas log1p y z-scores robustos de intensidad de volumen y de enumeración."""
    ref = reference
    return features.with_columns(
        log_requests_per_source_day=pl.col("requests_per_source_day").log1p(),
        log_invoices_per_source_day=pl.col("invoices_per_source_day").log1p(),
        log_unique_tokens=pl.col("unique_tokens").log1p(),
        log_unique_ips=pl.col("unique_ips").log1p(),
        log_unique_user_agents=pl.col("unique_user_agents").log1p(),
        z_requests=robust_z(
            features["requests_per_source_day"], None if ref is None else ref["requests_per_source_day"]
        ),
        z_unique_invoices=robust_z(
            features["invoices_per_source_day"], None if ref is None else ref["invoices_per_source_day"]
        ),
    )


def isolation_forest_scores(
    features: pl.DataFrame, random_state: int = 42, reference: pl.DataFrame | None = None
) -> pl.Series:
    """Score de anomalía normalizado a [0, 1] (1 = más anómalo). Determinista por `random_state`.

    Sin `reference` (análisis forense de un único log) el bosque se ajusta y evalúa sobre los mismos actores:
    es un ranking relativo, no una probabilidad. Con `reference` (ventana de línea base, ya con las columnas de
    `add_model_columns`) se ajusta ahí y se evalúa fuera de muestra; la escala usa el rango de la referencia."""
    train = features if reference is None else reference
    if train.height < 8 or features.height == 0:  # muy pocos actores para un bosque útil
        return pl.Series("if_score", [0.0] * features.height)
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=random_state)
    model.fit(train.select(MODEL_FEATURES).fill_null(0.0).to_numpy())
    raw = -model.score_samples(features.select(MODEL_FEATURES).fill_null(0.0).to_numpy())  # mayor = más anómalo
    base = raw if reference is None else -model.score_samples(train.select(MODEL_FEATURES).fill_null(0.0).to_numpy())
    low, high = float(base.min()), float(base.max())
    span = high - low
    normalized = np.clip((raw - low) / span, 0.0, 1.0) if span > 0 else np.zeros_like(raw)
    return pl.Series("if_score", normalized)
