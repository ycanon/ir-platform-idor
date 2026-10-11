"""Métricas generales del tráfico exigidas por el reto [R3]:
requests por IP, distribución temporal y tasa de error (403/401 vs 200).
"""

from __future__ import annotations

from typing import Any, cast

import polars as pl


def traffic_metrics(lf: pl.LazyFrame, top_n: int = 20) -> dict[str, Any]:
    """Calcula las métricas en una sola ejecución streaming y devuelve un dict serializable."""
    per_ip = lf.group_by("source_ip").agg(requests=pl.len())
    per_day = lf.group_by(day=pl.col("ts").dt.date()).agg(requests=pl.len()).sort("day")
    per_hour = lf.group_by(hour=pl.col("ts").dt.hour()).agg(requests=pl.len()).sort("hour")
    status = lf.select(
        total=pl.len(),
        s200=(pl.col("status") == 200).sum(),
        s2xx=pl.col("status").is_between(200, 299).sum(),
        s401=(pl.col("status") == 401).sum(),
        s403=(pl.col("status") == 403).sum(),
        s4xx=pl.col("status").is_between(400, 499).sum(),
    )
    per_ip_df, day_df, hour_df, status_df = pl.collect_all([per_ip, per_day, per_hour, status], engine="streaming")

    s = status_df.row(0, named=True)
    total = max(int(s["total"]), 1)
    desc = per_ip_df["requests"]
    return {
        "requests_per_ip": {
            "ips": per_ip_df.height,
            "mean": round(cast(float, desc.mean() or 0), 1),
            "median": cast(float, desc.median() or 0),
            "p95": float(desc.quantile(0.95) or 0),
            "max": int(desc.max() or 0),  # type: ignore[arg-type]
            "top": [
                {"ip": r["source_ip"], "requests": int(r["requests"])}
                for r in per_ip_df.sort("requests", descending=True).head(top_n).iter_rows(named=True)
            ],
        },
        "temporal": {
            "per_day": [{"day": str(r["day"]), "requests": int(r["requests"])} for r in day_df.iter_rows(named=True)],
            "per_hour": [
                {"hour": int(r["hour"]), "requests": int(r["requests"])} for r in hour_df.iter_rows(named=True)
            ],
        },
        "error_rates": {
            "count_200": int(s["s200"]),
            "count_401": int(s["s401"]),
            "count_403": int(s["s403"]),
            "ratio_401_403_vs_200": round((int(s["s401"]) + int(s["s403"])) / max(int(s["s200"]), 1), 4),
            "ratio_2xx": round(int(s["s2xx"]) / total, 4),
            "ratio_4xx": round(int(s["s4xx"]) / total, 4),
        },
    }
