"""Contrato común de los detectores y registro para extender a otros ataques.

Cómo agregar un detector nuevo (p. ej. fuerza bruta de tokens) sin tocar el pipeline:
1. Crear una clase con `name`, `description` y `run(lf, profile) -> DetectionResult`.
2. Registrarla con `register(MiDetector())`.
El pipeline ejecuta todos los detectores registrados. En el MVP solo existe `idor`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

import polars as pl

from idor_ir.profile import IncidentProfile


@dataclass
class DetectionResult:
    """Salida de un detector: tablas de actores puntuados + parámetros usados."""

    detector: str
    actors: dict[str, pl.DataFrame]  # p. ej. {"source_ip": df, "authtoken": df, "subnet24": df}
    parameters: dict[str, Any] = field(default_factory=dict)


class Detector(Protocol):
    name: str
    description: str

    def run(self, lf: pl.LazyFrame, profile: IncidentProfile) -> DetectionResult: ...


_REGISTRY: dict[str, Detector] = {}


def register(detector: Detector) -> None:
    _REGISTRY[detector.name] = detector


def registered() -> dict[str, Detector]:
    return dict(_REGISTRY)
