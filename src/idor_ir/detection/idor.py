"""Detector IDOR sobre el endpoint y los parámetros del perfil del incidente [Reto §2, R2, R5].

En el reto: `GET /invoices/search?invoice_id&site_id&authtoken`. El endpoint viene del perfil de cada ejecución
(antes quedaba fijo al registrar el detector y la configuración `IRP_TARGET_ENDPOINT` no se aplicaba).

Aplica el mismo análisis a dos tipos de actor:
- `source_ip`  (exigido por el reto: volumen anómalo por IP, Top 20 IPs)
- `authtoken`  (IDOR = una cuenta legítima pidiendo objetos de otros; el token identifica la cuenta)
Las subredes /24 no se puntúan como actor (una /24 con cientos de IPs legítimas genera falsos
positivos); se usan en la evidencia para agrupar IPs sospechosas que actúan juntas.
"""

from __future__ import annotations

import polars as pl

from idor_ir.detection.base import DetectionResult, register
from idor_ir.detection.features import ActorKey, actor_features
from idor_ir.detection.scoring import ScoringParams, score_actors
from idor_ir.profile import IncidentProfile

ACTOR_KEYS: tuple[ActorKey, ...] = ("source_ip", "authtoken")


class IdorDetector:
    name = "idor"
    description = "Enumeración de identificadores de objeto con credenciales (IDOR) en el endpoint del perfil"

    def __init__(self, params: ScoringParams | None = None) -> None:
        self.params = params or ScoringParams()

    def run(self, lf: pl.LazyFrame, profile: IncidentProfile | None = None) -> DetectionResult:
        profile = profile or IncidentProfile()
        # Solo el endpoint afectado y peticiones con identificador numérico (las demás no pueden ser IDOR aquí).
        scoped = lf.filter((pl.col("path") == profile.endpoint) & pl.col("invoice_id_num").is_not_null())
        actors: dict[str, pl.DataFrame] = {
            key: score_actors(actor_features(scoped, key), self.params) for key in ACTOR_KEYS
        }
        return DetectionResult(
            detector=self.name,
            actors=actors,
            parameters={
                "target_endpoint": profile.endpoint,
                "object_param": profile.object_param,
                **self.params.as_dict(),
            },
        )


register(IdorDetector())
