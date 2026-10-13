"""Niveles de evidencia y estados de campaña: separa señal, hipótesis, corroboración e impacto confirmado.

Por qué existe: el log HTTP del reto NO contiene el propietario de cada objeto, la identidad autenticada ni la
decisión de autorización de la aplicación. Con esos datos se puede sostener un patrón COMPATIBLE con enumeración
y abuso de autorización (IDOR), pero no DEMOSTRARLO ni contar víctimas. Este módulo fija el vocabulario para que
ningún artefacto (evidencia, agentes, interfaz, reportes) convierta un indicador en una conclusión confirmada.

Escala:
1. Señal          actor con comportamiento anómalo (score de riesgo >= medio).
2. Hipótesis      campaña formada por señales concordantes (grafo IP↔credencial). Confianza alta o por validar.
3. Corroboración  una fuente independiente de la aplicación (ownership, logs de autorización) confirma o refuta.
4. Impacto        solo con corroboración: objetos entregados a quien NO era su titular.
"""

from __future__ import annotations

from typing import Any

STATUS_CORROBORATED = "corroborada"
STATUS_HIGH = "alta_confianza"
STATUS_PENDING = "por_validar"
STATUS_REFUTED = "descartada"
# Runs antiguos (antes de esta escala) usaban "confirmada": se lee como hipótesis de alta confianza.
LEGACY_CONFIRMED = "confirmada"

PRIORITY_STATUSES = frozenset({STATUS_CORROBORATED, STATUS_HIGH, LEGACY_CONFIRMED})

STATUS_LABELS = {
    STATUS_CORROBORATED: "corroborada (impacto confirmado con fuente de la aplicación)",
    STATUS_HIGH: "hipótesis de alta confianza (sin corroborar)",
    STATUS_PENDING: "por validar",
    STATUS_REFUTED: "descartada por la fuente de corroboración",
    LEGACY_CONFIRMED: "hipótesis de alta confianza (sin corroborar)",
}

EVIDENCE_SCALE = ["señal", "hipótesis", "corroboración", "impacto confirmado"]

# Lo que el log NO permite afirmar (se repite en evidencia, agentes y reportes).
LOG_LIMITATIONS = [
    "El log no contiene el propietario (titular) de cada objeto: no se puede saber si el objeto pertenecía a la "
    "cuenta que lo pidió.",
    "El log no registra la identidad autenticada ni la decisión de autorización de la aplicación; un status 2xx "
    "solo indica que el servidor respondió con éxito.",
    "Por eso los conteos de objetos con respuesta 2xx son EXPOSICIÓN POTENCIAL (límite superior), no accesos "
    "indebidos ni víctimas confirmadas.",
]

CORROBORATION_SOURCES = [
    "Ownership: exportación de la base de datos de la aplicación (objeto → titular) para cruzarla con la "
    "credencial usada.",
    "Logs de la aplicación: usuario autenticado y decisión de autorización por objeto (allow/deny) en el endpoint.",
    "Proveedor de identidad: credencial → usuario, sesiones y origen (para atribuir las credenciales).",
    "Reproducción controlada: dos cuentas de prueba en un entorno aislado confirman si el endpoint valida la "
    "propiedad del objeto.",
]


def is_priority(campaign: dict[str, Any]) -> bool:
    """Campaña que guía la respuesta: corroborada o hipótesis de alta confianza."""
    return campaign.get("status") in PRIORITY_STATUSES


def status_label(status: str | None) -> str:
    return STATUS_LABELS.get(status or "", status or "desconocido")
