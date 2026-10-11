"""Métricas Prometheus expuestas en /metrics (requisito de observabilidad del reto).

Permiten verificar desde fuera que la solución funcionó: cuántos análisis se ejecutaron y cuánto
tardaron, cuántas veces cada agente respondió con el LLM o cayó al fallback, cuántas acciones se
aprobaron o rechazaron y las peticiones HTTP por ruta/estado.
"""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Histogram

REGISTRY = CollectorRegistry()

ANALYSES = Counter("irp_analyses_total", "Análisis ejecutados", ["status"], registry=REGISTRY)
ANALYSIS_SECONDS = Histogram(
    "irp_analysis_seconds", "Duración del análisis completo", buckets=(5, 10, 20, 40, 80, 160, 320), registry=REGISTRY
)
AGENT_NODES = Counter("irp_agent_nodes_total", "Nodos del grafo ejecutados", ["node", "source"], registry=REGISTRY)
AGENT_SECONDS = Histogram(
    "irp_agents_seconds", "Duración del flujo de agentes", buckets=(10, 60, 180, 360, 720, 1200), registry=REGISTRY
)
APPROVALS = Counter("irp_approvals_total", "Decisiones humanas sobre acciones", ["decision"], registry=REGISTRY)
HTTP_REQUESTS = Counter("irp_http_requests_total", "Peticiones HTTP", ["route", "status"], registry=REGISTRY)
UPLOADS = Counter("irp_uploads_total", "Cargas de archivos", ["status"], registry=REGISTRY)
# Mejora O13 (respuestas del modelo local): cuánto tuvo que corregir/fijar el código y cómo responde el chat.
AGENT_CHECKS = Counter(
    "irp_agent_checks_total",
    "Revisión de las salidas de los agentes: correcciones, observaciones abiertas y datos fijados por el código",
    ["agent", "kind"],
    registry=REGISTRY,
)
CHAT_TURNS = Counter(
    "irp_chat_turns_total", "Preguntas al chat por agente y origen", ["agent", "source"], registry=REGISTRY
)
CHAT_SECONDS = Histogram(
    "irp_chat_seconds", "Duración de las respuestas del chat", buckets=(1, 5, 15, 30, 60, 120, 240), registry=REGISTRY
)
REVIEW_ISSUES = Counter(
    "irp_review_issues_total", "Observaciones de la revisión automática del chat", ["kind"], registry=REGISTRY
)
