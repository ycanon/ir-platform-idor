"""Trabajos en segundo plano (análisis y agentes) con eventos de progreso para SSE.

Diseño simple y suficiente para una herramienta local de un analista:
- Un hilo por trabajo; como máximo un trabajo activo por tipo (el análisis y el LLM consumen CPU).
- Eventos en memoria (lista acotada) que la web consume por Server-Sent Events.
- La aprobación humana de los agentes se implementa como una espera sobre `threading.Event`:
  el grafo de LangGraph queda pausado en `interrupt()` hasta que el analista decide en la UI.
"""

from __future__ import annotations

import threading
import time
import traceback
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

MAX_EVENTS = 500
APPROVAL_TIMEOUT_S = 1800  # sin decisión en 30 min → todas las acciones pendientes se rechazan


@dataclass
class Job:
    id: str
    kind: str
    status: str = "queued"  # queued | running | awaiting_approval | completed | failed
    events: list[dict[str, Any]] = field(default_factory=list)
    result: dict[str, Any] | None = None
    error: str | None = None
    pending_actions: list[dict[str, Any]] = field(default_factory=list)
    # Acciones que se ejecutan sin aprobación (solo informativas en la pausa; no se deciden).
    automatic_actions: list[dict[str, Any]] = field(default_factory=list)
    created: float = field(default_factory=time.time)
    _approvals: dict[str, str] = field(default_factory=dict)
    _decided: threading.Event = field(default_factory=threading.Event)
    _seq: int = 0

    def emit(self, kind: str, message: str, data: dict[str, Any] | None = None) -> None:
        # Secuencia monótona (no len(events)): la lista se recorta y el SSE usa seq para no repetir eventos.
        event = {"seq": self._seq, "ts": time.time(), "kind": kind, "message": message, "data": data or {}}
        self._seq += 1
        self.events.append(event)
        if len(self.events) > MAX_EVENTS:
            del self.events[0]

    def wait_for_approval(self, payload: dict[str, Any]) -> dict[str, str]:
        """Usado como `decide` del grafo: bloquea el hilo del trabajo hasta la decisión humana."""
        self.pending_actions = list(payload.get("pending_actions", []))
        self.automatic_actions = list(payload.get("automatic_actions", []))
        self.status = "awaiting_approval"
        self.emit(
            "awaiting_approval",
            f"{len(self.pending_actions)} acciones esperan aprobación humana; "
            f"{len(self.automatic_actions)} automáticas se ejecutan sin aprobación",
        )
        decided = self._decided.wait(timeout=APPROVAL_TIMEOUT_S)
        self._decided.clear()  # una futura interrupción vuelve a esperar al analista
        self.status = "running"
        pending = [a["action_id"] for a in self.pending_actions]
        self.pending_actions = []
        self.automatic_actions = []
        if not decided:
            self.emit("approval_timeout", "Sin decisión a tiempo: se rechazan las acciones pendientes")
            return {aid: "reject" for aid in pending}
        # Acción sin decisión explícita = rechazada (fail-safe: nada se ejecuta sin aprobación expresa).
        return {aid: self._approvals.get(aid, "reject") for aid in pending}

    def submit_approvals(self, approvals: dict[str, str]) -> None:
        self._approvals = approvals
        self._decided.set()

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "status": self.status,
            "error": self.error,
            "result": self.result,
            "pending_actions": self.pending_actions,
            "automatic_actions": self.automatic_actions,
            "events": self.events[-50:],
        }


class JobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def busy(self, kind: str) -> Job | None:
        return next(
            (
                j
                for j in self._jobs.values()
                if j.kind == kind and j.status in {"queued", "running", "awaiting_approval"}
            ),
            None,
        )

    def start(self, kind: str, target: Callable[[Job], dict[str, Any]]) -> Job:
        with self._lock:
            if self.busy(kind):
                raise RuntimeError(f"Ya hay un trabajo '{kind}' en curso")
            job = Job(id=uuid.uuid4().hex[:12], kind=kind)
            self._jobs[job.id] = job

        def runner() -> None:
            job.status = "running"
            try:
                job.result = target(job)
                job.status = "completed"
                job.emit("completed", "Trabajo finalizado")
            except Exception as exc:  # el detalle va al log del servidor, no a la UI
                job.status = "failed"
                job.error = f"{type(exc).__name__}: {str(exc)[:200]}"
                job.emit("failed", job.error)
                traceback.print_exc()

        threading.Thread(target=runner, name=f"job-{kind}-{job.id}", daemon=True).start()
        return job
