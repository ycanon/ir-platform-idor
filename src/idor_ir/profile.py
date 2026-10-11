"""Perfil del incidente: qué endpoint y qué parámetros se analizan, y cómo se nombran los objetos expuestos.

Objetivo: que la plataforma sirva para este incidente (facturas en `/invoices/search`) y para otros IDOR sobre
logs con el mismo esquema de 8 campos [Reto §2], sin textos fijos del escenario en la evidencia, los agentes, el
chat ni las reglas de contención.

Nombres internos canónicos [DEC]: las columnas derivadas se siguen llamando `invoice_id`, `site_id` y `authtoken`
(y las claves de la evidencia `unique_invoices_*`) por compatibilidad; significan "identificador del objeto",
"ámbito/tenant" y "credencial". Lo que ve el analista (textos, reglas, prompts) usa este perfil.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, fields
from typing import Any

PARAM_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,40}$")
ENDPOINT_RE = re.compile(r"^/[A-Za-z0-9_\-/.]*$")
LABEL_RE = re.compile(r"^[\wáéíóúüñÁÉÍÓÚÜÑ ]{1,30}$")


@dataclass(frozen=True)
class IncidentProfile:
    endpoint: str = "/invoices/search"
    object_param: str = "invoice_id"
    scope_param: str = "site_id"  # "" = el endpoint no tiene ámbito/tenant
    token_param: str = "authtoken"  # noqa: S105 (nombre del parámetro, no un secreto)
    object_label: str = "factura"
    object_label_plural: str = "facturas"
    scope_label: str = "sitio"

    def __post_init__(self) -> None:
        if not ENDPOINT_RE.fullmatch(self.endpoint):
            raise ValueError("Endpoint inválido (debe empezar por / y usar solo letras, números, _ - . /)")
        for name in ("object_param", "token_param"):
            if not PARAM_RE.fullmatch(getattr(self, name)):
                raise ValueError(f"Parámetro inválido: {name}")
        if self.scope_param and not PARAM_RE.fullmatch(self.scope_param):
            raise ValueError("Parámetro inválido: scope_param")
        for name in ("object_label", "object_label_plural", "scope_label"):
            if not LABEL_RE.fullmatch(getattr(self, name)):
                raise ValueError(f"Etiqueta inválida: {name}")

    @property
    def request_template(self) -> str:
        params = [f"{self.object_param}={{id}}"]
        if self.scope_param:
            params.append(f"{self.scope_param}={{{self.scope_label}}}")
        params.append(f"{self.token_param}={{token}}")
        return f"GET {self.endpoint}?{'&'.join(params)}"

    def as_dict(self) -> dict[str, str]:
        return asdict(self)

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> IncidentProfile:
        """Desde la metadata de una evidencia. Runs anteriores sin perfil → valores del reto (compatibilidad)."""
        names = {f.name for f in fields(cls)}
        return cls(**{k: str(v) for k, v in (data or {}).items() if k in names and v is not None})

    @classmethod
    def from_evidence(cls, evidence: dict[str, Any] | None) -> IncidentProfile:
        return cls.from_mapping(((evidence or {}).get("metadata") or {}).get("profile"))
