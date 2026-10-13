"""Contratos de salida de los 3 agentes [R8-R10].

Cada agente DEBE devolver JSON que cumpla su esquema. El esquema se envía a Ollama en el parámetro
`format` (salida estructurada) y la respuesta se valida con Pydantic antes de usarla: la salida de un
LLM es entrada no confiable (OWASP LLM Top 10 - LLM05 Improper Output Handling).
Los límites de longitud mantienen la generación corta (el equipo de referencia, solo CPU, genera ~7,6 tokens/s).
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field

from idor_ir.agents.mitre import CATALOG

# Límites de longitud: los valida Pydantic DESPUÉS de generar (el recorte se hace en una palabra completa).
# Ya NO viajan en la gramática de Ollama: allí cortaban la frase en mitad de una palabra (y de una letra con
# tilde, produciendo "�"). La longitud se controla pidiendo viñetas de ≤ 25 palabras [mejora O13, punto 5].
Short = Annotated[str, Field(max_length=240)]
Line = Annotated[str, Field(max_length=280)]

# Catálogo curado de técnicas MITRE ATT&CK (Enterprise) pertinentes para ataques a APIs web. Nombre y tácticas
# viven en `mitre.py`. Los IDs se envían como `enum` en la gramática: el modelo SOLO puede elegir de esta lista.
# Motivo: en la prueba real qwen3-4b propuso T1047 (WMI) y T1068, que no aplican a este incidente.
MITRE_CATALOG: dict[str, str] = {tid: t.name for tid, t in CATALOG.items()}
TechniqueId = Literal["T1595.002", "T1595.003", "T1190", "T1078", "T1119", "T1213", "T1090", "T1020"]

Severity = Literal["critico", "alto", "medio", "bajo"]
ActionType = Literal[
    "corroborate",
    "block_ip",
    "rate_limit",
    "revoke_token",
    "waf_rule",
    "monitoring",
    "fix_idor",
    "rotate_tokens",
    "notify",
]


class Checks(BaseModel):
    """Transparencia [mejora O13, punto 12]: qué revisó, agregó o corrigió el código en la salida del agente."""

    status: Literal["verificado", "con observaciones"] = "verificado"
    issues: list[str] = Field(default_factory=list)  # observaciones que siguen abiertas
    corrections: list[str] = Field(default_factory=list)  # corregidas por el modelo tras la revisión
    code_additions: list[str] = Field(default_factory=list)  # lo que agregó o fijó el código


class Hypothesis(BaseModel):
    text: str = Field(max_length=240)
    kind: Literal["hecho", "hipotesis"]
    origin: Literal["modelo", "código"] = "modelo"


class TriageOutput(BaseModel):
    """Triage Agent: clasifica severidad y tipo de ataque, plantea hipótesis y prioriza [R8]."""

    severity: Severity
    attack_type: str = Field(max_length=140)
    confidence: float = Field(ge=0, le=1)  # la calcula el código (confidence_basis)
    hypotheses: list[Short] = Field(min_length=1, max_length=6)
    investigation_plan: list[Short] = Field(min_length=1, max_length=6)
    priority_targets: list[Annotated[str, Field(max_length=60)]] = Field(
        default_factory=list, max_length=6, description="Campañas a priorizar (por campaña, no por IP)"
    )
    hypotheses_detail: list[Hypothesis] = Field(default_factory=list)
    confidence_basis: list[str] = Field(default_factory=list)
    severity_basis: str = ""
    checks: Checks = Field(default_factory=Checks)


class MitreMapping(BaseModel):
    technique_id: TechniqueId
    name: str = Field(max_length=100)
    tactic: str = Field(max_length=60)  # SIEMPRE del catálogo (mitre.py)
    justification: str = Field(max_length=280)
    verified_in_catalog: bool = False  # lo completa el código, no el LLM
    tactics_all: list[str] = Field(default_factory=list)
    source: str = "modelo"  # modelo | regla (evidencia)
    justification_source: str = "modelo"  # modelo | código
    required: bool = False  # la evidencia la demuestra
    rule: str = ""
    url: str = ""


class ForensicOutput(BaseModel):
    """Forensic Analyst Agent: explica el patrón con razonamiento basado en evidencia [R9]."""

    attack_pattern: str = Field(max_length=600)
    reasoning: list[Line] = Field(min_length=2, max_length=6, description="Cadena evidencia -> inferencia")
    patient_zero: str = Field(max_length=300)  # lo completa el código (punto 7)
    exploitation_start: str = Field(max_length=300)  # lo completa el código
    automation_type: str = Field(max_length=300)  # lo completa el código
    campaigns_assessment: str = Field(max_length=500)
    mitre_attack: list[MitreMapping] = Field(min_length=1, max_length=8)
    open_questions: list[Short] = Field(default_factory=list, max_length=4)
    checks: Checks = Field(default_factory=Checks)


class ResponseAction(BaseModel):
    action_id: str = Field(max_length=10)
    action_type: ActionType
    target: str = Field(max_length=200)
    priority: int = Field(ge=1, le=16)
    phase: Literal["inmediata", "estrategica"]
    rationale: str = Field(max_length=200)
    false_positive_risk: Literal["bajo", "medio", "alto"]
    business_impact: Literal["bajo", "medio", "alto"]
    requires_human_approval: bool  # el código lo puede ENDURECER según la política, nunca relajar
    mandatory: bool = False  # la evidencia la exige (campaña priorizada, por validar, datos personales)
    added_by_policy: bool = False  # el modelo no la incluyó y la política la agregó
    reason_required: str = ""
    # Lo fija la política (código), nunca el modelo: nivel de evidencia que exige la acción y, si no se cumple,
    # por qué queda condicionada (no se ejecuta aunque se apruebe).
    evidence_required: str = "señal"
    blocked_reason: str = ""


class ResponseOutput(BaseModel):
    """Response Advisor Agent: contención priorizada + mini-playbook [R10]."""

    actions: list[ResponseAction] = Field(min_length=1, max_length=16)
    playbook: list[Short] = Field(min_length=3, max_length=8)
    ordering_rationale: str = Field(max_length=500)
    checks: Checks = Field(default_factory=Checks)


# --------------------------------------------------------------------------- borradores que escribe el LLM
# [mejora O13, punto 7] El modelo escribe SOLO lo que requiere redacción o criterio; los datos (patient zero,
# inicio, automatización, tácticas MITRE, acciones candidatas, prioridades, confianza) los pone el código.
# Menos tokens generados = menos tiempo (Ollama escribe a ~4-5 tokens/s) y menos espacio para inventar.


class HypothesisDraft(BaseModel):
    text: str = Field(max_length=240)
    kind: Literal["hecho", "hipotesis"]


class TriageDraft(BaseModel):
    severity: Severity
    attack_type: str = Field(max_length=140)
    hypotheses: list[HypothesisDraft] = Field(min_length=1, max_length=4)
    investigation_plan: list[Short] = Field(min_length=1, max_length=5)


class MitreChoice(BaseModel):
    technique_id: TechniqueId
    justification: str = Field(max_length=280)


class ForensicDraft(BaseModel):
    attack_pattern: str = Field(max_length=600)
    reasoning: list[Line] = Field(min_length=2, max_length=5)
    campaigns_assessment: str = Field(max_length=500)
    mitre: list[MitreChoice] = Field(min_length=1, max_length=6)
    open_questions: list[Short] = Field(default_factory=list, max_length=3)


class ActionRank(BaseModel):
    action_id: str = Field(max_length=10)
    rationale: str = Field(max_length=240)


class ResponseDraft(BaseModel):
    ranking: list[ActionRank] = Field(min_length=1, max_length=16)
    playbook: list[Short] = Field(min_length=3, max_length=7)
    ordering_rationale: str = Field(max_length=500)


class TextFix(BaseModel):
    """Corrección puntual de un texto tras la revisión automática (punto 9)."""

    texto: str = Field(max_length=280)
