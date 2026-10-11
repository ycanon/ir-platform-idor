"""MITRE ATT&CK fijado por el código [mejora O13, fase 1].

Problema observado (prueba real con qwen3-4b, 05-oct-2026): el modelo elegía IDs válidos del catálogo pero
inventaba la táctica (T1190 "Execution", T1595.002 "Privilege Escalation") y cruzaba justificaciones (T1078
justificado con el escaneo, T1595 con las credenciales); además omitía T1119.

Diseño:
- **Catálogo** con nombre, tácticas oficiales (ATT&CK Enterprise) y la táctica que aplica en un IDOR web.
  El modelo SOLO elige técnicas y redacta la justificación; nombre y táctica los pone el código.
- **Técnicas obligatorias** deducidas de la evidencia (reglas explicables). Si el modelo no las elige, se
  agregan con una justificación generada con los datos.
- **Coherencia de la justificación**: cada técnica tiene palabras clave que su justificación debe contener.
  Si no, se pide una corrección puntual al modelo y, si persiste, se usa la justificación del código.

Fuente: https://attack.mitre.org (Enterprise). Versión de referencia registrada en `ATTACK_VERSION`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from idor_ir.profile import IncidentProfile

ATTACK_VERSION = "ATT&CK Enterprise v16"


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]  # tácticas oficiales de la técnica
    primary: str  # táctica que corresponde a lo observado en un ataque IDOR a una API web
    keywords: str  # regex (sin acentos, minúsculas) que la justificación debe cumplir

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/") + "/"


CATALOG: dict[str, Technique] = {
    t.id: t
    for t in (
        Technique(
            "T1595.002", "Active Scanning: Vulnerability Scanning", ("Reconnaissance",), "Reconnaissance",
            r"sonde|escane|reconoc|explor|error|rechaz|fallid|4\d\d|0 ?%|prueba|tante|sin exito",
        ),
        Technique(
            "T1595.003", "Active Scanning: Wordlist Scanning", ("Reconnaissance",), "Reconnaissance",
            r"diccionario|wordlist|lista de|fuerza bruta|enumer|escane|sonde",
        ),
        Technique(
            "T1190", "Exploit Public-Facing Application", ("Initial Access",), "Initial Access",
            r"endpoint|2xx|explot|aplicacion|idor|autoriz|pertenencia|vulnerab|expuest|publica|/[a-z]",
        ),
        Technique(
            "T1078", "Valid Accounts",
            ("Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"), "Initial Access",
            r"credencial|token|cuenta|autentic|sesion|usuario|login|clave",
        ),
        Technique(
            "T1119", "Automated Collection", ("Collection",), "Collection",
            r"automat|herramient|script|crawler|scrapy|wget|curl|bot|volumen|program|masiv|recolec",
        ),
        Technique(
            "T1213", "Data from Information Repositories", ("Collection",), "Collection",
            r"repositor|datos|informacion|registro|objeto|document|factura",
        ),
        Technique(
            "T1090", "Proxy", ("Command and Control",), "Command and Control",
            r"proxy|ips?\b|infraestructura|rotaci|anonim|tor\b|vpn",
        ),
        Technique(
            "T1020", "Automated Exfiltration", ("Exfiltration",), "Exfiltration",
            r"exfil|extrac|descarg|salida de datos|automat",
        ),
    )
}  # fmt: skip


def _fold(text: str) -> str:
    """Minúsculas sin acentos (las palabras clave se escriben sin tildes)."""
    table = str.maketrans("áéíóúüñ", "aeiouun")
    return text.lower().translate(table)


def justification_matches(technique_id: str, text: str) -> bool:
    tech = CATALOG.get(technique_id)
    return bool(tech and re.search(tech.keywords, _fold(text)))


@dataclass
class RequiredTechnique:
    id: str
    rule: str  # regla de la evidencia que la hace obligatoria (explicable en la presentación)
    justification: str  # generada con los datos del run


@dataclass
class MitreAssembly:
    mappings: list[dict[str, Any]] = field(default_factory=list)
    added: list[str] = field(default_factory=list)  # obligatorias que el modelo no eligió
    mismatched: list[str] = field(default_factory=list)  # justificación del modelo incoherente
    dropped: list[str] = field(default_factory=list)  # IDs fuera del catálogo o repetidos


def required_techniques(evidence: dict[str, Any]) -> list[RequiredTechnique]:
    """Técnicas que la evidencia DEMUESTRA (campañas confirmadas). Reglas:

    - una fase con 0 % de éxito antes del primer acceso exitoso → T1595.002 (sondeo/reconocimiento);
    - respuestas 2xx obtenidas con credencial → T1078 (cuentas válidas);
    - respuestas 2xx en el endpoint para objetos ajenos → T1190 (explotación de la aplicación expuesta);
    - user agents de herramientas con volumen diario constante → T1119 (recolección automatizada).
    """
    profile = IncidentProfile.from_evidence(evidence)
    objs = profile.object_label_plural
    out: dict[str, RequiredTechnique] = {}
    for c in evidence.get("campaigns", []):
        if c.get("status") != "confirmada":
            continue
        cid, imp = c["campaign_id"], c.get("impact", {})
        recon = [p for p in c.get("phases", []) if p.get("success_ratio") == 0]
        if recon and "T1595.002" not in out:
            p = recon[0]
            pz = c.get("patient_zero") or {}
            out["T1595.002"] = RequiredTechnique(
                "T1595.002",
                "fase con 0 % de éxito",
                f"{cid}: fase {p['start']} a {p['end']} con ~{p['median_per_day']:.0f} peticiones/día y 0 % de éxito "
                f"(primera petición con status {pz.get('status')}, UA {str(pz.get('user_agent', ''))[:30]}): sondeo "
                "previo al primer acceso exitoso.",
            )
        with_token = imp.get("success_2xx_with_token", imp.get("success_responses_2xx", 0)) or 0
        if with_token and "T1078" not in out:
            out["T1078"] = RequiredTechnique(
                "T1078",
                "respuestas 2xx con credencial",
                f"{cid}: {len(c.get('tokens', []))} credenciales válidas ({profile.token_param}) usadas desde "
                f"{len(c.get('ips', []))} IPs obtuvieron {with_token:,} respuestas 2xx.",
            )
        if imp.get("success_responses_2xx") and "T1190" not in out:
            out["T1190"] = RequiredTechnique(
                "T1190",
                "respuestas 2xx en el endpoint expuesto",
                f"{cid}: {imp['success_responses_2xx']:,} respuestas 2xx en {profile.endpoint} entregaron "
                f"{imp.get('unique_invoices_2xx', 0):,} {objs} sin comprobar su pertenencia (IDOR).",
            )
        tools = sorted({u["user_agent"].split("/")[0].split(" ")[0] for u in c.get("user_agents", [])
                        if u.get("category") != "navegador_u_otro"})  # fmt: skip
        constant = any(p.get("constant_daily_volume") for p in c.get("phases", []))
        if tools and "T1119" not in out:
            out["T1119"] = RequiredTechnique(
                "T1119",
                "UA de herramientas" + (" y volumen diario constante" if constant else ""),
                f"{cid}: herramientas de automatización ({', '.join(tools[:3])})"
                + (" con volumen diario constante por fase" if constant else "")
                + f": recolección masiva de {objs}.",
            )
    order = ["T1595.002", "T1078", "T1190", "T1119"]
    return [out[k] for k in order if k in out]


def mapping(technique_id: str, justification: str, source: str, justification_source: str,
            required: bool, rule: str = "") -> dict[str, Any]:  # fmt: skip
    tech = CATALOG[technique_id]
    return {
        "technique_id": tech.id,
        "name": tech.name,
        "tactic": tech.primary,
        "tactics_all": list(tech.tactics),
        "justification": justification,
        "verified_in_catalog": True,
        "source": source,  # modelo | regla (evidencia)
        "justification_source": justification_source,  # modelo | código
        "required": required,
        "rule": rule,
        "url": tech.url,
    }


def assemble(choices: list[dict[str, str]], evidence: dict[str, Any]) -> MitreAssembly:
    """Une lo que eligió el modelo con las técnicas obligatorias. Nombre y táctica SIEMPRE del catálogo."""
    required = {r.id: r for r in required_techniques(evidence)}
    result = MitreAssembly()
    seen: set[str] = set()
    for choice in choices:
        tid = str(choice.get("technique_id", ""))
        if tid not in CATALOG or tid in seen:
            result.dropped.append(tid)
            continue
        seen.add(tid)
        text = str(choice.get("justification", "")).strip()
        req = required.get(tid)
        if text and justification_matches(tid, text):
            result.mappings.append(mapping(tid, text, "modelo", "modelo", req is not None, req.rule if req else ""))
        else:
            result.mismatched.append(tid)
            # Provisional: la justificación del código (o la del modelo marcada) hasta que llegue una corrección.
            fixed = req.justification if req else text
            result.mappings.append(
                mapping(tid, fixed, "modelo", "código" if req else "modelo", req is not None, req.rule if req else "")
                | {"justification_issue": "no corresponde a la técnica"}
            )
    for tid, req in required.items():
        if tid not in seen:
            result.added.append(tid)
            result.mappings.append(mapping(tid, req.justification, "regla (evidencia)", "código", True, req.rule))
    order = {tid: i for i, tid in enumerate(CATALOG)}
    result.mappings.sort(key=lambda m: order[m["technique_id"]])
    return result
