"""Construye el contexto compacto que reciben los agentes.

Principios:
- **Minimización**: solo agregados y hechos de `evidence.json`; nunca filas crudas ni tokens en claro
  (solo huella + pista). El LLM corre en otro equipo de la LAN por HTTP.
- **Contexto corto**: ~1-1.5 k tokens; el equipo de referencia (solo CPU) lee ~105 tokens/s, así que cada agente tarda
  ~15 s solo en leer su entrada.
- **Datos controlados por el atacante** (user agents) se truncan y se entregan dentro de un bloque
  JSON marcado como datos, nunca como instrucciones (mitigación de prompt injection).
"""

from __future__ import annotations

import json
from typing import Any

from idor_ir.forensics.evidence import auth_statement
from idor_ir.profile import IncidentProfile

MAX_UA_LEN = 60


def _ua(value: str | None) -> str:
    text = (value or "").replace("\n", " ").replace("\r", " ")
    return text[:MAX_UA_LEN]


def build_context(evidence: dict[str, Any], metrics: dict[str, Any] | None = None) -> dict[str, Any]:
    """Resumen estructurado y acotado del incidente para los agentes."""
    campaigns = []
    for c in evidence.get("campaigns", []):
        imp = c["impact"]
        campaigns.append(
            {
                "id": c["campaign_id"],
                "status": c["status"],
                "ips": c["ips"],
                "tokens": [t["hint"] for t in c["tokens"]],
                "requests": c["requests"],
                "first_seen": c["first_seen"],
                "last_seen": c["last_seen"],
                "patient_zero": {k: c["patient_zero"][k] for k in ("ts", "source_ip", "status")}
                | {"user_agent": _ua(c["patient_zero"]["user_agent"])},
                "exploitation_start": c["exploitation_start"],
                "user_agents": [
                    {"ua": _ua(u["user_agent"]), "category": u["category"], "first_seen": u["first_seen"]}
                    for u in c["user_agents"]
                ],
                "phases": [
                    {k: p[k] for k in ("start", "end", "median_per_day", "constant_daily_volume", "success_ratio")}
                    for p in c["phases"]
                ],
                "impact": {
                    k: imp[k]
                    for k in (
                        "success_responses_2xx",
                        "success_2xx_with_token",
                        "success_2xx_without_token",
                        "unique_invoices_2xx",
                        "unique_invoices_2xx_outside_baseline",
                        "invoice_id_ranges_2xx",
                        "invoice_id_ranges_outside_baseline",
                        "first_request_outside_baseline",
                        "unique_invoices_2xx_by_site",
                    )
                    if k in imp
                },
            }
        )
    top = [
        {
            k: t.get(k)
            for k in (
                "ip",
                "risk_score",
                "risk_level",
                "campaign_id",
                "requests",
                "success_2xx",
                "unique_invoices",
                "automation_ratio",
            )
        }  # fmt: skip
        | {"reasons": t["reasons"][:3]}
        for t in evidence.get("top20_ips", [])[:12]
    ]
    profile = IncidentProfile.from_evidence(evidence)
    ctx: dict[str, Any] = {
        "incident": {
            "endpoint": profile.request_template,  # del perfil del run, no fijo del escenario
            "objetos": profile.object_label_plural,
            "profile": profile.as_dict(),
            "dataset_range": evidence.get("metadata", {}).get("dataset_range"),
            "total_records": evidence.get("metadata", {}).get("total_records"),
            "detection_date": evidence.get("response_metrics", {}).get("detection_date"),
        },
        "campaigns": campaigns,
        "top_ips": top,
        "response_metrics": {
            k: v for k, v in evidence.get("response_metrics", {}).items() if k != "detection_date_note"
        },
    }
    if metrics:
        ctx["traffic"] = {
            "error_rates": metrics.get("error_rates"),
            "requests_per_ip": {k: v for k, v in metrics.get("requests_per_ip", {}).items() if k != "top"},
        }
    ctx["verified_facts"] = verified_facts(evidence)
    return ctx


def verified_facts(evidence: dict[str, Any]) -> list[str]:
    """Hechos derivados de forma determinista de la evidencia, redactados en lenguaje natural y en AFIRMATIVO.

    Motivo: en pruebas reales el modelo afirmó "acceso sin autenticación" (incluso cuando el hecho decía "no hay
    evidencia de acceso sin autenticación": los modelos pequeños pierden la negación y copian la frase) y "uso para
    phishing". Por eso: hechos explícitos, con cifras, sin negaciones, y la autenticación MEDIDA en los datos de cada
    run (2xx con y sin credencial), no un texto fijo del escenario.
    """
    profile = IncidentProfile.from_evidence(evidence)
    objs = profile.object_label_plural
    facts: list[str] = []
    for c in evidence.get("campaigns", []):
        imp, cid = c["impact"], c["campaign_id"]
        status = "confirmada" if c["status"] == "confirmada" else "por validar"
        facts.append(
            f"{cid} ({status}): {len(c['tokens'])} credenciales ({profile.token_param}) usadas desde {len(c['ips'])} "
            f"IPs; el servidor respondió 2xx {imp['success_responses_2xx']:,} veces."
        )
        if "success_2xx_without_token" in imp:
            facts.append(auth_statement(cid, imp, profile))
        outside = imp["unique_invoices_2xx_outside_baseline"]
        facts.append(
            f"{cid}: {imp['unique_invoices_2xx']:,} {objs} únicas obtenidas con 2xx EN TOTAL"
            + (f" (no por {profile.scope_label})" if profile.scope_param else "")
            + "; "
            + (
                f"{outside:,} de ellas nunca aparecen en el tráfico normal."
                if outside
                else "todas están dentro del rango consultado por el tráfico normal."
            )
        )
        for p in c["phases"]:
            constant = ", volumen diario constante." if p["constant_daily_volume"] else "."
            facts.append(
                f"{cid} fase {p['phase']} ({p['start']} a {p['end']}): mediana {p['median_per_day']:.0f} "
                f"peticiones/día, éxito 2xx {p['success_ratio']:.0%}{constant}"
            )
    facts.append(
        f"Los logs registran solo las peticiones: el uso posterior de las {objs} (fraude, phishing, venta) es una "
        "hipótesis."
    )
    facts.append("Los logs no indican cómo obtuvo el atacante las credenciales.")
    return facts


RULES = [
    "Prioriza POR CAMPAÑA, no por IP: todas las IPs de una campaña comparten credenciales; contener solo algunas "
    "no detiene el ataque.",
    "Las cifras 'TOTAL_de_la_campaña' son de toda la campaña; para hablar de una IP usa 'cifras_por_ip'.",
    "Una campaña 'por validar' se valida con AppSec/QA antes de cualquier acción técnica; no se bloquea.",
    "Al listar IPs de una campaña, nómbralas TODAS (están en 'ips_todas').",
    "Usa solo fechas dentro de 'periodo_del_log' (o la fecha de detección).",
]


def _status(value: str) -> str:
    return "confirmada" if value == "confirmada" else "por validar (validar con AppSec/QA antes de actuar)"


def fichas(ctx: dict[str, Any], detail: bool = True) -> dict[str, Any]:
    """Vista del contexto para el MODELO, en "fichas" sin ambigüedad [mejora O13, punto 4].

    Errores reales que corrige: el modelo atribuía a una IP el total de la campaña y omitía una IP (justo la del
    primer acceso exitoso). Por eso cada campaña lista TODAS sus IPs con su papel, los totales van rotulados como
    "TOTAL_de_la_campaña" y las cifras por IP van en una tabla aparte.
    """
    profile = ctx.get("incident", {}).get("profile") or {}
    scope = profile.get("scope_label", "ámbito")
    out: list[dict[str, Any]] = []
    for c in ctx.get("campaigns", []):
        imp = c.get("impact", {})
        pz = (c.get("patient_zero") or {}).get("source_ip")
        es = (c.get("exploitation_start") or {}).get("source_ip")

        def role(ip: str, pz: Any = pz, es: Any = es) -> str:
            tags = [t for t, hit in (("primera actividad/patient zero", ip == pz), ("primer acceso exitoso", ip == es))
                    if hit]  # fmt: skip
            return f"{ip} ({' y '.join(tags)})" if tags else ip

        ficha: dict[str, Any] = {
            "id": c["id"],
            "estado": _status(c["status"]),
            "periodo": f"{str(c['first_seen'])[:16]} a {str(c['last_seen'])[:16]}",
            f"ips_todas ({len(c['ips'])})": [role(ip) for ip in c["ips"]],
            f"credenciales ({len(c['tokens'])})": c["tokens"],
            "TOTAL_de_la_campaña": {
                "peticiones": c.get("requests"),
                "respuestas_2xx": imp.get("success_responses_2xx"),
                "respuestas_2xx_con_credencial": imp.get("success_2xx_with_token"),
                "objetos_unicos_2xx": imp.get("unique_invoices_2xx"),
                "objetos_fuera_del_rango_normal": imp.get("unique_invoices_2xx_outside_baseline"),
            },
            f"objetos_por_{scope} (todos)": imp.get("unique_invoices_2xx_by_site"),
        }
        if detail:
            ficha["fases"] = [
                f"{p['start']} a {p['end']}: mediana {p['median_per_day']:.0f}/día, éxito {p['success_ratio']:.0%}"
                + (", volumen constante" if p.get("constant_daily_volume") else "")
                for p in c.get("phases", [])
            ]
            ficha["primera_peticion"] = c.get("patient_zero")
            ficha["primer_acceso_exitoso"] = c.get("exploitation_start")
            ficha["user_agents"] = [
                f"{u['ua']} ({u['category']}, desde {u['first_seen']})" for u in c.get("user_agents", [])
            ]
        out.append(ficha)
    view: dict[str, Any] = {
        "periodo_del_log": ctx.get("incident", {}).get("dataset_range"),
        "incidente": {k: v for k, v in ctx.get("incident", {}).items() if k not in ("profile", "dataset_range")},
        "verified_facts": ctx.get("verified_facts", []),
        "campañas": out,
        "cifras_por_ip": {
            "columnas": ["ip", "campaña", "nivel", "peticiones", "respuestas_2xx", "objetos_unicos"],
            "filas": [
                [
                    t["ip"],
                    t.get("campaign_id"),
                    t.get("risk_level"),
                    t.get("requests"),
                    t.get("success_2xx"),
                    t.get("unique_invoices"),
                ]
                for t in ctx.get("top_ips", [])
            ],  # fmt: skip
        },
        "reglas": RULES,
    }
    rm = ctx.get("response_metrics") or {}
    if rm:
        view["tiempos"] = {k: rm.get(k) for k in ("first_malicious_request", "first_successful_access",
                                                  "ttd_reference", "ttd_reference_source",
                                                  "ttd_from_first_malicious_request_days",
                                                  "ttd_from_first_successful_access_days")}  # fmt: skip
    if ctx.get("traffic"):
        view["trafico"] = ctx["traffic"]
    return view


def as_prompt_block(data: dict[str, Any]) -> str:
    """Serializa el contexto como bloque de DATOS delimitado."""
    return "<datos_incidente>\n" + json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n</datos_incidente>"
