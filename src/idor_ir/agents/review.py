"""Revisión automática de lo que escribe el modelo contra la evidencia [mejora O13, fase 2 · punto 9].

Errores reales que detecta (prueba con qwen3-4b, 05-oct-2026):
- **fechas fuera del dataset** ("C2 ... en febrero 2021" con un log de oct–dic 2020);
- **IPs o campañas inexistentes**;
- **listas incompletas** (4 de las 5 IPs de C1; omitió justo la del primer acceso exitoso);
- **atribución equivocada**: un total de la campaña presentado como cifra de una IP
  ("73.130.229.200 ... 5,232 facturas fuera de rango": 5 232 es el total de C1);
- **cifras** que no están en la evidencia (aviso, ya existía).

No bloquea: devuelve observaciones con el dato correcto. En los agentes se usan para pedir una corrección puntual;
en el chat, para una nota de verificación generada por el código.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any

MONTHS = {
    "enero": 1, "ene": 1, "febrero": 2, "feb": 2, "marzo": 3, "mar": 3, "abril": 4, "abr": 4, "mayo": 5, "may": 5,
    "junio": 6, "jun": 6, "julio": 7, "jul": 7, "agosto": 8, "ago": 8, "septiembre": 9, "setiembre": 9, "sep": 9,
    "sept": 9, "octubre": 10, "oct": 10, "noviembre": 11, "nov": 11, "diciembre": 12, "dic": 12,
}  # fmt: skip
MONTH_NAMES = ["", "enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre",
               "octubre", "noviembre", "diciembre"]  # fmt: skip
_MONTH_ALT = "|".join(sorted(MONTHS, key=len, reverse=True))
_ISO_RE = re.compile(r"\b(20\d{2})-(\d{2})-(\d{2})")
_DMY_RE = re.compile(rf"\b(\d{{1,2}})[-/ ](?:de )?({_MONTH_ALT})\.?[-/ ](?:de )?(20\d{{2}})\b", re.I)
_MY_RE = re.compile(rf"\b({_MONTH_ALT})\.?(?: de)? (?:de )?(20\d{{2}})\b", re.I)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CAMPAIGN_RE = re.compile(r"\bC(\d{1,2})\b")
_NUM_RE = re.compile(r"(?<![\w.])\d{1,3}(?:[.,]\d{3})+(?![\d])|(?<![\w.,])\d{3,}(?![\d%])")
_NUM_CTX_RE = re.compile(r"\d[\d.,]{2,}\d|\d{3,}")


@dataclass
class Issue:
    kind: str  # fecha | ip | campaña | lista_incompleta | atribución | cifra
    message: str  # para el analista
    fact: str  # dato correcto que se entrega al modelo para corregir (o en la nota del chat)
    blocking: bool = True  # False = solo aviso (no motiva una corrección)

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "message": self.message, "fact": self.fact, "blocking": self.blocking}


@dataclass
class Facts:
    """Lo que la revisión necesita saber de la evidencia (se construye una vez por run)."""

    start: date | None
    end: date | None
    extra_dates: set[date] = field(default_factory=set)  # detección, referencia del TTD
    campaigns: dict[str, dict[str, Any]] = field(default_factory=dict)
    ip_campaign: dict[str, str] = field(default_factory=dict)
    known_ips: set[str] = field(default_factory=set)
    ip_figures: dict[str, set[int]] = field(default_factory=dict)
    haystack: str = ""

    @property
    def range_text(self) -> str:
        if not self.start or not self.end:
            return "el periodo del log"
        return f"{self.start.isoformat()} a {self.end.isoformat()}"


def _d(value: Any) -> date | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace(" ", "T")[:19]).date()
    except ValueError:
        return None


def build_facts(evidence: dict[str, Any], extra: dict[str, Any] | None = None) -> Facts:
    meta = evidence.get("metadata", {})
    rng = meta.get("dataset_range") or [None, None]
    rm = evidence.get("response_metrics", {})
    facts = Facts(start=_d(rng[0]), end=_d(rng[1]))
    facts.extra_dates = {d for d in (_d(rm.get("detection_date")), _d(rm.get("ttd_reference"))) if d}
    for c in evidence.get("campaigns", []):
        cid, imp = c["campaign_id"], c.get("impact", {})
        roles: dict[str, str] = {}
        pz = (c.get("patient_zero") or {}).get("source_ip")
        es = (c.get("exploitation_start") or {}).get("source_ip")
        if pz:
            roles[pz] = "primera actividad/patient zero"
        if es:
            roles[es] = (roles.get(es, "") + " y " if es in roles else "") + "primer acceso exitoso"
        totals = {
            "peticiones": c.get("requests"),
            "respuestas 2xx": imp.get("success_responses_2xx"),
            "objetos únicos 2xx": imp.get("unique_invoices_2xx"),
            "objetos fuera del rango normal": imp.get("unique_invoices_2xx_outside_baseline"),
        }
        facts.campaigns[cid] = {
            "status": c.get("status"),
            "ips": list(c.get("ips", [])),
            "roles": roles,
            "first_seen": c.get("first_seen"),
            "last_seen": c.get("last_seen"),
            "totals": {k: int(v) for k, v in totals.items() if isinstance(v, int | float) and v >= 100},
            "sites": sorted((imp.get("unique_invoices_2xx_by_site") or {}).keys()),
        }
        for ip in c.get("ips", []):
            facts.ip_campaign[ip] = cid
            facts.known_ips.add(ip)
    for t in evidence.get("top20_ips", []):
        facts.known_ips.add(t["ip"])
        facts.ip_figures[t["ip"]] = {int(t[k]) for k in ("requests", "success_2xx", "unique_invoices") if t.get(k)}
    for i in evidence.get("iocs", {}).get("ips", []):
        facts.known_ips.add(i.get("value", ""))
    facts.haystack = re.sub(r"[.,]", "", json.dumps([evidence, extra or {}], ensure_ascii=False, default=str))
    return facts


def _num(text: str) -> int | None:
    try:
        return int(re.sub(r"[.,]", "", text))
    except ValueError:
        return None


def _date_ok(facts: Facts, d: date) -> bool:
    if d in facts.extra_dates or not facts.start or not facts.end:
        return True
    return facts.start - timedelta(days=1) <= d <= facts.end + timedelta(days=1)


def _month_ok(facts: Facts, year: int, month: int) -> bool:
    if not facts.start or not facts.end:
        return True
    months = {(d.year, d.month) for d in facts.extra_dates}
    cur, last = (facts.start.year, facts.start.month), (facts.end.year, facts.end.month)
    while cur <= last:
        months.add(cur)
        cur = (cur[0] + (cur[1] == 12), cur[1] % 12 + 1)
    return (year, month) in months


def _campaign_period(facts: Facts) -> str:
    return "; ".join(
        f"{cid} ocurrió entre {str(c['first_seen'])[:10]} y {str(c['last_seen'])[:10]}"
        for cid, c in facts.campaigns.items()
    )


def _ip_list(facts: Facts, cid: str) -> str:
    c = facts.campaigns[cid]
    parts = [f"{ip} ({c['roles'][ip]})" if ip in c["roles"] else ip for ip in c["ips"]]
    return f"{cid} tiene {len(c['ips'])} IPs: " + ", ".join(parts)


def review_text(text: str, facts: Facts, check_numbers: bool = True) -> list[Issue]:
    """Observaciones sobre un texto del modelo (respuesta del chat o campo de un agente)."""
    issues: list[Issue] = []
    seen: set[str] = set()

    def add(issue: Issue) -> None:
        if issue.message not in seen:
            seen.add(issue.message)
            issues.append(issue)

    # 1) Fechas fuera del periodo del log (y de la fecha de detección).
    period = _campaign_period(facts)
    for y, m, d in _ISO_RE.findall(text):
        try:
            when = date(int(y), int(m), int(d))
        except ValueError:
            continue
        if not _date_ok(facts, when):
            add(
                Issue(
                    "fecha",
                    f"Fecha {when.isoformat()} fuera del periodo del log ({facts.range_text})",
                    f"El log cubre {facts.range_text}. {period}.",
                )
            )
    for d, mon, y in _DMY_RE.findall(text):
        month = MONTHS[mon.lower()]
        try:
            when = date(int(y), month, int(d))
        except ValueError:
            continue
        if not _date_ok(facts, when):
            add(
                Issue(
                    "fecha",
                    f"Fecha {d}-{mon}-{y} fuera del periodo del log ({facts.range_text})",
                    f"El log cubre {facts.range_text}. {period}.",
                )
            )
    for mon, y in _MY_RE.findall(text):
        if not _month_ok(facts, int(y), MONTHS[mon.lower()]):
            add(
                Issue(
                    "fecha",
                    f"«{mon} {y}» está fuera del periodo del log ({facts.range_text})",
                    f"El log cubre {facts.range_text}. {period}.",
                )
            )

    # 2) IPs y campañas inexistentes.
    ips = _IP_RE.findall(text)
    for ip in ips:
        if ip not in facts.known_ips:
            add(
                Issue(
                    "ip",
                    f"La IP {ip} no aparece en la evidencia",
                    "IPs de las campañas: " + "; ".join(_ip_list(facts, cid) for cid in facts.campaigns),
                )
            )
    for n in _CAMPAIGN_RE.findall(text):
        cid = f"C{n}"
        if facts.campaigns and cid not in facts.campaigns:
            add(
                Issue(
                    "campaña",
                    f"La campaña {cid} no existe",
                    "Campañas: " + ", ".join(f"{k} ({v['status']})" for k, v in facts.campaigns.items()),
                )
            )

    # 3) Listas incompletas: se nombran 2 o más IPs de una campaña pero no todas.
    mentioned = set(ips)
    for cid, c in facts.campaigns.items():
        hits = [ip for ip in c["ips"] if ip in mentioned]
        if 2 <= len(hits) < len(c["ips"]):
            missing = [ip for ip in c["ips"] if ip not in mentioned]
            role = "; ".join(f"papel: {c['roles'][ip]}" for ip in missing if ip in c["roles"])
            add(
                Issue(
                    "lista_incompleta",
                    f"Se mencionan {len(hits)} de las {len(c['ips'])} IPs de {cid}; falta(n): {', '.join(missing)}"
                    + (f" ({role})" if role else ""),
                    _ip_list(facts, cid) + ". Todas comparten credenciales: se tratan como una unidad.",
                )
            )

    # 4) Total de la campaña atribuido a una IP (por línea/viñeta).
    for line in re.split(r"\n|(?<=[.;])\s+(?=[-•*]|\d+\.)|\s[-•]\s", text):
        line_ips = [ip for ip in _IP_RE.findall(line) if ip in facts.ip_campaign]
        if len(line_ips) != 1:
            continue
        ip = line_ips[0]
        cid = facts.ip_campaign[ip]
        own = facts.ip_figures.get(ip, set())
        clean = _IP_RE.sub(" ", line)
        for raw in _NUM_RE.findall(clean):
            value = _num(raw)
            if value is None or value in own:
                continue
            for label, total in facts.campaigns[cid]["totals"].items():
                if value == total:
                    add(
                        Issue(
                            "atribución",
                            f"{raw} es el total de {cid} ({label}), no una cifra de la IP {ip}",
                            f"{raw} = {label} de toda la campaña {cid}; para cada IP use sus propias cifras.",
                        )
                    )
            owners = [other for other, figs in facts.ip_figures.items() if other != ip and value in figs]
            if owners and own:
                add(
                    Issue(
                        "atribución",
                        f"{raw} es una cifra de {owners[0]}, no de {ip}",
                        f"Cifras de {ip} (peticiones, 2xx, objetos únicos): "
                        + ", ".join(f"{v:,}" for v in sorted(own, reverse=True)),
                    )
                )

    # 5) Cifras que no están en los datos (solo aviso).
    if check_numbers:
        plain = re.sub(r"\bT\d{4}(?:\.\d{3})?\b", " ", _IP_RE.sub(" ", _ISO_RE.sub(" ", text)))
        found = {re.sub(r"[.,]", "", n) for n in _NUM_CTX_RE.findall(plain)}
        bad = sorted(
            n for n in found if n not in facts.haystack and not n.startswith("0") and not re.fullmatch(r"20\d{2}", n)
        )
        if bad:
            add(
                Issue(
                    "cifra",
                    f"Cifras que no aparecen en la evidencia: {', '.join(bad[:6])}",
                    "Use las cifras exactas de la evidencia.",
                    blocking=False,
                )
            )
    return issues


def blocking(issues: list[Issue]) -> list[Issue]:
    return [i for i in issues if i.blocking]


def correction_note(issues: list[Issue]) -> str:
    """Nota de verificación para el chat (la escribe el código, no el modelo)."""
    if not issues:
        return ""
    lines = []
    for i in issues[:5]:
        lines.append(f"• {i.message}." + (f" Dato correcto: {i.fact}" if i.blocking else ""))
    return "Verificación automática (código):\n" + "\n".join(lines)
