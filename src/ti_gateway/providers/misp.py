"""MISP (Malware Information Sharing Platform) — instancia propia o de la comunidad a la que pertenece la empresa.

API REST de MISP (OpenAPI oficial, https://www.misp-project.org/openapi/):
- POST {url}/attributes/restSearch  cuerpo JSON {"returnFormat": "json", "value": ..., "limit": ...,
  "includeEventTags": true, "includeWarninglistHits": true}; respuesta {"response": {"Attribute": [...]}}.
- GET  {url}/servers/getVersion     para validar la clave.
- Cabecera `Authorization: <clave>` (la clave de autenticación del usuario de MISP) y `Accept: application/json`.

Diferencias con las fuentes SaaS:
- Es AUTOALOJADA: necesita la URL de la instancia (TI_MISP_URL) y, si usa una CA interna, TI_MISP_CA_BUNDLE.
  TLS siempre verificado; sin seguir redirecciones (no se reenvía la clave a otro host).
- Lo consultado no se publica: queda en los logs de la propia instancia (publishes_queries = False).

Veredicto [DEC]:
- atributo con `to_ids` = true (el analista que lo compartió lo marcó como IOC accionable) → "malicioso";
- solo atributos sin `to_ids` (contexto) → "sospechoso";
- coincidencia con una warninglist de MISP (rangos de nubes, resolvers, CDNs...) → baja un nivel y se marca
  como posible falso positivo;
- sin atributos → "sin reportes".
"""

from __future__ import annotations

from typing import Any

from ti_gateway.models import IndicatorType, SourceResult
from ti_gateway.providers.base import Provider, ProviderError
from ti_gateway.util import clean_list, clean_text

THREAT_LEVEL = {"1": "alta", "2": "media", "3": "baja", "4": "indefinida"}
MAX_ATTRIBUTES = 50


class MISP(Provider):
    id = "misp"
    label = "MISP"
    indicator_types = ("ip", "domain", "hash", "url")
    terms_note = (
        "Instancia autoalojada o de su comunidad: lo consultado queda en los logs de ESA instancia (no es "
        "público). Los eventos los comparten terceros: revisar contexto y warninglists."
    )
    docs_url = "https://www.misp-project.org/openapi/"
    default_per_minute = 60
    needs_url = True
    url_placeholder = "https://misp.example.internal"

    def _headers(self) -> dict[str, str]:
        return {"Authorization": self.secret, "Accept": "application/json", "Content-Type": "application/json"}

    def _url(self, path: str) -> str:
        if not self.base_url:
            raise ProviderError(f"{self.label}: falta la URL de la instancia ({self.url_env()})")
        return f"{self.base_url}{path}"

    def fetch(self, indicator: str, indicator_type: IndicatorType) -> SourceResult:
        body = {
            "returnFormat": "json",
            "value": indicator,
            "limit": MAX_ATTRIBUTES,
            "includeEventTags": True,
            "includeWarninglistHits": True,
        }
        raw = self.check(self.request("POST", self._url("/attributes/restSearch"), headers=self._headers(), json=body))
        attrs = [a for a in ((raw or {}).get("response") or {}).get("Attribute") or [] if isinstance(a, dict)]
        if not attrs:
            return self.result("sin reportes", "Sin atributos en MISP", status="not_found")

        ids_attrs = [a for a in attrs if a.get("to_ids") in (True, 1, "1", "true")]
        warnings = sorted(
            {
                clean_text(w.get("warninglist_name") or w.get("name") or "", 80)
                for a in attrs
                for w in (a.get("warnings") or [])
                if isinstance(w, dict)
            }
            - {""}
        )
        events: dict[str, dict[str, Any]] = {}
        tags: list[str] = []
        for a in attrs:
            raw_ev = a.get("Event")
            ev: dict[str, Any] = raw_ev if isinstance(raw_ev, dict) else {}
            eid = clean_text(str(a.get("event_id") or ev.get("id") or ""), 12)
            if eid and eid not in events and eid.isdigit():
                raw_org = ev.get("Orgc")
                org: dict[str, Any] = raw_org if isinstance(raw_org, dict) else {}
                events[eid] = {
                    "id": eid,
                    "info": clean_text(ev.get("info", ""), 120),
                    "threat_level": THREAT_LEVEL.get(str(ev.get("threat_level_id", "")), "indefinida"),
                    "date": clean_text(ev.get("date", ""), 12),
                    "org": clean_text(org.get("name", ""), 60),
                }
            tags += [t.get("name", "") for t in (a.get("Tag") or []) if isinstance(t, dict)]
        tag_list = clean_list(list(dict.fromkeys(tags)), 8)

        if ids_attrs:
            level, reasons = "malicioso", [f"{len(ids_attrs)} atributo(s) marcados como IOC (to_ids)"]
        else:
            level, reasons = "sospechoso", [f"{len(attrs)} atributo(s) de contexto (sin to_ids)"]
        if warnings:
            level = "sospechoso" if level == "malicioso" else "sin reportes"
            reasons.append(f"En warninglist de MISP: {', '.join(warnings[:2])}")
        high = [e for e in events.values() if e["threat_level"] == "alta"]
        if high:
            reasons.append(f"{len(high)} evento(s) con nivel de amenaza alto")
        first = next(iter(events.values()), None)
        return self.result(
            level,  # type: ignore[arg-type]
            f"{len(attrs)} atributo{'s' if len(attrs) != 1 else ''} en {len(events)} evento"
            f"{'s' if len(events) != 1 else ''}" + (f": {first['info'][:60]}" if first and first["info"] else ""),
            reasons=reasons,
            possible_false_positive=bool(warnings),
            data={
                "attribute_count": len(attrs),
                "to_ids_count": len(ids_attrs),
                "categories": clean_list(list(dict.fromkeys(str(a.get("category", "")) for a in attrs)), 6),
                "events": list(events.values())[:5],
                "tags": tag_list,
                "warninglists": warnings[:5],
                "truncated": len(attrs) >= MAX_ATTRIBUTES,
                "tls_verified": self.tls_verify,
            },
            permalink=f"{self.base_url}/events/view/{first['id']}" if first else "",
        )

    def validate(self) -> str:
        body = self.check(self.request("GET", self._url("/servers/getVersion"), headers=self._headers()))
        version = clean_text(str((body or {}).get("version", "")), 20)
        warn = " · ⚠ certificado TLS SIN verificar (excepción de laboratorio)" if not self.tls_verify else ""
        return (f"Clave válida (MISP {version})" if version else "Clave válida") + warn
