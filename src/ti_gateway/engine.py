"""Motor del gateway: valida el indicador, aplica caché/cuota/ritmo, consulta las fuentes y agrega el veredicto.

Las herramientas MCP (`server.py`) son una capa delgada sobre esta clase, lo que permite probar toda la
lógica sin el protocolo y reutilizarla desde cualquier transporte.
"""

from __future__ import annotations

from typing import Any

from ti_gateway.config import GatewayConfig
from ti_gateway.models import LEVEL_ORDER, CheckResult, IndicatorType, Level, LookupResult, SourceInfo, SourceResult
from ti_gateway.providers import AuthError, Provider, ProviderError, QuotaExceeded
from ti_gateway.providers.base import HttpFactory, default_http
from ti_gateway.state import StateStore
from ti_gateway.util import normalize_indicator, scrub

# Prioridad al combinar el contexto de red (ASN, país...): fuentes especializadas primero.
CONTEXT_PRIORITY = ("ipinfo", "abuseipdb", "virustotal", "shodan", "greynoise", "otx", "abusech")


class Gateway:
    def __init__(self, config: GatewayConfig, http_factory: HttpFactory = default_http, sleep: Any = None) -> None:
        self.config = config
        self.state = StateStore(config.data_dir, config.cache_ttl_hours)
        self.providers: dict[str, Provider] = config.build_providers(http_factory, sleep)

    # ------------------------------------------------------------------ catálogo y cuota
    def list_sources(self) -> list[SourceInfo]:
        out = []
        for p in self.providers.values():
            period = p.period
            out.append(
                SourceInfo(
                    id=p.id,
                    label=p.label,
                    indicator_types=list(p.indicator_types),
                    key_required=p.key_required,
                    key_env=p.key_env(),
                    configured=p._key is not None,
                    needs_url=p.needs_url,
                    url_env=p.url_env() if p.needs_url else None,
                    base_url=p.base_url,
                    url_placeholder=p.url_placeholder,
                    enabled=p.enabled,
                    publishes_queries=p.publishes_queries,
                    terms_note=p.terms_note,
                    docs_url=p.docs_url,
                    per_minute=p.per_minute,
                    quota_limit=p.quota_limit,
                    quota_period=period,
                    quota_used=self.state.quota_used(p.id, period) if period else 0,
                )
            )
        return out

    def _provider(self, source: str) -> Provider:
        if source not in self.providers:
            raise ValueError(f"Fuente desconocida: {source}")
        return self.providers[source]

    def _consume(self, p: Provider) -> bool:
        return self.state.quota_try_consume(p.id, p.period or "day", p.quota_limit if p.period else None)

    # ------------------------------------------------------------------ validación de clave
    def check_source(self, source: str) -> CheckResult:
        p = self._provider(source)
        if not p.configured:
            return CheckResult(source=source, ok=False, detail=f"Configure {p.missing_config()} para {p.label}")
        if p.period and not self._consume(p):
            return CheckResult(source=source, ok=False, detail=f"{p.label}: cupo del periodo agotado")
        try:
            p.pacer.wait()
            detail = p.validate()
            ok = True
        except ProviderError as exc:
            detail, ok = str(exc), False
        self.state.audit("check_source", {"client": self.config.client_name, "source": source, "ok": ok})
        return CheckResult(source=source, ok=ok, detail=scrub(detail, [p.secret]))

    # ------------------------------------------------------------------ consulta
    def _query(self, p: Provider, indicator: str, itype: IndicatorType) -> tuple[SourceResult, bool]:
        """Devuelve (resultado, ¿se envió el indicador a la fuente?)."""
        if not p.enabled:
            return SourceResult(source=p.id, status="not_configured", summary="Fuente deshabilitada"), False
        if itype not in p.indicator_types:
            return SourceResult(source=p.id, status="unsupported", summary=f"No soporta indicadores '{itype}'"), False
        if not p.configured:
            return SourceResult(
                source=p.id, status="not_configured", summary=f"Sin configurar ({p.missing_config()})"
            ), False
        if p.auth_failed:
            return SourceResult(source=p.id, status="error", error=p.auth_failed), False
        cache_key = f"{p.id}:{itype}:{indicator}"
        cached = self.state.cache_get(cache_key)
        if cached:
            result = SourceResult.model_validate(cached["result"])
            return result.model_copy(update={"cached": True}), False
        if p.period and not self._consume(p):
            limit = f"{p.quota_limit} por {'semana' if p.period == 'week' else 'día'}"
            return SourceResult(source=p.id, status="quota", error=f"{p.label}: cupo agotado ({limit})"), False
        p.pacer.wait()
        try:
            result = p.fetch(indicator, itype)
        except AuthError as exc:
            p.auth_failed = str(exc)
            return SourceResult(source=p.id, status="error", error=str(exc)), True
        except QuotaExceeded as exc:
            return SourceResult(source=p.id, status="quota", error=str(exc)), True
        except ProviderError as exc:
            return SourceResult(source=p.id, status="error", error=str(exc)), True
        self.state.cache_put(cache_key, result.model_dump())
        return result, True

    def lookup(
        self,
        indicator: str,
        indicator_type: IndicatorType | None = None,
        sources: list[str] | None = None,
        consent: dict[str, Any] | None = None,
    ) -> LookupResult:
        """`consent`: autorización del envío (la herramienta MCP la exige; aquí se audita con la consulta)."""
        value, itype = normalize_indicator(indicator, indicator_type)  # lanza IndicatorError
        selected = sources or [p.id for p in self.providers.values() if p.enabled and p.configured]
        unknown = set(selected) - set(self.providers)
        if unknown:
            raise ValueError(f"Fuentes desconocidas: {', '.join(sorted(unknown))}")
        results, sent = [], []
        for source in selected:
            result, was_sent = self._query(self.providers[source], value, itype)
            results.append(result)
            if was_sent:
                sent.append(source)
        verdict, reasons, fp, context = aggregate(results, self.providers)
        self.state.audit(
            "lookup",
            {
                "client": self.config.client_name,
                "indicator": value,
                "type": itype,
                "sent_to": sent,
                "cached": [r.source for r in results if r.cached],
                "verdict": verdict,
                "consent": consent,
            },
        )
        return LookupResult(
            indicator=value,
            indicator_type=itype,
            verdict=verdict,
            reasons=reasons,
            possible_false_positive=fp,
            context=context,
            sources=results,
            sent_to=sent,
        )


def aggregate(
    results: list[SourceResult], providers: dict[str, Provider]
) -> tuple[Level, list[str], bool, dict[str, Any]]:
    """Veredicto = el nivel más grave entre las fuentes con reputación ('informativo' no cuenta)."""
    usable = [r for r in results if r.status in ("ok", "not_found") and r.level != "informativo"]
    verdict: Level = max((r.level for r in usable), key=lambda lv: LEVEL_ORDER[lv], default="sin datos")
    reasons = [f"{providers[r.source].label}: {reason}" for r in results for reason in r.reasons]
    fp = any(r.possible_false_positive for r in results)
    context: dict[str, Any] = {}
    by_source = {r.source: r for r in results}
    for source in CONTEXT_PRIORITY:
        for k, v in (by_source[source].context if source in by_source else {}).items():
            context.setdefault(k, v)
    return verdict, reasons, fp, context
