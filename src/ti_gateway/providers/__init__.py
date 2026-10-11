"""Registro de fuentes. Para agregar una nueva: crear el adaptador y añadirlo a PROVIDERS."""

from ti_gateway.providers.abusech import AbuseCh
from ti_gateway.providers.abuseipdb import AbuseIPDB
from ti_gateway.providers.base import AuthError, Provider, ProviderError, QuotaExceeded
from ti_gateway.providers.greynoise import GreyNoise
from ti_gateway.providers.ipinfo import IPinfo
from ti_gateway.providers.misp import MISP
from ti_gateway.providers.otx import OTX
from ti_gateway.providers.shodan import Shodan
from ti_gateway.providers.virustotal import VirusTotal

PROVIDERS: dict[str, type[Provider]] = {
    p.id: p for p in (VirusTotal, OTX, AbuseIPDB, GreyNoise, IPinfo, Shodan, AbuseCh, MISP)
}

__all__ = ["PROVIDERS", "AuthError", "Provider", "ProviderError", "QuotaExceeded"]
