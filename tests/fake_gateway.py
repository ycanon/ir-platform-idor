"""Lanzador de PRUEBA del servidor MCP ti-gateway apuntando a servicios simulados locales.

Uso (solo tests/E2E): python tests/fake_gateway.py http://127.0.0.1:PUERTO
Reescribe las URL base de los adaptadores hacia el servidor simulado y arranca el gateway real por stdio.
No forma parte del paquete: el código de producción no tiene ningún mecanismo para redirigir las URL.
"""

from __future__ import annotations

import os
import sys

for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
    os.environ.pop(var, None)  # el simulador es local: nunca a través de un proxy

from ti_gateway.providers import abusech, abuseipdb, greynoise, ipinfo, otx, shodan, virustotal  # noqa: E402
from ti_gateway.server import main  # noqa: E402

base = sys.argv[1].rstrip("/")
virustotal.BASE = f"{base}/vt/api/v3"
otx.BASE = f"{base}/otx/api/v1"
abuseipdb.URL = f"{base}/abuseipdb/api/v2/check"
greynoise.BASE = f"{base}/greynoise/v3/community"
ipinfo.BASE = f"{base}/ipinfo/lite"
shodan.BASE = f"{base}/shodan"
abusech.THREATFOX = f"{base}/threatfox/api/v1/"
abusech.URLHAUS_HOST = f"{base}/urlhaus/v1/host/"
main()
