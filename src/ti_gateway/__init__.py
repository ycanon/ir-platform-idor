"""ti-gateway: servidor MCP de inteligencia de amenazas (VirusTotal, OTX, AbuseIPDB, GreyNoise, IPinfo, Shodan,
abuse.ch).

Paquete independiente: NO importa nada de `idor_ir`. Cualquier cliente MCP puede usarlo (la IR Platform,
Claude Desktop, Cowork...). Las API keys llegan solo por variables de entorno al arrancar; ninguna
herramienta MCP recibe ni devuelve claves.
"""

__version__ = "0.1.0"
