# ti-gateway: servidor MCP de inteligencia de amenazas

`ti-gateway` es un servidor [MCP](https://modelcontextprotocol.io) que centraliza las consultas a fuentes de
inteligencia de amenazas. IR Platform lo usa para enriquecer las IPs del Top 20, y cualquier otro cliente
MCP (Claude Desktop, Cowork, Claude Code…) puede usarlo con la misma configuración.

- **Paquete independiente** (`src/ti_gateway/`): no importa nada de `idor_ir`.
- **Transporte stdio**: el cliente lanza el servidor como subproceso; no abre puertos de red.
- **SDK**: `mcp>=1.28,<2`. La rama 1.x es la que admite `langchain-mcp-adapters` (requiere `mcp<2`) y sigue
  recibiendo parches de seguridad.

## Fuentes incluidas

| ID | Fuente | Indicadores | Clave | Límites por defecto (plan gratuito) | Aporta |
|---|---|---|---|---|---|
| `virustotal` | VirusTotal v3 | IP, dominio, hash | Obligatoria | 4/min, 500/día · **publica lo consultado** · sin uso comercial | Detecciones de motores |
| `otx` | AlienVault OTX | IP, dominio, hash | Obligatoria | 60/min | Pulsos comunitarios |
| `abuseipdb` | AbuseIPDB v2 | IP | Obligatoria | 1 000/día | Confianza de abuso, tipo de uso, Tor |
| `greynoise` | GreyNoise Community | IP | Opcional | 10/día sin clave · 50/semana con clave | ¿Escáner masivo de Internet o servicio benigno? |
| `ipinfo` | IPinfo Lite | IP | Obligatoria (token gratuito) | Sin límite | ASN y país (contexto) |
| `shodan` | Shodan | IP | Obligatoria | No consume créditos | Puertos, etiquetas (`compromised`) |
| `abusech` | abuse.ch ThreatFox + URLhaus | IP, dominio, hash | Obligatoria (gratuita) | Uso justo | IOCs de malware/C2 |
| `misp` | MISP (instancia propia o de su comunidad) | IP, dominio, hash, URL | Obligatoria + **URL de la instancia** | 60/min (ajustable) · lo consultado queda en los logs de esa instancia, no es público | Eventos, `to_ids`, nivel de amenaza, etiquetas, warninglists |

Los límites se pueden ajustar por fuente (planes premium) desde la pestaña Configuración o con
`TI_<ID>_PER_MINUTE` y `TI_<ID>_QUOTA`.

### MISP (fuente autoalojada)

- **API:** `POST {url}/attributes/restSearch` con `{"returnFormat": "json", "value": <indicador>, "limit": 50,
  "includeEventTags": true, "includeWarninglistHits": true}` y `GET {url}/servers/getVersion` para validar la clave.
  Cabecera `Authorization: <clave de autenticación del usuario MISP>` (OpenAPI oficial de MISP).
- **Configuración:** en Configuración → Inteligencia de amenazas, fila **MISP**, columna **Conexión**: "URL de la
  instancia" y "API key" (o `TI_MISP_URL` y `TI_MISP_API_KEY`). Sirve una instancia **interna**
  (`https://misp.example.internal`) o **externa** (de una comunidad o un proveedor, `https://misp.example.org`).
- **TLS:** sin certificado propio se valida con el almacén de certificados del sistema operativo (`truststore`), así
  que una instancia con certificado de la CA corporativa ya instalada en el equipo funciona sin configurar nada. Si la
  instancia usa un certificado **autofirmado** (instalación por defecto de MISP) o de una CA interna que el equipo no
  reconoce, pegue el certificado PEM (de la instancia o de su CA) en el campo **"Certificado TLS"** de la fila MISP
  (solo memoria; nunca una clave privada; la interfaz muestra su huella SHA-256 para compararla con la del servidor).
  Alternativa: la variable de entorno del sistema `TI_MISP_CA_BUNDLE=<ruta al PEM>` (no se lee del `.env`). La
  verificación nunca se desactiva. El certificado debe incluir la IP o el nombre usado en la URL (SAN).
- **Omitir la verificación TLS (excepción de laboratorio):** casilla "Omitir la verificación del certificado TLS" en la
  fila MISP (o `TI_MISP_TLS_VERIFY=0`). Solo se acepta si la URL apunta a la red interna (IP privada o nombre que
  resuelve a IP privada) y se desactiva sola si la URL pasa a ser externa. El tráfico sigue cifrado, pero no se
  comprueba la identidad del servidor (riesgo de suplantación en la red). El cambio queda en la cadena de custodia,
  la validación lo advierte y cada resultado de MISP registra `tls_verified: false`. Nunca está activa por defecto.
- **Diagnóstico:** si no conecta, el mensaje indica la causa: certificado autofirmado o de CA no reconocida,
  certificado que no corresponde a la IP/nombre, puerto que no habla HTTPS, conexión rechazada, tiempo de espera,
  proxy o nombre que no resuelve.
- **Lista blanca:** el host de la URL debe estar en `TI_ALLOWED_HOSTS` (lo define el administrador por entorno; la
  interfaz no puede ampliarla). Ejemplo: `TI_ALLOWED_HOSTS=misp.example.internal,10.0.0.70`.
- **Validación de la URL:** `https://` hacia cualquier servidor autorizado; `http://` solo hacia la red interna (IP privada o un
  nombre que resuelve únicamente a IPs privadas), porque por Internet la clave viajaría en claro. Sin
  usuario/contraseña, parámetros ni fragmento. No se siguen redirecciones (la clave no se reenvía a otro host).
- **Veredicto [DEC]:** atributo con `to_ids` → *malicioso*; solo atributos de contexto → *sospechoso*; coincidencia
  con una warninglist (rangos de nubes, CDN, resolvers) → baja un nivel y marca posible falso positivo; sin
  atributos → *sin reportes*. Enlace al primer evento (`{url}/events/view/<id>`).
- Use un usuario de MISP de **solo lectura** para la clave (mínimo privilegio).

## Herramientas MCP

| Herramienta | Qué hace | ¿Sale a Internet? |
|---|---|---|
| `ti_list_sources` | Catálogo: fuentes, tipos de indicador, si tienen clave, límites y consumo | No |
| `ti_lookup(indicator, consent, indicator_type?, sources?)` | Veredicto agregado, contexto de red y detalle por fuente. `consent` = `{granted: true, run_id, granted_by, purpose}` es **obligatorio** | Sí (salvo caché) |
| `ti_check_source(source)` | Valida la clave configurada con una llamada real | Sí |
| `ti_quota_status` | Consumo del periodo por fuente | No |

**Veredicto:** es el nivel más grave entre las fuentes con reputación, en este orden: malicioso > sospechoso
> sin reportes > sin datos. IPinfo y Shodan aportan contexto ("informativo"), salvo que Shodan marque la IP como
`compromised` o `malware`. Las listas de confianza (OTX, AbuseIPDB, GreyNoise RIOT) se señalan como posible
falso positivo.

## Seguridad

- **Las claves entran solo por variables de entorno** (`TI_<ID>_API_KEY`). Ninguna herramienta recibe ni
  devuelve claves, y no aparecen en la caché, la auditoría ni los errores (lo verifican las pruebas).
- **Mínimo privilegio:** la plataforma lanza el gateway con las claves de las fuentes que necesita cada
  operación, y el SDK solo hereda variables de entorno seguras.
- **Solo IPs públicas:** las privadas o reservadas se rechazan antes de llamar a cualquier fuente.
- **HTTPS con verificación TLS, sin seguir redirecciones**, con timeouts y respuestas normalizadas y acotadas.
  Los textos de terceros (nombres de pulsos, etiquetas) se limpian de caracteres de control/bidi y se marcan
  como datos, nunca como instrucciones.
- **Consentimiento obligatorio en el servidor:** `ti_lookup` rechaza la consulta sin un `consent` válido
  (`granted: true`, caso/run, quién autorizó y para qué) y lo guarda en la auditoría encadenada junto al indicador y
  las fuentes. No depende de que el cliente lo pida: un agente o un cliente MCP no puede consultar por su cuenta. En
  la IR Platform el consentimiento lo da un usuario con rol **aprobador** (casilla de autorización) y queda también en
  la cadena de custodia del caso. Las instrucciones del servidor indican a los clientes que nunca lo inventen.
- **Salida de red controlada (anti-SSRF):** cada conexión pasa por `egress_guard`: solo hosts de las APIs públicas
  fijas del código (que deben resolver a IPs públicas) o de `TI_ALLOWED_HOSTS` (instancias propias como MISP); se
  resuelve el DNS en cada conexión, se rechazan link-local, metadatos de nube y direcciones reservadas, y se conecta
  a la IP verificada (anti DNS rebinding).
- **Estado compartido** en `TI_DATA_DIR`:
  - `cache.json` (24 h) y `quota.json`, con un candado de archivo, para que varias copias del gateway no
    superen juntas un cupo;
  - `audit.jsonl`, encadenado con SHA‑256 (quién consultó qué, a qué fuentes y cuándo).

## Uso desde Claude Desktop o Cowork (opcional)

Agregue al archivo de configuración MCP del cliente (en Claude Desktop: `claude_desktop_config.json`). Use la ruta
absoluta al intérprete del entorno virtual del proyecto (`.venv/bin/python` en Linux y macOS,
`.venv\Scripts\python.exe` en Windows):

```json
{
  "mcpServers": {
    "ti-gateway": {
      "command": "/ruta/al/proyecto/.venv/bin/python",
      "args": ["-m", "ti_gateway"],
      "env": {
        "TI_DATA_DIR": "/ruta/al/proyecto/output/ti_gateway",
        "TI_CLIENT_NAME": "claude-desktop",
        "TI_ALLOWED_HOSTS": "misp.example.internal",
        "TI_ABUSEIPDB_API_KEY": "<su clave>",
        "TI_GREYNOISE_API_KEY": "<su clave>"
      }
    }
  }
}
```

> ⚠ En ese archivo las claves quedan en texto plano en disco. Use solo las fuentes necesarias y proteja el
> archivo. Si `TI_DATA_DIR` apunta a la misma carpeta que usa la web (`output/ti_gateway`), la caché y las
> cuotas se comparten entre ambos.

## Agregar una fuente nueva

1. Crear `src/ti_gateway/providers/<fuente>.py` con una subclase de `Provider`: metadatos, `fetch()` y
   `validate()`. Si es autoalojada (como MISP), `needs_url = True`: la web pide la URL y el gateway usa
   `TI_<ID>_URL` / `TI_<ID>_CA_BUNDLE`.
2. Registrarla en `PROVIDERS` (`providers/__init__.py`).
3. Agregar pruebas con respuestas simuladas (`tests/test_ti_gateway.py`).
4. Revisar los términos de uso y los límites de la fuente.

La web la mostrará sola en Configuración (catálogo vía `ti_list_sources`), con su campo de clave y sus límites.
Por seguridad, no se pueden definir fuentes nuevas desde la interfaz: eso convertiría el gateway en un proxy
HTTP genérico, con riesgo de SSRF y de fuga de claves.
