# Especificación técnica

> Convenciones: **[Reto §x]** remite a la sección del enunciado del reto técnico que originó el proyecto;
> **[DEC]** marca una decisión de diseño propia, con su justificación.

## Contenido

1. [Propósito y alcance](#1-propósito-y-alcance)
2. [Requisitos](#2-requisitos)
3. [Datos de entrada y supuestos](#3-datos-de-entrada-y-supuestos)
4. [Definiciones operativas](#4-definiciones-operativas)
5. [Arquitectura y decisiones técnicas](#5-arquitectura-y-decisiones-técnicas)
6. [Agentes de GenAI](#6-agentes-de-genai)
7. [Inteligencia de amenazas (MCP)](#7-inteligencia-de-amenazas-mcp)
8. [Observabilidad](#8-observabilidad)
9. [Controles de seguridad](#9-controles-de-seguridad)
10. [Validación con el dataset del reto](#10-validación-con-el-dataset-del-reto)
11. [Limitaciones y trabajo futuro](#11-limitaciones-y-trabajo-futuro)

---

## 1. Propósito y alcance

Plataforma de investigación y respuesta automatizada que permite **detectar y analizar la explotación de una
vulnerabilidad IDOR**, **generar evidencia forense sólida** y **automatizar parcialmente la respuesta inicial**, con
el ciclo de NIST SP 800-61 como marco (detección y análisis → contención → erradicación y recuperación → lecciones).

| Aspecto | Definición |
|---|---|
| Caso de referencia | Explotación de IDOR en `GET /invoices/search?invoice_id={id}&site_id={id}&authtoken={token}`: acceso no autorizado a facturas y datos personales [Reto §2] |
| Entrada | Log HTTP en CSV de ~1,1 GB y ~4,5 M registros con los campos `timestamp, http_status, http_host, http_uri, http_method, http_referer, http_user_agent, source_ip` [Reto §2] |
| Salidas | Métricas, clasificación y *risk score* de actores, Top 20 IPs con evidencia, timeline, IOCs, hash y registro de integridad, JSON estructurado, salidas de 3 agentes, respuestas de análisis NIST y métricas TTD/TTR/TTC [Reto §3] |
| Fuera de alcance | Sistemas distribuidos o Kubernetes [Reto §3]; ejecución real de acciones de contención sobre sistemas externos [DEC] |

## 2. Requisitos

### 2.1 Requisitos funcionales y del repositorio

| ID | Requisito | Origen | Implementación |
|---|---|---|---|
| R1 | Procesar ~4,5 M registros por streaming o chunking | [Reto §3, 1.1] | Polars *lazy* + streaming (§5.2) |
| R2 | Detectar patrones IDOR: acceso secuencial a IDs, enumeración masiva, volumen anómalo por IP | [Reto §3, 1.1] | `detection/` (§4, §5.3) |
| R3 | Métricas: peticiones por IP, distribución temporal, tasa 401/403 vs 200 | [Reto §3, 1.1] | `detection/metrics.py` |
| R4 | Justificar decisiones técnicas y rendimiento | [Reto §3, 1.1] | §5.2 |
| R5 | Modelo de anomalías simple y justificado: clasificar IPs, *risk scoring*, detectar automatización | [Reto §3, 1.2] | z-score robusto + Isolation Forest + reglas (§5.3) |
| R6 | Top 20 IPs con evidencia, timeline e IOCs (IPs, user agents, patrones de enumeración) | [Reto §3, 1.3] | `forensics/evidence.py` |
| R7 | Hash del archivo original, registro de integridad y export JSON | [Reto §3, 1.3] | `forensics/integrity.py` (§9) |
| R8 | 3 agentes (Triage, Forensic Analyst, Response Advisor) con LangGraph o equivalente | [Reto §3, C2] | `agents/graph.py` (§6) |
| R9 | Forensic Analyst: *patient zero*, inicio de explotación, tipo de automatización, MITRE ATT&CK; razonamiento, no solo resumen | [Reto §3, C2] | §6 |
| R10 | Response Advisor: acciones priorizadas (bloqueo de IP, *rate limiting*, revocación de tokens), aprobación humana, mini-playbook | [Reto §3, C2] | §6 |
| R11 | Orquestación con estados claros, registro de decisiones, *dry-run* e intervención humana | [Reto §3, C2] | §6 |
| R12 | Responder con datos las 7 preguntas de análisis del incidente | [Reto §3, 3.1] | `evidence.json → incident_answers` |
| R13 | Contención inmediata y estratégica justificando orden, falsos positivos, impacto y criterio de automatización | [Reto §3, 3.2] | §6.3 |
| R14 | Estimar TTD, TTR y TTC y explicar cómo los reduce la automatización | [Reto §3, 3.3] | `agents/estimates.py` |
| R15 | Repositorio con código tipado, README, Docker Compose funcional, pruebas, especificación y observabilidad | [Reto §4] | Este repositorio |

### 2.2 Requisitos técnicos derivados

| ID | Requisito | Deriva de |
|---|---|---|
| D1 | Extraer el ID del objeto, el ámbito y la credencial del `http_uri` (perfil detectado, §5.4) | R2 |
| D2 | Agregaciones por IP, por credencial y por ventana temporal en streaming | R1, R3 |
| D3 | SHA-256 por bloques (sin cargar el archivo en memoria) y manifiesto que también incluya los artefactos generados | R7 |
| D4 | Salidas de los agentes estructuradas y validadas con esquemas | R8, R11 |
| D5 | Ninguna acción de contención se ejecuta realmente: *dry-run* y punto de aprobación humana | R10, R11 |
| D6 | Tipado estático estricto (mypy) y pruebas con pytest | R15 |
| D7 | Contenedor de la plataforma y `docker-compose.yml`; el LLM es un servicio externo configurable | R15 |
| D8 | Las credenciales de terceros presentes en los logs se enmascaran en evidencia, interfaz, logs y prompts | R6, R7 |

## 3. Datos de entrada y supuestos

| # | Aspecto | Decisión |
|---|---|---|
| S1 | Formato del CSV | Separador `,`; el encabezado del dataset trae `http_staus` (sic) y se normaliza a `http_status`; codificación UTF-8 con o sin BOM |
| S2 | Formato del `timestamp` | El dataset del reto usa **`AAAA-DD-MMTHH:MM`**, sin segundos ni zona horaria (segundo campo ∈ [1, 31], tercero ∈ [10, 12]). Es el valor por defecto (`%Y-%d-%mT%H:%M`); la autodetección como `AAAA-MM-DD` dejaba el 61 % de las filas sin fecha. Configurable con `IRP_TIMESTAMP_FORMAT` (o `auto`) |
| S3 | Resolución temporal | Minuto: la automatización se mide en peticiones por minuto/día, no en intervalos de segundos |
| S4 | Acceso «indebido» | El log no relaciona credencial, objeto y titular. Se infiere por comportamiento (enumeración de objetos, objetos fuera del tráfico normal, automatización) y se reporta como **estimación** [DEC] |
| S5 | Usuarios afectados | Límite superior = IDs de objeto únicos con respuesta 2xx en campañas confirmadas, desglosado por ámbito (1 objeto = 1 titular potencial) [DEC] |
| S6 | Fecha de detección | El enunciado indica 12-ene-2020, anterior al log (oct–dic 2020). Para el caso de referencia se usa **12-ene-2021**, coherente con «periodo sospechoso: últimos 3 meses» [DEC]. No está fija: se indica por análisis (`--detection-date`, interfaz o `IRP_DETECTION_DATE`); sin ella el TTD se estima hasta el último registro y se marca como estimado |
| S7 | TTR y TTC | El escenario no da fechas de respuesta: se estiman con supuestos explícitos (manual vs. automatizado); solo los tiempos de la plataforma son medidos |
| S8 | Códigos 401/403 | El dataset no contiene 403; las métricas reportan 401, 403 y 4xx vs 2xx |
| S9 | LLM | Local por defecto (Ollama) por privacidad del dato y costo nulo; proveedores en la nube opcionales con consentimiento explícito [DEC] |

## 4. Definiciones operativas

| Concepto | Definición implementada |
|---|---|
| IP sospechosa | Nivel de riesgo ≥ medio **y** ≥ 20 % de peticiones con user agent de herramienta |
| Tráfico de ataque | Peticiones de IPs sospechosas con user agent de herramienta (el resto de esas IPs se trata como tráfico compartido) |
| Campaña | Componente conexo del grafo IP↔credencial sobre el tráfico de ataque; **confirmada** si contiene una IP de nivel crítico, si no **por validar** |
| Fase | Tramo de la serie diaria; empieza una nueva cuando los 3 días siguientes duplican (o reducen a la mitad) la mediana de los 7 anteriores |
| *Patient zero* | Primera petición de la campaña (hora, IP, credencial enmascarada, status, user agent); se marca como dato censurado si coincide con el inicio del log |
| Inicio de la explotación | Primera respuesta 2xx de la campaña |
| Fuera de la línea base | ID de objeto con respuesta 2xx que nunca aparece en el tráfico que no es de ataque |
| Secuencialidad | Cobertura densa de rangos contiguos de IDs (no se exige +1 petición a petición, porque el log tiene resolución de minuto y viene desordenado) |

## 5. Arquitectura y decisiones técnicas

### 5.1 Componentes

```
                ┌──────────────────────────────── IR Platform ─────────────────────────────────┐
 log CSV ──────►│ ingestion/ ──► detection/ + anomaly/ ──► forensics/                          │
 (./data)       │ Polars lazy    reglas IDOR, z robusto,    campañas, Top 20, timeline, IOCs,  │
                │ streaming      Isolation Forest, score    respuestas NIST, manifiestos       │
                │                                                  │ contexto compacto (sin PII)│
                │ agents/ (LangGraph): triage ─► forensic ─► response ─► política ─► humano   │
                │                                                         └─► dry-run, playbook│
                │ web/ (FastAPI): interfaz · API · /metrics · credenciales en memoria          │
                └────────────┬─────────────────────────────┬───────────────────────────────────┘
                             │ HTTP (solo contexto agregado) │ stdio (MCP)
                    LLM: Ollama / compatible OpenAI /    ti-gateway ──► VirusTotal, OTX, AbuseIPDB,
                         API en la nube                                 GreyNoise, IPinfo, Shodan,
                                                                        abuse.ch, MISP
```

| Módulo | Responsabilidad |
|---|---|
| `config.py` | Configuración por variables de entorno / `.env` (pydantic-settings, `SecretStr`) |
| `logging_setup.py`, `redaction.py` | Logs estructurados con filtro de redacción (credenciales, API keys) |
| `ingestion/` | Esquema, carga *lazy*/streaming, extracción de parámetros y detección del perfil del incidente |
| `detection/`, `anomaly/` | Métricas, detector IDOR, *features* por actor, Isolation Forest y *risk score* |
| `forensics/` | Evidencia, respuestas NIST, IOCs, hash, manifiestos y cadena de custodia |
| `agents/` | Grafo LangGraph, proveedores LLM, política, revisión, ejecución *dry-run*, chat y evaluación |
| `enrichment/` | Cliente MCP del `ti-gateway` |
| `web/` | FastAPI: carga y selección de datasets, trabajos en segundo plano con progreso (SSE), tableros, credenciales en memoria y `/metrics` |
| `ti_gateway/` | Servidor MCP independiente de inteligencia de amenazas |

### 5.2 Tecnologías y alternativas

| Elección | Justificación | Alternativa descartada |
|---|---|---|
| Python 3.12/3.13 | Ecosistema de datos, ML y GenAI; *wheels* disponibles en Linux, macOS y Windows | — |
| **Polars** (*lazy* + streaming) | Motor columnar multihilo; `scan_csv` sin cargar el archivo; regex vectorizada sobre `http_uri` | pandas con `chunksize`: un hilo, regex en Python y más memoria. DuckDB: igual de válido, pero mezcla SQL y Python |
| Parquet como *staging* | Se normaliza una vez; cada detector lee solo sus columnas | Releer el CSV en cada etapa |
| scikit-learn `IsolationForest` + z-score robusto (MAD) | No supervisado (no hay etiquetas), barato con miles de actores; el z robusto no se deja inflar por los propios atacantes | DBSCAN: sensible a parámetros y a la escala |
| LangGraph | Grafo de estados explícito, `interrupt()` para la intervención humana, *checkpoints* | Frameworks conversacionales con menos control del flujo |
| `httpx` directo para los LLM | Control de TLS, *timeouts*, redirecciones y mensajes de error (la clave nunca llega a un log) | SDK por proveedor |
| Modelo por defecto `qwen3:4b-instruct-2507-q4_K_M` (~2,5 GB, Apache 2.0) | Funciona en CPU con 16 GB de RAM; variante *instruct* sin *thinking*; buen seguimiento de JSON y español | Modelos de 14B+: lentos en CPU |
| FastAPI + Jinja2 | API e interfaz en un proceso, validación Pydantic, cabeceras de seguridad, SSE | Streamlit: menos control de sesión y seguridad. SPA: requiere *build* |
| Docker Compose | Requisito del reto; perfiles opcionales | Kubernetes: no requerido |

**Rendimiento medido** (CPU, sin GPU): pipeline completo sobre el log del reto (1,18 GB, 4 478 619 registros):
**12,3 s**; perfil del dataset: 0,9 s; Parquet resultante: 36 MB. Agentes con `qwen3:4b` en CPU (~7,6 tokens/s de
generación, ~105 tokens/s de lectura): ~9 min los tres; la evidencia no depende de ellos.

### 5.3 Detección y *risk score*

Se agrega por IP **y** por credencial, porque el tráfico normal está muy disperso (miles de IPs con pocas peticiones
cada una) y una sola dimensión ocultaría el ataque. El *score* (0–100) es explicable: cada punto tiene una razón
legible en la evidencia.

| Señal | Puntos | Condición |
|---|---|---|
| Volumen anómalo | 20 | z robusto de peticiones por fuente-día ≥ 3,5 |
| Enumeración masiva | 20 | z robusto de IDs distintos por fuente-día ≥ 3,5 |
| Rango contiguo de IDs | 15 | Enumeración + densidad del rango ≥ 0,5 (≥ 100 IDs) |
| Automatización | 0–25 | Proporcional a la fracción de peticiones con user agent de herramienta (máximo desde el 50 %; desde el 20 % se marca «posible bot») |
| Modelo | 0–20 | Proporcional al *score* normalizado de Isolation Forest sobre las variables anteriores |

Niveles: crítico, alto, medio, bajo. Isolation Forest es una señal más, no el decisor: sin datos etiquetados, un
modelo complejo no sería auditable [DEC].

### 5.4 Perfil del incidente detectado del dataset

La plataforma no está atada al endpoint del caso de referencia. En una pasada streaming (`ingestion/autoprofile.py`):

- Normaliza las rutas (segmentos numéricos/UUID → `{id}`) y obtiene, por ruta, estadísticas de cada parámetro.
- **ID de objeto**: ≥ 90 % numérico y ≥ 20 valores distintos (preferencia por `*_id`). **Credencial**: nombre tipo
  *token/auth/session/key* o valores largos y opacos. **Ámbito**: pocos valores distintos, preferencia por
  *site/tenant/org*.
- Con varios endpoints candidatos elige el de más objetos distintos consultados por una misma credencial o IP (la
  señal de un IDOR) y lista los demás.
- Nombra los objetos por diccionario (*invoice → factura*, *order → pedido*…), con confianza y evidencia registradas
  en el manifiesto. El analista puede ajustar el perfil (interfaz o CLI); `IRP_PROFILE_MODE=fixed` lo desactiva.
- El hecho de autenticación se deriva de los datos: si todas las 2xx llevan credencial, la evidencia afirma «acceso
  autenticado, falla de autorización»; si no, lo matiza.

Probado con datasets sintéticos y con otro endpoint (`/orders/search?order_id&tenant&token`).

## 6. Agentes de GenAI

### 6.1 Flujo

| Elemento | Implementación |
|---|---|
| Grafo | `triage → (severidad baja ⇒ reporte) → forensic → response → policy → human_review (interrupt) → execute (dry-run) → report` |
| Entrada | Contexto compacto de la evidencia: sin credenciales en claro; textos del log truncados y marcados como datos no confiables |
| Salida | Borradores con JSON Schema (gramática en Ollama, *tool use* o `json_schema` en APIs) validados con Pydantic; si fallan, lógica determinista equivalente, registrada en el *decision log* |
| Intervención humana | CLI `--approve interactive\|all\|none`; interfaz con aprobar/rechazar. La pausa muestra también las acciones automáticas, sin selector, para que el plan completo y el criterio de automatización queden a la vista. Sin decisión explícita, la acción se rechaza (*fail-safe*) |
| Ejecución | Solo *dry-run*: artefactos de nginx, ModSecurity, SIEM y tickets. Los objetivos salen de los IOCs, nunca del texto del modelo |

### 6.2 El código fija los hechos; el modelo redacta [DEC]

Con un modelo pequeño se observaron tácticas MITRE inventadas, acciones obligatorias omitidas, confianza del 99 % y
fechas fuera del periodo del log. El diseño reparte responsabilidades:

1. **MITRE ATT&CK** (`agents/mitre.py`, catálogo ATT&CK Enterprise v16): nombre y táctica salen del catálogo; las
   técnicas que la evidencia exige son obligatorias (fase con 0 % de éxito → T1595.002; 2xx con credencial → T1078;
   2xx en el endpoint expuesto → T1190; herramientas y volumen constante → T1119). La justificación debe corresponder
   a su técnica.
2. **Acciones**: el código arma las candidatas (campaña confirmada → *rate limit*, WAF, bloqueo de IPs, revocación,
   monitoreo y fix; por validar → solo validar con AppSec/QA; objetos expuestos → Legal/Privacidad) y el modelo las
   ordena y justifica. Las obligatorias omitidas se agregan «por política».
3. **Triage**: severidad mínima por regla (el modelo puede subirla, no bajarla), confianza calculada por el código e
   hipótesis rotuladas *hecho*/*hipótesis*.
4. **Revisión automática** (`agents/review.py`): fechas fuera del periodo, IPs o campañas inexistentes, listas
   incompletas y cifras atribuidas a quien no corresponde; hasta 3 correcciones puntuales por agente.
5. **Parámetros**: temperatura 0 en los agentes, semilla fija y un ejemplo de salida por agente.
6. **Evaluación** (`agents/evaluation.py`, CLI `eval`): banco de ~15 preguntas con hechos esperados del run y
   comparación entre modelos.
7. **Transparencia**: la interfaz distingue lo verificado, lo corregido, lo fijado por el código y el origen de cada
   técnica y acción.

### 6.3 Contención y criterio de automatización

Se automatiza solo lo **reversible, con riesgo de falso positivo bajo e impacto de negocio bajo** (*rate limit*, regla
WAF por user agent exclusivo del ataque, monitoreo). Bloqueo de IPs, revocación y rotación de credenciales, fix y
notificaciones requieren aprobación humana. La política vive en el código: el modelo puede endurecerla, nunca
relajarla. Una campaña «por validar» nunca se bloquea sin validación.

### 6.4 Proveedores LLM

| Proveedor | URL base | Salida estructurada | Modelos |
|---|---|---|---|
| Ollama | Editable (local o red) | `format` = JSON Schema | `GET /api/tags` |
| Compatible con OpenAI (LM Studio, vLLM…) | Editable | `json_object` | `GET /models` |
| Anthropic | Fija | *tool use* forzado | `GET /v1/models` |
| OpenAI | Fija | `response_format: json_schema` | `GET /models` |
| Google Gemini | Fija (compatible OpenAI) | `json_schema` | `GET /models` |
| DeepSeek, Mistral, Groq, xAI, OpenRouter | Fija (compatible OpenAI) | `json_object` + esquema en el prompt | `GET /models` |

En todos: esquema en el prompt, un reintento sin parámetros opcionales ante HTTP 400, validación y reparación limitada
a recortes, y *fallback* determinista. Los nombres de modelo no se fijan en el código. Si el proveedor está fuera de la
red local, cada ejecución exige consentimiento explícito, registrado en el informe y en la cadena de custodia.

### 6.5 Conversación con los agentes

Cada agente responde sobre el run con un contexto fijo (evidencia minimizada, su última salida e información de su
rol), sin herramientas ni ejecución. Las preguntas de dato (IPs, fechas, cifras) se responden desde la evidencia sin
llamar al modelo; las demás, con el proveedor de conversación (igual o distinto al de los agentes). Cada turno queda en
`agents/chats/*.jsonl` con hash y evento de custodia, y una nota de verificación señala cifras que no están en la
evidencia.

## 7. Inteligencia de amenazas (MCP)

Servidor MCP propio `ti-gateway` (`src/ti_gateway/`, sin dependencias de `idor_ir`, transporte stdio, `mcp>=1.28,<2`).
Fuentes: VirusTotal, AlienVault OTX, AbuseIPDB, GreyNoise, IPinfo, Shodan, abuse.ch y MISP (autoalojado). Solo se
consultan IPs públicas del Top 20, con autorización explícita por ejecución (VirusTotal publica lo consultado). Las
claves llegan solo por entorno, con mínimo privilegio por operación; caché, cuota y auditoría encadenada son
compartidas entre procesos. La reputación es la **actual**, no la de la fecha del incidente: es contexto, no prueba
de atribución. Detalle en [`MCP.md`](MCP.md).

## 8. Observabilidad

- **Interfaz**: tableros de cada análisis, evidencia, verificación de integridad, decisiones de los agentes.
- **`/metrics`** (Prometheus): análisis y su duración, nodos de agentes por origen (LLM o determinista), aprobaciones,
  revisión de las salidas del modelo, conversación, cargas y HTTP. Con `IRP_METRICS_TOKEN`, exige un token de solo
  lectura.
- **Perfil `observabilidad`** de Docker Compose: Prometheus `v3.1.0` (lee `/metrics` por la red interna con el token
  como secreto de Compose) y Grafana `11.4.0` con fuente de datos y tablero aprovisionados.
- **Evidencias de ejecución**: manifiestos SHA-256, cadena de custodia y logs estructurados sin secretos.

## 9. Controles de seguridad

Referencia: OWASP Cheat Sheet Series.

| Riesgo | Control | Referencia |
|---|---|---|
| Archivos maliciosos o enormes | Lista blanca de extensión, límite de tamaño, nombre aleatorio en servidor, almacenamiento fuera de rutas servidas, validación del encabezado | File Upload |
| Alteración de la evidencia cargada | Acta de cadena de custodia obligatoria (validada con Pydantic, sin caracteres de control); SHA-256 calculado durante la recepción y comparado con el de origen si se informa; archivo y acta en solo lectura; el análisis se niega si el hash ya no coincide | File Upload, Logging |
| Descargas | Lista blanca cerrada de artefactos más un patrón fijo para los *dry-run* (`agents/actions/A<n>_<tipo>.txt`) y verificación de ruta resuelta; `sensitive/` y `work/` nunca se sirven | Input Validation |
| *Path traversal* | Solo datasets listados en el directorio permitido; `run_id` validado por expresión regular y resolución de ruta | Input Validation |
| XSS (los logs traen user agents y URIs del atacante) | Autoescape de Jinja2, CSP estricta sin scripts inline, nunca `\|safe` sobre datos del log | XSS Prevention |
| Inyección de prompts vía el log | Al modelo solo llegan agregados; textos truncados y marcados como datos; sin herramientas | LLM Prompt Injection Prevention |
| Exposición de credenciales del log | Enmascarado en evidencia, interfaz, logs y prompts; tokens completos solo en `sensitive/`, nunca servido | Secrets Management, Logging |
| API keys (LLM y TI) | Solo escritura y en memoria (`SecretStr`); la interfaz muestra `••••` + 4; formato validado; nunca en caché, artefactos ni custodia | Secrets Management |
| Fuga de claves a terceros (SSRF) | URL fija por proveedor; URLs editables solo http(s) sin credenciales ni query, `http` solo hacia hosts privados; sin seguir redirecciones | SSRF Prevention, TLS |
| Errores verbosos | Mensaje genérico con ID de correlación; errores de proveedores limpiados de claves | Error Handling |
| CSRF | *Double-submit* (cookie + cabecera `X-CSRF-Token`), `SameSite=Strict` | CSRF Prevention |
| *Clickjacking* / *sniffing* | `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `nosniff`, `Referrer-Policy` | HTTP Headers |
| Acceso no autorizado | Escucha en `127.0.0.1`; token opcional `IRP_ACCESS_TOKEN` (comparación en tiempo constante, cookie HMAC `HttpOnly`); aviso si se expone sin token | Authentication, Session Management |
| Envío de datos a terceros | Consentimiento por ejecución para LLM fuera de la red y para TI; solo contexto agregado o IPs públicas; registro en informe y custodia | Gobierno de datos |
| Acciones peligrosas | *Dry-run*, aprobación humana, rechazo por defecto, sin ejecución de comandos del sistema | — |
| Contenedor | Sin root, solo lectura, sin capacidades, `no-new-privileges`, puertos solo en `127.0.0.1`, sin secretos en la imagen | Docker Security |
| Lectura de métricas | `IRP_METRICS_TOKEN` de solo lectura; no autoriza otras rutas; secreto de Compose | Secrets Management |
| Servidor MCP | Ninguna herramienta recibe ni devuelve claves; IPs privadas rechazadas; textos de terceros saneados; auditoría encadenada | MCP Security |

**Integridad**: SHA-256 del original antes de procesar; manifiesto con el hash de cada artefacto; registro de custodia
(`output/custody_log.jsonl`) en el que cada evento incluye el hash del anterior; `idor-ir verify` recalcula todo.

**Recepción de evidencia (carga web)**: el analista diligencia el acta con los datos que no se pueden obtener del
archivo: recolectado por, fecha y hora de recolección, sistema de origen y zona horaria del log (obligatorios), y caso,
ID de evidencia, método de extracción, autorización, receptor, SHA-256 de origen, descripción y observaciones
(opcionales). La plataforma agrega el nombre original, el tamaño, el SHA-256, la fecha de recepción en UTC y la versión
de la herramienta. Guarda el acta junto al CSV (`<archivo>.csv.custody.json`), deja ambos en **solo lectura** y registra
`evidence_received` en la custodia. Al analizar, compara el hash actual con el de la recepción
(`custody_intake_verified` o `custody_hash_mismatch`, que detiene el análisis). Además copia el acta al run como
`custody_intake.json`, incluido en el manifiesto y descargable.

El original nunca se modifica ni se copia byte a byte: el análisis lo **lee** en modo streaming y trabaja sobre la copia
derivada `work/parsed.parquet`. La protección de solo lectura es operativa; la garantía es el hash, porque algunos
montajes (por ejemplo, los de Docker Desktop) no respetan los permisos.

## 10. Validación con el dataset del reto

Resultados del análisis del log del reto (SHA-256 `128f5d7d…aca9841a`). Ningún valor está fijado en el código: sirven
para comprobar que la detección genérica encuentra lo que hay.

| Hallazgo | Dato |
|---|---|
| Tráfico de base | 31 credenciales, ~5 700 IPs, user agents de navegador; consultan ~5 000 facturas en dos bloques de IDs |
| Campaña confirmada (C1) | 4 credenciales usadas desde 5 IPs (malla completa), 61 961 peticiones, user agents de herramientas (Scrapy, crawler4j, wget) |
| Fases de C1 | Oct: 48 peticiones/día, 0 % de éxito · Nov: 504/día, primer 2xx el 2020-11-01 00:04 · Dic: 1 463/día, 94 % de éxito y rango de IDs ampliado |
| Impacto de C1 | 48 827 respuestas 2xx, todas con credencial; 10 181 facturas distintas, 5 232 nunca consultadas por el tráfico normal |
| Actividad por validar (C2) | Herramienta de pruebas de API con credenciales de prueba desde una /24, solo en horario laboral y dentro del rango normal |
| TTD | 103 días desde la primera actividad; 72 desde el primer acceso exitoso (detección: 12-ene-2021) |

## 11. Limitaciones y trabajo futuro

- **Esquema**: supone los 8 campos del log del reto y un ID de objeto numérico en la query; las credenciales en
  cabeceras no aparecen en este formato.
- **Afectados**: límite superior; la cifra exacta requiere cruzar los IDs con la base de datos de la aplicación.
- **TTR/TTC**: estimaciones con supuestos explícitos.
- **Calidad del modelo**: la redacción y el criterio dependen del LLM; el banco de evaluación permite medirlo.
- **Futuro**: detección en ventanas sobre un flujo (SIEM o Kafka), líneas base por cliente, nuevos detectores sobre el
  registro existente, adaptadores para otros formatos de log, ejecución real de contención vía API de WAF/SOAR con
  aprobación, y persistencia cifrada de secretos.
