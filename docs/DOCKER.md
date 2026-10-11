# Despliegue con Docker Compose

La plataforma corre en **un contenedor** (interfaz web, CLI y servidor MCP `ti-gateway`). Dos perfiles opcionales
agregan un **LLM local** (Ollama) y **observabilidad** (Prometheus y Grafana con un tablero aprovisionado).

```
Equipo anfitrión (Linux, macOS o Windows)
┌──────────────────────────────────────────────────────────────┐
│  irp  (usuario sin privilegios, sistema de archivos de solo   │──► Ollama del anfitrión (host.docker.internal)
│        lectura)  127.0.0.1:8000 ◄── navegador                │──► servicios en la red (Ollama, MISP)
│        ./data → /data    ./output → /output                  │──► APIs de inteligencia de amenazas
│                                                              │
│  perfil "ollama"          ollama (red interna, sin puertos)  │
│  perfil "observabilidad"  prometheus 127.0.0.1:9090          │
│                           grafana    127.0.0.1:3000          │
└──────────────────────────────────────────────────────────────┘
```

| Archivo | Contenido |
|---|---|
| `Dockerfile` | Imagen de dos etapas (instalación → ejecución), usuario sin privilegios, healthcheck |
| `.dockerignore` | Deja fuera `data/`, `output/`, `.env`, `.git/`, CSV y Parquet: ninguna evidencia ni secreto entra a la imagen |
| `docker-compose.yml` | Servicio `irp` y perfiles `ollama` y `observabilidad` |
| `observability/prometheus.yml` | Lectura de `/metrics` con token de solo lectura |
| `observability/grafana/` | Fuente de datos y tablero aprovisionados |

## 1. Requisitos

- **Docker Engine** (Linux) o **Docker Desktop** (macOS, Windows), con **Compose v2.23 o superior**
  (`docker compose version`). Alternativas compatibles: Rancher Desktop (motor *dockerd/moby*), OrbStack o Colima.
- Docker Desktop requiere suscripción en organizaciones grandes; las alternativas anteriores no.
- **Memoria**: analizar ~4,5 M filas necesita 3–4 GB para el contenedor. En Docker Desktop, ajústelo en
  *Settings → Resources* (en Windows con WSL2, en `%UserProfile%\.wslconfig`: `[wsl2]` / `memory=6GB`).

## 2. Configurar

```bash
cp .env.example .env                 # Windows (PowerShell): Copy-Item .env.example .env
```

**Linux:** el contenedor escribe en `./data` y `./output` con un usuario sin privilegios. Use el suyo para que los
archivos le pertenezcan:

```bash
echo "IRP_UID=$(id -u)" >> .env
echo "IRP_GID=$(id -g)" >> .env
```

En macOS y Windows (Docker Desktop) no hace falta.

Variables relevantes en `.env` (las rutas `IRP_DATA_DIR` / `IRP_OUTPUT_DIR` no aplican: Compose usa `/data` y `/output`):

| Variable | Para qué | Por defecto |
|---|---|---|
| `IRP_OLLAMA_BASE_URL` | Servidor Ollama visto **desde el contenedor** | `http://host.docker.internal:11434` (Ollama del anfitrión) |
| `IRP_ACCESS_TOKEN` | Login de la interfaz (recomendado) | vacío |
| `IRP_METRICS_TOKEN` | Token de **solo lectura** para que Prometheus lea `/metrics` (obligatorio con `observabilidad`) | vacío |
| `GRAFANA_ADMIN_PASSWORD` | Clave del usuario `admin` de Grafana (obligatoria con `observabilidad`) | vacío |
| `IRP_PORT`, `PROMETHEUS_PORT`, `GRAFANA_PORT` | Puertos locales si 8000/9090/3000 están ocupados | 8000 / 9090 / 3000 |

Genere valores aleatorios con `openssl rand -base64 32` (o, en PowerShell,
`[Convert]::ToBase64String((1..32 | % { Get-Random -Maximum 256 }) -as [byte[]])`).

> `localhost` dentro del contenedor es el propio contenedor: no lo use en `IRP_OLLAMA_BASE_URL` para Docker.

Las claves de VirusTotal, OTX, MISP, etc. se recomiendan **por la interfaz** (quedan solo en memoria).

## 3. Levantar

```bash
docker compose up -d --build
docker compose ps                    # irp debe quedar "healthy"  → http://127.0.0.1:8000
```

Coloque los logs en `./data` (o cárguelos desde la interfaz); los resultados quedan en `./output`. Son las mismas
carpetas que usa la instalación local, así que un análisis hecho en Docker se ve también desde la CLI local.

Las cargas desde la interfaz quedan en `./data/uploads` en solo lectura, con su acta de cadena de custodia
(`*.csv.custody.json`). En Docker Desktop (Windows/macOS) el montaje puede no respetar ese permiso; la integridad la
garantiza el SHA-256 registrado al recibir el archivo, que se verifica antes de cada análisis.

### Perfil `ollama`: LLM local en un contenedor

Para quien no tiene Ollama instalado. En `.env`: `IRP_OLLAMA_BASE_URL=http://ollama:11434`.

```bash
docker compose --profile ollama up -d --build
docker compose exec ollama ollama pull qwen3:4b-instruct-2507-q4_K_M    # ~2,5 GB, una sola vez
docker compose exec irp python -m idor_ir llm-check
```

El modelo queda en el volumen `ollama-models`. Funciona en CPU; para GPU NVIDIA, agregue la reserva de dispositivos
según la [documentación de Docker](https://docs.docker.com/compose/how-tos/gpu-support/).

### Perfil `observabilidad`: Prometheus y Grafana

Requiere `IRP_METRICS_TOKEN` y `GRAFANA_ADMIN_PASSWORD` en `.env`.

```bash
docker compose --profile observabilidad up -d --build
```

- Prometheus: <http://127.0.0.1:9090/targets> (`ir-platform` debe estar **UP**).
- Grafana: <http://127.0.0.1:3000> (usuario `admin`) → *Dashboards → IR Platform*: análisis, agentes (LLM o
  determinista), aprobaciones, revisión de las salidas del modelo, conversación y HTTP.

Los perfiles se combinan: `docker compose --profile ollama --profile observabilidad up -d --build`.

### CLI dentro del contenedor

```bash
docker compose exec irp python -m idor_ir analyze --file /data/<log>.csv --detection-date 2021-01-12
docker compose exec irp python -m idor_ir agents --run <RUN_ID> --approve all
docker compose exec irp python -m idor_ir verify --run <RUN_ID> --file /data/<log>.csv
```

### Operación

```bash
docker compose logs -f irp                       # registros (sin secretos)
docker compose down                              # detener (./data y ./output se conservan)
docker compose --profile observabilidad down -v  # además borra los volúmenes (métricas, tableros, modelos)
docker compose up -d --build                     # tras actualizar el código
```

## 4. Comprobaciones

| Comprobación | Resultado esperado |
|---|---|
| `docker compose ps` | `irp ... (healthy)` |
| `curl http://127.0.0.1:8000/api/health` | `{"status":"ok", ...}` |
| Analizar un log desde la interfaz | Carpeta nueva en `./output` |
| `docker compose exec irp python -m idor_ir llm-check` | LLM accesible y esquemas aceptados (si configuró uno) |
| `curl -i http://127.0.0.1:8000/metrics` (con `IRP_METRICS_TOKEN`) | `401` sin el token |
| `docker compose exec irp touch /x` | `Read-only file system` |

## 5. Redes internas, MISP y certificados

- **Servicios en la red** (Ollama en otro servidor, MISP): el contenedor sale con la IP del anfitrión, así que las
  reglas de firewall o listas de IP permitidas que ya incluyan al anfitrión siguen valiendo.
- **Nombres que solo resuelve el archivo `hosts` del anfitrión**: el contenedor no lo lee. Agréguelos a
  `extra_hosts` del servicio `irp` (p. ej. `"misp.example.internal:10.0.0.70"`) o use la IP en la URL.
- **CA interna de MISP**: péguela en *Configuración → MISP → Certificado TLS*. Omitir la verificación TLS es una
  excepción de laboratorio, limitada a URLs internas y registrada en la cadena de custodia (ver [`MCP.md`](MCP.md)).
- **Proxy con inspección TLS** (si la construcción falla con `CERTIFICATE_VERIFY_FAILED`): pase la CA como secreto de
  compilación; no queda en ninguna capa de la imagen.

  ```bash
  docker build --secret id=build_ca,src=/ruta/ca-corporativa.pem -t ir-platform:0.13.0 .
  docker compose up -d
  ```

- **Registro interno**: si Docker Hub no está disponible, use su espejo con
  `IRP_PYTHON_IMAGE=registro.example.internal/python:3.12-slim-bookworm` (y `OLLAMA_IMAGE` para el perfil `ollama`).

## 6. Controles de seguridad (OWASP Docker Security Cheat Sheet)

| Control | Implementación |
|---|---|
| Sin root | Usuario `irp` (uid 10001) en la imagen; `user:` configurable en Compose |
| Puertos solo locales | Todo se publica en `127.0.0.1`; Prometheus y Ollama se comunican por la red interna de Compose |
| Sin capacidades ni escalada | `cap_drop: [ALL]` y `no-new-privileges:true` |
| Sistema de archivos de solo lectura | `read_only: true` en la plataforma; escritura solo en `/data`, `/output` y `tmpfs` privados |
| Límite de procesos | `pids_limit: 512` |
| Sin secretos en la imagen | `.dockerignore` excluye `.env`, datos y evidencia; los tokens de Prometheus y Grafana son **secretos de Compose** (archivos en `/run/secrets`, no variables visibles en `docker inspect`) |
| `/metrics` autenticado | Con `IRP_METRICS_TOKEN`, `/metrics` exige `Authorization: Bearer` aunque la interfaz no tenga login; ese token no abre la API |
| Grafana cerrado | Sin registro ni acceso anónimo, sin telemetría ni descarga de plugins |
| Versiones fijadas | Python `3.12-slim-bookworm`, Prometheus `v3.1.0`, Grafana `11.4.0`; Ollama configurable con `OLLAMA_IMAGE` |
| Healthcheck | `/api/health` cada 30 s |

## 7. Problemas frecuentes

| Síntoma | Causa y solución |
|---|---|
| `irp` se reinicia con `Permission denied` en `/data` u `/output` (Linux) | Defina `IRP_UID` / `IRP_GID` con su usuario (sección 2), o `sudo chown -R 10001:10001 data output` |
| Los agentes usan la lógica determinista (`fallback`) | El LLM no responde desde el contenedor: `docker compose exec irp python -m idor_ir llm-check` y revise `IRP_OLLAMA_BASE_URL` |
| Ollama del anfitrión rechaza la conexión (Linux) | Ollama escucha solo en `127.0.0.1`: inícielo con `OLLAMA_HOST=0.0.0.0:11434` y limite el puerto con el firewall |
| Prometheus muestra el target `DOWN` con `401` | `IRP_METRICS_TOKEN` vacío o distinto: defínalo y ejecute `docker compose --profile observabilidad up -d --force-recreate` |
| `environment variable "IRP_METRICS_TOKEN" required by secret ... is not set` | Falta `IRP_METRICS_TOKEN` o `GRAFANA_ADMIN_PASSWORD` en `.env` al usar el perfil `observabilidad` |
| Análisis lento | Las carpetas compartidas desde Windows o macOS hacia la VM de Docker son más lentas que un disco Linux nativo; asigne más memoria o clone el repositorio dentro del sistema de archivos de WSL2 |
| Puerto ocupado | Cambie `IRP_PORT`, `PROMETHEUS_PORT` o `GRAFANA_PORT` en `.env` |
