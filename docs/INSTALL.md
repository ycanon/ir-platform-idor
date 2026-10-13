# Instalación local

Guía para ejecutar IR Platform en un entorno virtual de Python, sin Docker. Para contenedores, ver
[`DOCKER.md`](DOCKER.md).

## Requisitos

| Componente | Versión | Para qué |
|---|---|---|
| Python | 3.12 o 3.13 | Plataforma, CLI y pruebas |
| Git | reciente | Clonar el repositorio |
| Memoria | 4 GB libres o más | Analizar un log de ~1 GB / 4,5 M filas |
| Ollama u otro LLM | opcional | Agentes con GenAI (sin LLM usan su lógica determinista) |

## 1. Python y Git

| Sistema | Comando |
|---|---|
| Debian / Ubuntu | `sudo apt install python3.12 python3.12-venv git` (en versiones antiguas, use el PPA *deadsnakes* o `pyenv`) |
| Fedora / RHEL | `sudo dnf install python3.12 git` |
| macOS (Homebrew) | `brew install python@3.12 git` |
| Windows | `winget install -e --id Python.Python.3.12` y `winget install -e --id Git.Git` |

## 2. Entorno virtual y dependencias

Linux / macOS:

```bash
git clone https://github.com/ycanon/ir-platform-idor.git
cd ir-platform-idor
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
cp .env.example .env
```

Windows (PowerShell):

```powershell
git clone https://github.com/ycanon/ir-platform-idor.git
cd ir-platform-idor
py -3.12 -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass   # solo si PowerShell bloquea el script de activación
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
Copy-Item .env.example .env
```

`.env` no se versiona. Todas sus variables son opcionales; las más usadas:

| Variable | Por defecto | Descripción |
|---|---|---|
| `IRP_DATA_DIR` / `IRP_OUTPUT_DIR` | `data` / `output` | Logs de entrada y resultados |
| `IRP_TIMESTAMP_FORMAT` | `%Y-%d-%mT%H:%M` | Formato del timestamp; `auto` para autodetectar |
| `IRP_PROFILE_MODE` | `auto` | `auto` detecta el perfil del incidente del dataset; `fixed` usa los valores de `.env` |
| `IRP_DETECTION_DATE` | vacío | Fecha de detección por defecto para el TTD |
| `IRP_OLLAMA_BASE_URL` | `http://localhost:11434` | Servidor Ollama |
| `IRP_OLLAMA_MODEL` | `qwen3:4b-instruct-2507-q4_K_M` | Modelo de los agentes |
| `IRP_ACCESS_TOKEN` | vacío | Login de la interfaz (obligatorio si se expone fuera de `127.0.0.1`) |

La lista completa, comentada, está en [`.env.example`](../.env.example).

## 3. LLM (opcional)

Los agentes funcionan sin LLM con una lógica determinista equivalente. Para usar GenAI con un modelo local:

1. Instale [Ollama](https://ollama.com/download) (Linux: `curl -fsSL https://ollama.com/install.sh | sh`;
   macOS y Windows: instalador oficial).
2. Descargue el modelo por defecto (~2,5 GB; funciona en CPU con 16 GB de RAM):

   ```bash
   ollama pull qwen3:4b-instruct-2507-q4_K_M
   ```

3. Si Ollama corre en **otro equipo**, defina en `.env` `IRP_OLLAMA_BASE_URL=http://<servidor>:11434` y, en ese
   servidor, haga que escuche en la red (`OLLAMA_HOST=0.0.0.0:11434`). Ollama no tiene autenticación: limite el puerto
   11434 con el firewall a las IP que deban usarlo.

Alternativas: en la pestaña *Configuración* se puede elegir un endpoint compatible con OpenAI (LM Studio, vLLM) o una
API en la nube (Anthropic, OpenAI, Gemini, DeepSeek, Mistral, Groq, xAI, OpenRouter). Las claves se ingresan en la
interfaz, viven solo en memoria y, si el proveedor está fuera de la red local, cada ejecución pide autorización
explícita para enviar el contexto agregado.

## 4. Ejecutar

```bash
python -m idor_ir serve                          # interfaz web → http://127.0.0.1:8000
python -m idor_ir analyze --file data/<log>.csv  # análisis desde la CLI
python -m idor_ir llm-check                      # comprueba la conexión con el LLM
python -m idor_ir validate-detector              # precisión/recall/FP del detector (banco sintético)
```

**Acceso desde otra máquina** (fail-closed): `serve --host 0.0.0.0` solo arranca con `IRP_ACCESS_TOKEN` de al menos
16 caracteres en `.env`; para separar funciones defina además `IRP_APPROVER_TOKEN` (distinto). Sirva por HTTPS con
`--ssl-certfile cert.pem --ssl-keyfile key.pem` o detrás de un proxy TLS (`IRP_TRUSTED_PROXIES`, `IRP_COOKIE_SECURE=true`).

**Ollama u otro LLM en otra máquina de la red:** agregue su host a `IRP_LLM_ALLOWED_HOSTS` (control anti-SSRF); el
host de `IRP_OLLAMA_BASE_URL` ya queda autorizado.

## 5. Verificar la instalación

```bash
pytest                                           # todas las pruebas en verde
ruff check src tests
mypy
python -m idor_ir llm-check                      # solo si configuró un LLM
```
