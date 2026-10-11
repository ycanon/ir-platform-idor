# IR Platform — investigación y respuesta automatizada ante incidentes IDOR.
#
# Imagen de dos etapas: la primera instala la plataforma en un entorno virtual; la final solo copia ese entorno
# (sin compiladores ni caché de pip) y corre como usuario sin privilegios. El servidor MCP ti-gateway va en la
# misma imagen: la plataforma lo lanza como subproceso stdio cuando se consulta inteligencia de amenazas.
# Ollama NO va en la imagen: es un servicio externo (en el mismo equipo o en la red) que se configura con
# IRP_OLLAMA_BASE_URL [SPECS D8].
#
# Controles (OWASP Docker Security Cheat Sheet): usuario no root, imagen base slim fijada por versión, sin
# secretos en la imagen (las claves llegan por .env o por la UI y viven solo en memoria), healthcheck, y en
# docker-compose.yml: puerto publicado solo en 127.0.0.1, sistema de archivos de solo lectura, sin capacidades
# de Linux y no-new-privileges.

ARG PYTHON_IMAGE=python:3.12-slim-bookworm

# --------------------------------------------------------------------------- etapa 1: instalación
FROM ${PYTHON_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /src
RUN python3 -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
# Primero solo los metadatos: las dependencias quedan en una capa cacheable aunque cambie el código.
COPY pyproject.toml README.md ./
RUN python -c "import tomllib; print(chr(10).join(tomllib.load(open('pyproject.toml', 'rb'))['project']['dependencies']))" \
    > /tmp/requirements.txt
# CA corporativa OPCIONAL solo para la descarga de paquetes (proxy con inspección TLS). Se pasa como secreto de
# BuildKit y NO queda en ninguna capa:  docker build --secret id=build_ca,src=/ruta/ca-corporativa.pem .
RUN --mount=type=secret,id=build_ca \
    if [ -s /run/secrets/build_ca ]; then export PIP_CERT=/run/secrets/build_ca; fi; \
    pip install --upgrade pip && pip install -r /tmp/requirements.txt
COPY src ./src
RUN --mount=type=secret,id=build_ca \
    if [ -s /run/secrets/build_ca ]; then export PIP_CERT=/run/secrets/build_ca; fi; \
    pip install --no-deps . && python -c "import idor_ir, ti_gateway; print('ok', idor_ir.__version__)"

# --------------------------------------------------------------------------- etapa 2: ejecución
FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.title="IR Platform - IDOR" \
      org.opencontainers.image.description="Investigación y respuesta automatizada ante incidentes IDOR" \
      org.opencontainers.image.licenses="MIT"
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/irp \
    IRP_DATA_DIR=/data \
    IRP_OUTPUT_DIR=/output \
    POLARS_TEMP_DIR=/output/.tmp \
    JOBLIB_TEMP_FOLDER=/output/.tmp
RUN groupadd --system --gid 10001 irp \
    && useradd --system --uid 10001 --gid irp --home-dir /home/irp --create-home --shell /usr/sbin/nologin irp \
    && mkdir -p /data /output /app \
    && chown irp:irp /data /output
COPY --from=build /opt/venv /opt/venv
USER irp
# Directorio de trabajo de solo lectura (sin .env dentro: la configuración llega por variables de entorno).
WORKDIR /app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"]
# Dentro del contenedor escucha en 0.0.0.0; docker-compose.yml lo publica SOLO en 127.0.0.1 del equipo.
CMD ["python", "-m", "idor_ir", "serve", "--host", "0.0.0.0", "--port", "8000"]
