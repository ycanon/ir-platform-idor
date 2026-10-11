"""Guardas sobre los archivos de despliegue (Docker Compose) para que el endurecimiento no se pierda."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_compose_publishes_only_on_localhost() -> None:
    ports = re.findall(r'^\s*-\s*"([^"]+:\d+)"\s*$', _read("docker-compose.yml"), flags=re.M)
    assert ports, "no se encontraron puertos publicados"
    assert all(p.startswith("127.0.0.1:") for p in ports), ports


def test_compose_hardening_and_no_inline_secrets() -> None:
    compose = _read("docker-compose.yml")
    for control in ("read_only: true", "cap_drop: [ALL]", "no-new-privileges:true", 'user: "${IRP_UID'):
        assert control in compose, control
    # Los secretos llegan del .env como secretos de Compose, nunca escritos en el archivo.
    assert "environment: IRP_METRICS_TOKEN" in compose
    assert "GF_SECURITY_ADMIN_PASSWORD__FILE" in compose
    assert not re.search(r"(PASSWORD|TOKEN|API_KEY)\s*[:=]\s*['\"]?[A-Za-z0-9]{6,}", compose.replace("__FILE", ""))


def test_dockerfile_runs_unprivileged_with_healthcheck() -> None:
    dockerfile = _read("Dockerfile")
    assert re.search(r"^USER irp$", dockerfile, flags=re.M)
    assert "HEALTHCHECK" in dockerfile and "/api/health" in dockerfile
    assert not re.search(r"^(ENV|ARG)\s+\S*(KEY|TOKEN|PASSWORD|SECRET)", dockerfile, flags=re.M | re.I)


def test_dockerignore_keeps_evidence_and_secrets_out() -> None:
    ignored = set(_read(".dockerignore").split())
    assert {"data/", "output/", ".env", ".git/", "*.parquet", "*.csv"} <= ignored


def test_prometheus_uses_token_file_and_grafana_dashboard_is_valid() -> None:
    prom = _read("observability/prometheus.yml")
    assert "credentials_file: /run/secrets/metrics_token" in prom and "irp:8000" in prom
    dash = json.loads(_read("observability/grafana/dashboards/ir-platform.json"))
    exprs = [t["expr"] for p in dash["panels"] for t in p.get("targets", [])]
    assert exprs and all(re.search(r"\birp_\w+", e) for e in exprs)
    ids = [p["id"] for p in dash["panels"]]
    assert len(ids) == len(set(ids))
