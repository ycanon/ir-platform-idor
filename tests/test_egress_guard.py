"""Control de salida anti-SSRF (retroalimentación del evaluador): lista blanca, IPs prohibidas y DNS rebinding.

Sin red externa: la resolución DNS se simula y el único servidor real es uno local en 127.0.0.1.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest

from egress_guard import EgressError, EgressPolicy, GuardedTransport
from idor_ir.agents import providers
from idor_ir.config import Settings

pytestmark = pytest.mark.no_test_allowlist

POLICY = EgressPolicy(allowed_hosts=("localhost", "127.0.0.1", "ollama.lan"), fixed_hosts=frozenset({"api.openai.com"}))


def _fake_dns(monkeypatch: pytest.MonkeyPatch, answers: dict[str, list[str]]) -> None:
    real = socket.getaddrinfo

    def fake(host: str, port: object, *args: object, **kwargs: object) -> list[tuple]:  # type: ignore[type-arg]
        if host in answers:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in answers[host]]
        return real(host, port, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(socket, "getaddrinfo", fake)


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",  # metadatos de nube
        "http://[fe80::1]:11434",  # link-local IPv6
        "http://0.0.0.0:11434",
        "https://internal-api.corp.example/v1",  # no autorizado por el administrador
    ],
)
def test_configuration_rejects_unlisted_or_forbidden_destinations(url: str) -> None:
    with pytest.raises(EgressError):
        POLICY.check_url(url)


def test_ui_cannot_point_llm_to_unlisted_host() -> None:
    providers.configure_egress(Settings())
    with pytest.raises(ValueError, match="IRP_LLM_ALLOWED_HOSTS"):
        providers.validate_base_url("http://10.9.9.9:11434")
    assert providers.validate_base_url("http://localhost:11434") == "http://localhost:11434"
    providers.configure_egress(Settings(llm_allowed_hosts="10.9.9.9"))  # el administrador lo autoriza
    assert providers.validate_base_url("http://10.9.9.9:11434") == "http://10.9.9.9:11434"


def test_dns_rebinding_of_a_public_provider_to_internal_ip_is_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_dns(monkeypatch, {"api.openai.com": ["10.0.0.1"]})
    with pytest.raises(EgressError, match="rebinding"):
        POLICY.resolve("api.openai.com", 443)


def test_allowlisted_name_resolving_to_metadata_is_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_dns(monkeypatch, {"ollama.lan": ["192.168.1.20", "169.254.169.254"]})  # TODAS las IPs se verifican
    with pytest.raises(EgressError, match="prohibida"):
        POLICY.resolve("ollama.lan", 11434)


@pytest.fixture
def local_server() -> Iterator[tuple[int, list[str]]]:
    seen: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            seen.append(self.headers.get("Host", ""))
            body = b'{"models": []}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1], seen
    server.shutdown()


def test_connection_is_pinned_to_the_verified_ip(
    local_server: tuple[int, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Se conecta a la IP verificada; el nombre original viaja en Host (y en SNI con HTTPS)."""
    port, seen = local_server
    _fake_dns(monkeypatch, {"ollama.lan": ["127.0.0.1"]})
    with httpx.Client(transport=GuardedTransport(POLICY), follow_redirects=False) as http:
        assert http.get(f"http://ollama.lan:{port}/api/tags").status_code == 200
        with pytest.raises(EgressError):
            http.get(f"http://not-allowed.example:{port}/")
    assert seen == [f"ollama.lan:{port}"]


def test_ti_allowlist_is_read_from_dotenv(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    """En el entorno virtual, TI_ALLOWED_HOSTS del .env también aplica (no solo las variables IRP_)."""
    from idor_ir.config import export_env_passthrough
    from ti_gateway.util import BaseURLError, validate_base_url

    monkeypatch.setenv("TI_ALLOWED_HOSTS", "")  # registrado: se restaura al terminar
    with pytest.raises(BaseURLError, match="TI_ALLOWED_HOSTS"):
        validate_base_url("https://misp.lab.example")
    (tmp_path / ".env").write_text("TI_ALLOWED_HOSTS=misp.lab.example\n", encoding="utf-8")
    export_env_passthrough(tmp_path / ".env")
    assert validate_base_url("https://misp.lab.example") == "https://misp.lab.example"
