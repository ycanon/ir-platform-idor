"""Servidor MCP ti-gateway: adaptadores, motor, estado compartido, seguridad y protocolo (sin red ni claves reales)."""

from __future__ import annotations

import json
import multiprocessing as mp
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from pydantic import SecretStr

from ti_gateway.config import GatewayConfig
from ti_gateway.engine import Gateway
from ti_gateway.server import build_server
from ti_gateway.state import StateStore
from ti_gateway.util import IndicatorError, clean_text, normalize_indicator, scrub

KEYS = {  # valores ficticios para pruebas
    "virustotal": "vt-FAKE-0123456789abcdef0123",
    "otx": "otx-FAKE-0123456789abcdef012",
    "abuseipdb": "abuse-FAKE-0123456789abcdef",
    "greynoise": "gn-FAKE-0123456789abcdef0123",
    "ipinfo": "ipinfo-FAKE-0123456789abcd",
    "shodan": "shodan-FAKE-0123456789abcde",
    "abusech": "abusech-FAKE-0123456789abcd",
}
IP = "73.130.229.200"
NO_SLEEP: Any = lambda _s: None  # noqa: E731

PAYLOADS: dict[str, Any] = {
    "www.virustotal.com": {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 20},
                "asn": 7922,
                "as_owner": "COMCAST-7922",
                "country": "US",
                "reputation": -12,
                "tags": ["scanner"],
            }
        }
    },
    "otx.alienvault.com": {
        "pulse_info": {"count": 2, "pulses": [{"name": "Web scanners‮ Q4", "tags": ["scan"]}]},
        "validation": [],
        "country_name": "United States of America",
        "asn": "AS7922 comcast",
    },
    "api.abuseipdb.com": {
        "data": {
            "abuseConfidenceScore": 88,
            "totalReports": 41,
            "numDistinctUsers": 17,
            "isp": "Comcast Cable",
            "usageType": "Fixed Line ISP",
            "countryCode": "US",
            "isWhitelisted": False,
            "isTor": False,
        }
    },
    "api.greynoise.io": {
        "ip": IP,
        "noise": True,
        "riot": False,
        "classification": "malicious",
        "name": "unknown",
        "last_seen": "2026-10-01",
    },
    "api.ipinfo.io": {
        "ip": IP,
        "asn": "AS7922",
        "as_name": "Comcast Cable Communications, LLC",
        "as_domain": "comcast.com",
        "country_code": "US",
        "country": "United States",
    },
    "api.shodan.io": {"ports": [22, 80, 443], "tags": ["compromised"], "org": "Comcast", "vulns": ["CVE-2023-0001"]},
    "threatfox-api.abuse.ch": {
        "query_status": "ok",
        "data": [
            {
                "ioc": f"{IP}:8443",
                "threat_type": "botnet_cc",
                "malware_printable": "Cobalt Strike",
                "confidence_level": 75,
            },
            {"ioc": "73.130.229.20:80", "malware_printable": "Other", "confidence_level": 100},
        ],
    },  # otra IP: se filtra
    "urlhaus-api.abuse.ch": {"query_status": "no_results"},
}


class Upstream:
    """Servicios simulados: registra cada petición y responde según el host."""

    def __init__(self, overrides: dict[str, httpx.Response] | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self.overrides = overrides or {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host = request.url.host
        if host in self.overrides:
            return self.overrides[host]
        return httpx.Response(200, json=PAYLOADS[host])

    def factory(self) -> Any:
        return lambda: httpx.Client(transport=httpx.MockTransport(self), follow_redirects=False)


def make_gateway(tmp_path: Path, upstream: Upstream, keys: dict[str, str] | None = None, **cfg: Any) -> Gateway:
    config = GatewayConfig(
        data_dir=tmp_path / "state",
        keys={k: SecretStr(v) for k, v in (KEYS if keys is None else keys).items()},
        client_name="tests",
        **cfg,
    )
    return Gateway(config, http_factory=upstream.factory(), sleep=NO_SLEEP)


# --------------------------------------------------------------------------- adaptadores y motor
def test_all_sources_normalized_and_aggregated(tmp_path: Path) -> None:
    upstream = Upstream()
    result = make_gateway(tmp_path, upstream).lookup(IP)
    by = {s.source: s for s in result.sources}
    assert {s: by[s].level for s in by} == {
        "virustotal": "malicioso", "otx": "sospechoso", "abuseipdb": "malicioso", "greynoise": "malicioso",
        "ipinfo": "informativo", "shodan": "sospechoso", "abusech": "malicioso",
    }  # fmt: skip
    assert result.verdict == "malicioso" and set(result.sent_to) == set(KEYS)
    assert result.context["asn"] == "AS7922" and result.context["as_name"].startswith("Comcast")  # prioridad IPinfo
    assert (
        by["abusech"].data["threatfox"][0]["malware"] == "Cobalt Strike" and len(by["abusech"].data["threatfox"]) == 1
    )
    assert "‮" not in by["otx"].summary  # control bidi eliminado del texto de terceros
    headers = {r.url.host: r for r in upstream.requests}
    assert headers["www.virustotal.com"].headers["x-apikey"] == KEYS["virustotal"]
    assert headers["api.abuseipdb.com"].headers["key"] == KEYS["abuseipdb"]
    assert headers["api.shodan.io"].url.params["key"] == KEYS["shodan"]  # Shodan lo exige en la URL
    assert headers["threatfox-api.abuse.ch"].headers["auth-key"] == KEYS["abusech"]
    dumped = result.model_dump_json()
    assert not any(v in dumped for v in KEYS.values())  # ninguna clave en el resultado


def test_validation_private_ip_and_types() -> None:
    assert normalize_indicator("EXAMPLE.com") == ("example.com", "domain")
    assert normalize_indicator("d41d8cd98f00b204e9800998ecf8427e")[1] == "hash"
    for bad in ("10.0.0.5", "127.0.0.1", "203.0.113.9", "no es un indicador", "x" * 3000):
        with pytest.raises(IndicatorError):
            normalize_indicator(bad)
    with pytest.raises(IndicatorError, match="parece de tipo"):
        normalize_indicator("8.8.8.8", "domain")


def test_scrub_and_clean_text() -> None:
    assert scrub("GET https://api.shodan.io/x?key=SECRET123&minify=true failed", []) == (
        "GET https://api.shodan.io/x?key=***&minify=true failed"
    )
    assert scrub("bad key SECRETVALUE99", ["SECRETVALUE99"]) == "bad key ***"
    assert clean_text("a\x00b‮c", 10) == "abc" and len(clean_text("x" * 500, 50)) == 50


def test_cache_quota_and_auth_stop(tmp_path: Path) -> None:
    upstream = Upstream()
    gw = make_gateway(tmp_path, upstream, keys={"virustotal": KEYS["virustotal"]}, quota={"virustotal": 2})
    gw.lookup(IP, sources=["virustotal"])
    again = gw.lookup(IP, sources=["virustotal"])
    assert len(upstream.requests) == 1 and again.sources[0].cached and again.sent_to == []  # desde caché
    gw.lookup("8.8.8.8", sources=["virustotal"])
    blocked = gw.lookup("1.1.1.1", sources=["virustotal"])
    assert blocked.sources[0].status == "quota" and len(upstream.requests) == 2  # cupo 2: la tercera no sale

    denied = Upstream(
        {"api.abuseipdb.com": httpx.Response(401, json={"errors": [{"detail": f"bad {KEYS['abuseipdb']}"}]})}
    )
    gw2 = make_gateway(tmp_path / "b", denied, keys={"abuseipdb": KEYS["abuseipdb"]})
    first = gw2.lookup(IP, sources=["abuseipdb"]).sources[0]
    second = gw2.lookup("8.8.8.8", sources=["abuseipdb"]).sources[0]
    assert first.status == "error" and "401" in (first.error or "") and KEYS["abuseipdb"] not in (first.error or "")
    assert second.status == "error" and len(denied.requests) == 1  # tras un 401 no se insiste


def test_not_found_unsupported_and_not_configured(tmp_path: Path) -> None:
    upstream = Upstream({"api.greynoise.io": httpx.Response(404, json={"message": "not observed"})})
    gw = make_gateway(tmp_path, upstream, keys={"greynoise": KEYS["greynoise"]})
    res = gw.lookup(IP, sources=["greynoise", "shodan"])
    gn, sh = res.sources
    assert gn.status == "not_found" and gn.level == "sin reportes" and sh.status == "not_configured"
    domain = gw.lookup("example.com", sources=["greynoise"]).sources[0]
    assert domain.status == "unsupported" and res.verdict == "sin reportes"


def test_audit_chain_has_no_secrets(tmp_path: Path) -> None:
    gw = make_gateway(tmp_path, Upstream())
    gw.lookup(IP)
    gw.check_source("otx")
    text = gw.state.audit_path.read_text(encoding="utf-8")
    assert gw.state.verify_audit() and not any(v in text for v in KEYS.values())
    assert json.loads(text.splitlines()[0])["details"]["sent_to"]
    lines = text.splitlines()
    tampered = json.loads(lines[0])
    tampered["details"]["indicator"] = "1.1.1.1"
    gw.state.audit_path.write_text("\n".join([json.dumps(tampered), *lines[1:]]) + "\n", encoding="utf-8")
    assert not gw.state.verify_audit()


def _consume(args: tuple[str, int]) -> int:
    data_dir, attempts = args
    store = StateStore(Path(data_dir))
    return sum(store.quota_try_consume("virustotal", "day", 30) for _ in range(attempts))


def test_quota_is_shared_between_processes(tmp_path: Path) -> None:
    """Dos copias del gateway (p. ej. la web y Claude Desktop) no pueden superar juntas el cupo diario."""
    with mp.get_context("spawn").Pool(2) as pool:
        granted = pool.map(_consume, [(str(tmp_path), 25), (str(tmp_path), 25)])
    assert sum(granted) == 30 and StateStore(tmp_path).quota_used("virustotal", "day") == 30


# --------------------------------------------------------------------------- protocolo MCP
@pytest.mark.anyio
async def test_mcp_tools_contract(tmp_path: Path) -> None:
    gw = make_gateway(tmp_path, Upstream())
    server = build_server(gw)
    async with create_connected_server_and_client_session(server._mcp_server) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        assert set(tools) == {"ti_list_sources", "ti_lookup", "ti_check_source", "ti_quota_status"}
        for tool in tools.values():  # ninguna herramienta recibe claves
            props = json.dumps(tool.inputSchema.get("properties", {})).lower()
            assert "api_key" not in props and "secret" not in props and "token" not in props
        assert tools["ti_lookup"].annotations and tools["ti_lookup"].annotations.openWorldHint
        listed = await client.call_tool("ti_list_sources", {})
        catalog = listed.structuredContent["result"]  # type: ignore[index]
        assert len(catalog) == 8 and all(s["configured"] for s in catalog if s["id"] != "misp")
        assert not any(v in json.dumps(catalog) for v in KEYS.values())
        # Sin consentimiento (o con granted=false) la herramienta se niega: un agente no puede consultar por su cuenta.
        assert "consent" in tools["ti_lookup"].inputSchema["required"]
        denied = await client.call_tool("ti_lookup", {"indicator": IP, "sources": ["virustotal"]})
        assert denied.isError
        fake = {**CONSENT, "granted": False}
        assert (await client.call_tool("ti_lookup", {"indicator": IP, "consent": fake})).isError
        args = {"indicator": IP, "sources": ["virustotal", "ipinfo"], "consent": CONSENT}
        looked = await client.call_tool("ti_lookup", args)
        assert looked.structuredContent["verdict"] == "malicioso"  # type: ignore[index]
        private = await client.call_tool("ti_lookup", {"indicator": "192.168.1.10", "consent": CONSENT})
        assert private.isError and "privada" in private.content[0].text  # type: ignore[union-attr]
    audit = [json.loads(line) for line in (tmp_path / "state" / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    lookups = [e for e in audit if e["event"] == "lookup"]
    assert lookups and lookups[-1]["details"]["consent"]["granted_by"] == CONSENT["granted_by"]


CONSENT = {"granted": True, "run_id": "20261013T000000Z-abc123", "granted_by": "carlos (aprobador)",
           "purpose": "Reputación de IPs del Top 20"}  # fmt: skip


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# --------------------------------------------------------------------------- MISP (fuente autoalojada)
MISP_URL = "https://misp.empresa.test"
MISP_KEY = "misp-FAKE-0123456789abcdef0123456789"


def _misp_attr(eid: str, to_ids: bool, warnings: list[dict[str, str]] | None = None) -> dict[str, Any]:
    return {
        "id": "1" + eid, "event_id": eid, "type": "ip-dst", "category": "Network activity", "to_ids": to_ids,
        "value": IP, "Event": {"id": eid, "info": f"Campaña de scraping {eid}\x00", "threat_level_id": "1",
                              "date": "2026-09-30", "Orgc": {"name": "CSIRT sectorial"}},
        "Tag": [{"name": "tlp:amber"}, {"name": "misp-galaxy:threat-actor=\"X\""}],
        **({"warnings": warnings} if warnings else {}),
    }  # fmt: skip


def test_misp_lookup_verdicts_and_request(tmp_path: Path) -> None:
    payload = {"response": {"Attribute": [_misp_attr("42", True), _misp_attr("43", False)]}}
    upstream = Upstream({"misp.empresa.test": httpx.Response(200, json=payload)})
    gw = make_gateway(tmp_path, upstream, keys={"misp": MISP_KEY}, urls={"misp": MISP_URL})
    res = gw.lookup(IP, sources=["misp"]).sources[0]
    assert res.status == "ok" and res.level == "malicioso" and res.data["to_ids_count"] == 1
    assert res.permalink == f"{MISP_URL}/events/view/42" and res.data["events"][0]["threat_level"] == "alta"
    assert "\x00" not in res.data["events"][0]["info"] and "tlp:amber" in res.data["tags"]
    req = upstream.requests[0]
    assert req.method == "POST" and str(req.url) == f"{MISP_URL}/attributes/restSearch"
    assert req.headers["authorization"] == MISP_KEY and json.loads(req.content)["value"] == IP
    assert MISP_KEY not in res.model_dump_json()

    # Solo contexto (sin to_ids) + warninglist → baja a "sin reportes" y se marca posible falso positivo.
    warn = [{"warninglist_name": "List of known Amazon AWS IP address ranges"}]
    soft = Upstream({"misp.empresa.test": httpx.Response(200, json={"response": {"Attribute": [
        _misp_attr("50", False, warn)]}})})  # fmt: skip
    res2 = make_gateway(tmp_path / "b", soft, keys={"misp": MISP_KEY}, urls={"misp": MISP_URL}).lookup(
        "8.8.8.8", sources=["misp"]).sources[0]  # fmt: skip
    assert res2.level == "sin reportes" and res2.possible_false_positive

    empty = Upstream({"misp.empresa.test": httpx.Response(200, json={"response": {"Attribute": []}})})
    res3 = make_gateway(tmp_path / "c", empty, keys={"misp": MISP_KEY}, urls={"misp": MISP_URL}).lookup(
        "1.1.1.1", sources=["misp"]).sources[0]  # fmt: skip
    assert res3.status == "not_found" and res3.level == "sin reportes"


def test_misp_requires_url_and_validates_version(tmp_path: Path) -> None:
    upstream = Upstream({"misp.empresa.test": httpx.Response(200, json={"version": "2.5.21"})})
    no_url = make_gateway(tmp_path, upstream, keys={"misp": MISP_KEY})
    assert no_url.lookup(IP, sources=["misp"]).sources[0].status == "not_configured"
    check = no_url.check_source("misp")
    assert not check.ok and "TI_MISP_URL" in check.detail and not upstream.requests
    gw = make_gateway(tmp_path / "b", upstream, keys={"misp": MISP_KEY}, urls={"misp": MISP_URL})
    assert gw.check_source("misp").detail == "Clave válida (MISP 2.5.21)"
    assert str(upstream.requests[0].url) == f"{MISP_URL}/servers/getVersion"
    info = {s.id: s for s in gw.list_sources()}["misp"]
    assert info.needs_url and info.base_url == MISP_URL and info.url_env == "TI_MISP_URL"


# Hosts propios autorizados por el administrador (anti-SSRF): sin esto, la configuración se rechaza al arrancar.
LAB = {"TI_ALLOWED_HOSTS": "misp.local,10.0.0.70,misp.comunidad.example"}


def test_base_url_validation() -> None:
    from ti_gateway.util import BaseURLError, validate_base_url

    assert validate_base_url("https://misp.local/") == "https://misp.local"
    assert validate_base_url("http://10.0.0.50:8080") == "http://10.0.0.50:8080"
    assert validate_base_url("http://localhost:8443") == "http://localhost:8443"  # nombre que resuelve a loopback
    assert validate_base_url("https://misp.comunidad.example") == "https://misp.comunidad.example"  # externa
    for bad in ("ftp://misp.local", "http://misp.example.com", "https://u:p@misp.local", "https://misp.local/?k=1",
                "https://misp.local#x", "misp.local", "http://8.8.8.8"):  # fmt: skip
        with pytest.raises(BaseURLError):
            validate_base_url(bad)
    cfg = GatewayConfig.from_env({**LAB, "TI_MISP_URL": "https://misp.local/", "TI_MISP_API_KEY": "k" * 20})
    assert cfg.urls == {"misp": "https://misp.local"}
    with pytest.raises(BaseURLError):
        GatewayConfig.from_env({"TI_MISP_URL": "http://misp.example.com"})
    with pytest.raises(BaseURLError, match="TI_ALLOWED_HOSTS"):  # host válido pero no autorizado (anti-SSRF)
        GatewayConfig.from_env({"TI_MISP_URL": "https://misp.local/"})


# --------------------------------------------------------------------------- diagnóstico de conexión y CA propia
TEST_CERT = """-----BEGIN CERTIFICATE-----
MIIDGjCCAgKgAwIBAgIUJLmvUsewWPnL/nm/ddjdGJGcUW8wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJMTI3LjAuMC4xMB4XDTI2MTAwNjAxNDE0OVoXDTI2MTAw
ODAxNDE0OVowFDESMBAGA1UEAwwJMTI3LjAuMC4xMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAulA+GjnPb/IflIw0FJDRBtesx2fuzLdGFACIJZ/hrakk
ZhEEFBQP6ObdQ5Jx6Mw7l2pksO+vwAV0Tn87PzKTkvGMHacP4ryENVpKP0166iwW
6zIINjZ6ubejcgoZewf/auGgfMDHXz6ac8F3RrDdb2zv1wVGYOxlEk/S3cwqmUOI
2SGXupZpzfJN8lEWnrc4aleyxBp1HJ6mbKeUuky6xW9PDn7QPzuxXDma3CziltRA
SxcEZeeCh0XviwaH0e+e5+QPA3Q4zfHSCrk7pILRDsH5PNuiG763hTfhhVav2zuU
OA+XWrE91sPO2/BsEd0wsRvsVfjHrcgnIkQgADGcewIDAQABo2QwYjAdBgNVHQ4E
FgQUvsQSwvhc6LJVbOnfPU8hv2i3cTQwHwYDVR0jBBgwFoAUvsQSwvhc6LJVbOnf
PU8hv2i3cTQwDwYDVR0TAQH/BAUwAwEB/zAPBgNVHREECDAGhwR/AAABMA0GCSqG
SIb3DQEBCwUAA4IBAQA3KGlJ2ifmTXe1Nk+zhIVuNExm8Te+43J0C9TOelgYsdZm
W+8U4tjGBvkMwyObl+SfMtkIMlTQ/Ob/lhdNVIbd3LF902Cha4CDxdQhi7wbrxr9
GT79g06qWT3U5stM0Me9nmfkSmUrhCNv95dw2VbddtjPymOqS6WKIjvYrowFlYmT
huzy5a8WCUTKjGw27GSY4GIAU5WVLH3Axczy7XeXkCiQfAubVbXcR78hjtv5T43Q
doevAe4Y4TPVDxXWZs3c6ISWCaiUeCGFSGer7qNrgXs5GG1tnFIG5mW9SFi0TV9K
PJgOeIstZ/QSkGqlYWYjVyT1lHczakmrQH505pAn
-----END CERTIFICATE-----
"""  # autofirmado de prueba (IP:127.0.0.1); es público, no secreto


def test_connection_errors_are_explained() -> None:
    import ssl

    from ti_gateway.util import describe_connection_error

    def msg(text: str, cls: type[Exception] = httpx.ConnectError) -> str:
        return describe_connection_error(cls(text))

    assert "autofirmado" in msg("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate")
    assert "no reconoce" in msg("[SSL: CERTIFICATE_VERIFY_FAILED] unable to get local issuer certificate")
    assert "no corresponde" in msg("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: IP address mismatch")
    assert "no responde HTTPS" in msg("[SSL: WRONG_VERSION_NUMBER] wrong version number")
    assert "rechazada" in msg("[WinError 10061] No se puede establecer una conexión")
    assert "tiempo de espera" in msg("timed out", httpx.ConnectTimeout)
    assert "key=***" in msg("GET https://x/y?key=SECRETO123 failed")  # sin secretos en el mensaje
    assert ssl  # (import usado solo para documentar el origen de los textos)


def test_ca_pem_validation_and_gateway_config(tmp_path: Path) -> None:
    from ti_gateway.util import BaseURLError, pem_fingerprint, validate_ca_pem

    pem = validate_ca_pem("texto previo\n" + TEST_CERT)
    assert pem.startswith("-----BEGIN CERTIFICATE-----") and len(pem_fingerprint(pem)) > 10
    for bad in ("hola", TEST_CERT + "\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
                "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"):  # fmt: skip
        with pytest.raises(BaseURLError):
            validate_ca_pem(bad)
    cfg = GatewayConfig.from_env({"TI_MISP_URL": "https://127.0.0.1:8443", "TI_MISP_CA_PEM": TEST_CERT})
    assert "misp" in cfg.ca_pems
    provider = cfg.build_providers()["misp"]
    assert provider.base_url == "https://127.0.0.1:8443"


def test_tls_verification_can_be_skipped_only_for_internal_instances() -> None:
    from ti_gateway.util import BaseURLError

    cfg = GatewayConfig.from_env({**LAB, "TI_MISP_URL": "https://10.0.0.70", "TI_MISP_TLS_VERIFY": "0"})
    assert cfg.tls_insecure == {"misp"} and cfg.build_providers()["misp"].tls_verify is False
    assert GatewayConfig.from_env({**LAB, "TI_MISP_URL": "https://10.0.0.70"}).build_providers()["misp"].tls_verify
    with pytest.raises(BaseURLError):  # nunca hacia Internet
        GatewayConfig.from_env({**LAB, "TI_MISP_URL": "https://misp.comunidad.example", "TI_MISP_TLS_VERIFY": "0"})
