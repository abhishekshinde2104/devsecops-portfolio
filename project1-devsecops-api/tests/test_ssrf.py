"""SSRF guard (A10:2021, API7:2023). DNS is faked so tests never touch the network."""

from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app import ssrf
from app.ssrf import FetchResult, OutboundRequestBlocked, validate_url


def fake_resolver(*ips: str):
    def _resolve(host, port, type=0):
        family = socket.AF_INET6 if ":" in ips[0] else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]

    return _resolve


PUBLIC = fake_resolver("93.184.215.14")


def test_public_https_url_allowed(settings):
    target = validate_url("https://example.com/page?x=1", settings, PUBLIC)
    assert target.host == "example.com" and target.port == 443 and target.path == "/page?x=1"
    assert str(target.ip) == "93.184.215.14"


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",  # loopback
        "10.0.0.5",  # RFC1918
        "172.16.3.4",
        "192.168.1.1",
        "169.254.169.254",  # link-local / cloud metadata
        "100.64.0.1",  # CGNAT
        "0.0.0.0",
        "::1",
        "fd00::1",  # unique local
        "fe80::1",  # link-local v6
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
        "224.0.0.1",  # multicast
    ],
)
def test_non_public_resolution_blocked(settings, ip):
    with pytest.raises(OutboundRequestBlocked) as exc:
        validate_url("https://innocent-looking.example/", settings, fake_resolver(ip))
    assert exc.value.reason == "non_public_address"


def test_mixed_public_and_private_records_blocked(settings):
    with pytest.raises(OutboundRequestBlocked):
        validate_url("https://rebind.example/", settings, fake_resolver("93.184.215.14", "10.0.0.1"))


@pytest.mark.parametrize(
    "url,reason",
    [
        ("http://example.com/", "scheme_not_allowed"),
        ("file:///etc/passwd", "scheme_not_allowed"),
        ("gopher://example.com/", "scheme_not_allowed"),
        ("https://user:pw@example.com/", "credentials_in_url"),
        ("https://example.com:22/", "port_not_allowed"),
        ("https:///nohost", "missing_host"),
        ("https://example.com:99999/", "malformed_url"),
    ],
)
def test_url_shape_checks(settings, url, reason):
    with pytest.raises(OutboundRequestBlocked) as exc:
        validate_url(url, settings, PUBLIC)
    assert exc.value.reason == reason


def test_dns_failure_blocked(settings):
    def failing(*_a, **_k):
        raise socket.gaierror("no such host")

    with pytest.raises(OutboundRequestBlocked) as exc:
        validate_url("https://does-not-exist.example/", settings, failing)
    assert exc.value.reason == "dns_resolution_failed"


def test_host_allowlist(settings):
    restricted = settings.model_copy(update={"outbound_allowed_hosts": ["pay.example.com"]})
    assert validate_url("https://pay.example.com/", restricted, PUBLIC).host == "pay.example.com"
    with pytest.raises(OutboundRequestBlocked) as exc:
        validate_url("https://evil.example.net/", restricted, PUBLIC)
    assert exc.value.reason == "host_not_allowlisted"


def test_endpoint_returns_400_for_blocked_url(client, alice, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_resolver("169.254.169.254"))
    resp = client.post("/integrations/url-preview", json={"url": "https://metadata.example/"}, headers=alice)
    assert resp.status_code == 400
    assert "non_public_address" in resp.json()["detail"]
    assert "169.254" not in resp.text  # resolved IP is never echoed back


def test_endpoint_happy_path(client, alice, monkeypatch):
    monkeypatch.setattr(ssrf, "fetch_preview", lambda url, settings: FetchResult(200, "text/html", "Hello", None))
    resp = client.post("/integrations/url-preview", json={"url": "https://example.com/"}, headers=alice)
    assert resp.status_code == 200 and resp.json()["title"] == "Hello"


def test_endpoint_requires_auth(client):
    assert client.post("/integrations/url-preview", json={"url": "https://example.com/"}).status_code == 401


# ------------------------------------------------------------ real socket fetch
# A throwaway local HTTP server proves the fetch path end to end: the request
# goes to the *validated* IP with the original Host header, redirects are not
# followed and the body is capped. _is_public is patched only so the test can
# use loopback; the address checks themselves are covered above.


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/")
            self.end_headers()
            return
        body = f"<html><title>Host={self.headers['Host']}</title>{'x' * 50_000}</html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def local_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()


@pytest.fixture
def loopback_settings(settings, local_server, monkeypatch):
    monkeypatch.setattr(ssrf, "_is_public", lambda ip: True)
    return settings.model_copy(
        update={"outbound_allow_http": True, "outbound_allowed_ports": [local_server], "outbound_max_bytes": 2_048}
    )


def test_fetch_uses_pinned_ip_and_original_host(loopback_settings, local_server):
    result = ssrf.fetch_preview(f"http://app.example:{local_server}/", loopback_settings, fake_resolver("127.0.0.1"))
    assert result.status_code == 200
    assert result.title == f"Host=app.example:{local_server}"
    assert result.content_type == "text/html"


def test_fetch_does_not_follow_redirects(loopback_settings, local_server):
    result = ssrf.fetch_preview(
        f"http://app.example:{local_server}/redirect", loopback_settings, fake_resolver("127.0.0.1")
    )
    assert result.status_code == 302
    assert result.redirect_location == "http://169.254.169.254/latest/"


def test_fetch_connection_error_is_blocked_not_raised(loopback_settings):
    closed_port = loopback_settings.outbound_allowed_ports[0]
    settings = loopback_settings.model_copy(update={"outbound_allowed_ports": [closed_port, 1]})
    with pytest.raises(OutboundRequestBlocked) as exc:
        ssrf.fetch_preview("http://app.example:1/", settings, fake_resolver("127.0.0.1"))
    assert exc.value.reason == "upstream_error"
