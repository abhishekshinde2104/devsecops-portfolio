"""Outbound HTTP with SSRF protection (OWASP A10:2021, API7:2023, CWE-918).

Defence layers, in order:
1. Scheme allowlist (https only by default) and no embedded credentials.
2. Optional hostname allowlist; port allowlist.
3. DNS resolution *before* connecting; every resolved address must be
   globally routable (blocks loopback, RFC1918, link-local incl. the
   169.254.169.254 cloud metadata endpoint, CGNAT, multicast, reserved,
   IPv4-mapped IPv6 variants of the same).
4. The connection is made to the *validated IP* (with SNI/Host set to the
   original hostname), so a second DNS lookup cannot return a different,
   internal address (DNS rebinding / TOCTOU).
5. Redirects are not followed; timeouts and a response size cap are enforced.

At the network layer, Project 2 adds a Kubernetes egress NetworkPolicy as a
second, independent control.
"""

from __future__ import annotations

import html
import ipaddress
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

import urllib3

from app.config import Settings
from app.metrics import OUTBOUND_BLOCKED

Resolver = Callable[..., list[tuple]]
_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_DEFAULT_PORTS = {"http": 80, "https": 443}


class OutboundRequestBlocked(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    path: str
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True)
class FetchResult:
    status_code: int
    content_type: str | None
    title: str | None
    redirect_location: str | None


def _block(reason: str) -> OutboundRequestBlocked:
    OUTBOUND_BLOCKED.labels(reason=reason).inc()
    return OutboundRequestBlocked(reason)


def _is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped or ip.sixtofour
        if mapped is not None:
            ip = mapped
    return ip.is_global and not ip.is_multicast


def validate_url(url: str, settings: Settings, resolver: Resolver | None = None) -> Target:
    resolver = resolver or socket.getaddrinfo
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        raise _block("malformed_url") from None

    scheme = parts.scheme.lower()
    allowed_schemes = {"https", "http"} if settings.outbound_allow_http else {"https"}
    if scheme not in allowed_schemes:
        raise _block("scheme_not_allowed")
    if parts.username is not None or parts.password is not None:
        raise _block("credentials_in_url")

    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise _block("missing_host")
    try:
        host.encode("idna")
    except UnicodeError:
        raise _block("malformed_host") from None
    if settings.outbound_allowed_hosts and host not in settings.outbound_allowed_hosts:
        raise _block("host_not_allowlisted")

    port = port or _DEFAULT_PORTS[scheme]
    if port not in settings.outbound_allowed_ports:
        raise _block("port_not_allowed")

    try:
        infos = resolver(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        raise _block("dns_resolution_failed") from None

    addresses = []
    for info in infos:
        raw = str(info[4][0]).split("%", 1)[0]  # drop IPv6 zone index
        try:
            addresses.append(ipaddress.ip_address(raw))
        except ValueError:
            raise _block("unparseable_address") from None
    if not addresses:
        raise _block("dns_resolution_failed")
    # Every address must be public; otherwise an attacker could publish one
    # public and one internal A record and win the race.
    if not all(_is_public(ip) for ip in addresses):
        raise _block("non_public_address")

    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return Target(scheme=scheme, host=host, port=port, path=path, ip=addresses[0])


def fetch_preview(url: str, settings: Settings, resolver: Resolver | None = None) -> FetchResult:
    target = validate_url(url, settings, resolver)
    timeout = urllib3.Timeout(connect=settings.outbound_timeout_seconds, read=settings.outbound_timeout_seconds)
    pool_kwargs = {"host": str(target.ip), "port": target.port, "timeout": timeout, "retries": False, "maxsize": 1}
    if target.scheme == "https":
        pool: urllib3.HTTPConnectionPool = urllib3.HTTPSConnectionPool(
            **pool_kwargs,
            server_hostname=target.host,
            assert_hostname=target.host,
            cert_reqs="CERT_REQUIRED",
        )
    else:
        # Plain HTTP is only reachable when an operator sets
        # APP_OUTBOUND_ALLOW_HTTP=true (default: false), and the target has
        # already passed the same IP validation. Triaged in docs/scan-results.md.
        # nosemgrep: python.lang.security.audit.network.http-not-https-connection.http-not-https-connection
        pool = urllib3.HTTPConnectionPool(**pool_kwargs)

    default_port = _DEFAULT_PORTS[target.scheme]
    host_header = target.host if target.port == default_port else f"{target.host}:{target.port}"
    try:
        response = pool.urlopen(
            "GET",
            target.path,
            headers={"Host": host_header, "User-Agent": "secure-invoice-api/1.0", "Accept": "text/html"},
            redirect=False,
            preload_content=False,
        )
        try:
            body = response.read(settings.outbound_max_bytes, decode_content=True) or b""
        finally:
            response.release_conn()
            response.close()
    except urllib3.exceptions.HTTPError:
        raise _block("upstream_error") from None
    finally:
        pool.close()

    title = None
    match = _TITLE_RE.search(body)
    if match:
        title = html.unescape(match.group(1).decode("utf-8", "replace")).strip()[:200] or None
    location = response.headers.get("Location") if 300 <= response.status < 400 else None
    return FetchResult(
        status_code=response.status,
        content_type=response.headers.get("Content-Type"),
        title=title,
        redirect_location=location,
    )
