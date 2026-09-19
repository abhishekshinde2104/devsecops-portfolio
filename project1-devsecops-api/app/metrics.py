"""Prometheus metrics.

Besides the usual RED metrics, the app exports *security* signals that the
monitoring stack (Project 3) alerts on: login failures (brute force), rejected
tokens, authorization denials (BOLA probing), rate-limit rejections and
blocked outbound requests (SSRF attempts).

Label values are always bounded (route templates, fixed reason strings) so an
attacker cannot blow up metric cardinality.
"""

from __future__ import annotations

from prometheus_client import Counter, Histogram

HTTP_REQUESTS = Counter(
    "http_requests_total",
    "HTTP requests by method, route template and status code",
    ["method", "route", "status"],
)
HTTP_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency by method and route template",
    ["method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)
AUTH_EVENTS = Counter(
    "auth_events_total",
    "Authentication events (login_success, login_failure, token_rejected, registration)",
    ["event", "reason"],
)
AUTHZ_DENIED = Counter(
    "authz_denied_total",
    "Authorization denials; spikes on resource=invoice indicate BOLA/IDOR probing",
    ["resource", "reason"],
)
RATE_LIMITED = Counter(
    "rate_limit_rejections_total",
    "Requests rejected by the rate limiter",
    ["scope"],
)
OUTBOUND_BLOCKED = Counter(
    "outbound_request_blocked_total",
    "Outbound requests blocked by the SSRF guard",
    ["reason"],
)
