# SIA-06: Missing rate limiting / brute force

| Field | Value |
|---|---|
| OWASP | API4:2023 Unrestricted Resource Consumption; A07:2021 |
| CWE | CWE-307 Improper Restriction of Excessive Authentication Attempts; CWE-770 Allocation of Resources Without Limits |
| CVSS 3.1 (if absent) | **6.5 Medium**: `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L` |
| Affected surface | `/auth/login`, `/auth/register`, `/integrations/url-preview`, all endpoints |
| Status | Mitigated for a single replica (see residual risk) |

## Threat
Without limits an attacker can run online password guessing or credential
stuffing, abuse expensive endpoints (Argon2 is deliberately slow; outbound
fetches hold workers) and exhaust capacity.

## Control
- **Sliding-window limiter** ([ratelimit.py](../../app/ratelimit.py)) returning
  `429` with `Retry-After`:
  - login: 5/min per (IP, account) **and** 20/min per account across all IPs,
    which covers both single-source and distributed guessing;
  - registration: 5/min per IP;
  - URL preview: 10/min per user;
  - global: 120/min per client IP (health and metrics excluded).
- **Bounded memory**: idle keys are evicted and the table is capped, so floods
  of unique keys can't exhaust memory.
- **Spoof-resistant client IP**: `X-Forwarded-For` is not trusted by default;
  trusted proxies are configured at the uvicorn layer.
- **Bounded work per request**: page size ≤100, search ≤100 characters,
  outbound timeouts and size caps, and length limits on every input field.
- **Detection**: `rate_limit_rejections_total{scope}` and
  `auth_events_total{event="login_failure"}` drive the brute-force alerts in
  Project 3.

## Verification
`tests/test_platform.py`: the sixth login attempt in a window returns `429` with
`Retry-After`; global limit; window recovery; memory bound.

## Residual risk
- Counters are per process: with N replicas the effective limit is N×. The
  production fix is a shared store (Redis) or limits at the ingress or gateway.
- Per-account limits let someone temporarily block a victim's logins (a soft
  lockout). Accepted in preference to hard lockout.
