# SIA-05: Server-side request forgery (SSRF)

| Field | Value |
|---|---|
| OWASP | API7:2023 Server Side Request Forgery; A10:2021 SSRF |
| CWE | CWE-918 Server-Side Request Forgery |
| CVSS 3.1 (if absent) | **7.7 High**: `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` (scope change into the internal network) |
| Affected surface | `POST /integrations/url-preview` |
| Status | Mitigated at the application layer; network layer added in Project 2 |

## Threat
A feature that fetches a user-supplied URL can be aimed at things only the
server can reach: cloud instance metadata (credential theft), `localhost`
admin ports, internal services, the Kubernetes API. String blocklists are
routinely bypassed through alternative IP notations, DNS names that resolve
to private addresses, redirects and DNS rebinding.

## Control
Implemented once, in [app/ssrf.py](../../app/ssrf.py); all outbound HTTP must go
through it.
1. **Scheme allowlist**: `https` only by default. Userinfo in the URL is
   rejected.
2. **Host and port allowlists**: an optional exact-host allowlist
   (`APP_OUTBOUND_ALLOWED_HOSTS`); port 443 only by default.
3. **Resolve, then validate every address**: *all* A/AAAA records must be
   globally routable (`ipaddress.is_global`). That excludes loopback,
   RFC 1918, link-local (including the metadata range), CGNAT, multicast and
   reserved ranges; IPv4-mapped and 6to4 IPv6 are unwrapped first. Checking
   resolved IPs rather than hostname strings makes alternative notations
   irrelevant.
4. **Connect to the validated IP**, keeping the original hostname for SNI,
   certificate verification and the Host header. There's no second DNS
   lookup, so rebinding can't swap the address.
5. **No redirects followed** (the `Location` is returned as data), a 3-second
   timeout and a 512 KB response cap.
6. **Per-user rate limit**; blocks are counted in
   `outbound_request_blocked_total{reason}` and logged.

## Verification
- `tests/test_ssrf.py`: 12 non-public address classes, mixed public and private
  records, scheme, userinfo, port, host allowlist and DNS failure. A real local
  HTTP server test proves IP pinning with the original Host header and that
  redirects are not followed; the endpoint never echoes resolved IPs.
- Semgrep custom rule `outbound-http-outside-ssrf-guard` fails the build if
  `requests`, `httpx`, `urllib` or `aiohttp` is used outside `app/ssrf.py`.

## Residual risk
- An allowlisted public host could itself be compromised. Set the host
  allowlist in production.
- Defence in depth: Project 2 adds a Kubernetes egress `NetworkPolicy` that
  blocks pod egress to cluster, node and metadata CIDRs independently of the
  application code.
