# SIA-09: Security misconfiguration

| Field | Value |
|---|---|
| OWASP | API8:2023 Security Misconfiguration; A05:2021 |
| CWE | CWE-16 Configuration; CWE-209 Information Exposure Through an Error Message; CWE-250 Execution with Unnecessary Privileges |
| CVSS 3.1 (if absent) | **5.3 Medium**: `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| Status | Mitigated |

## Controls

**HTTP layer** ([main.py](../../app/main.py))
- Security headers on every response: `X-Content-Type-Options`,
  `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'`,
  `Referrer-Policy`, `Cache-Control: no-store`, HSTS, CORP,
  `Permissions-Policy`.
- Interactive docs and the OpenAPI schema are **off by default**
  (`APP_DOCS_ENABLED=true` turns them on locally).
- A generic `500` body; stack traces go only to the logs.
- No CORS middleware (same-origin only); the Semgrep rule
  `cors-wildcard-with-credentials` guards future changes.
- `--no-server-header`; `X-Request-ID` is validated before being reflected.

**Container** ([Dockerfile](../../Dockerfile))
- Multi-stage build; the runtime image has no compilers, no pip and no tests.
- Runs as UID 10001 (non-root); application code is root-owned and read-only.
- Hash-verified, binary-only dependency installs (`--require-hashes
  --only-binary=:all:`), which protects against tampered packages and sdist
  build scripts.
- OS packages upgraded at build time; the weekly scheduled pipeline run picks
  up newly published CVEs.
- `docker-compose.yml` adds `read_only`, `cap_drop: ALL`, `no-new-privileges`,
  and pid, memory and CPU limits.

**Logging**
- JSON logs; security events use hashed account identifiers, not e-mail
  addresses (GDPR data minimisation).

## Verification
- `tests/test_platform.py`: headers, request-ID sanitising, docs disabled, no
  error-detail leakage, bounded metric labels.
- Trivy `config` scans the Dockerfile (and the Kubernetes manifests in
  Project 2) on every pipeline run.
