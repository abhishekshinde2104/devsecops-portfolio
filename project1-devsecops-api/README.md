# Secure Invoice API: FastAPI + DevSecOps pipeline

[![project1-devsecops](https://github.com/abhishekshinde2104/devsecops-portfolio/actions/workflows/project1-devsecops.yml/badge.svg)](https://github.com/abhishekshinde2104/devsecops-portfolio/actions/workflows/project1-devsecops.yml)

A small multi-tenant invoicing API built to be **secure by design against the
OWASP Top 10 and OWASP API Security Top 10**, plus a GitHub Actions pipeline
that proves it on every commit: SAST, SCA, container and IaC scanning, SBOM
generation, secret scanning and a policy-driven severity gate that fails the
build.

> Project 1 of a DevSecOps portfolio. The same API is deployed and hardened on
> Kubernetes (Project 2), monitored for attacks with Prometheus and Grafana
> (Project 3), threat-modelled with STRIDE and fed into DefectDojo (Project 4),
> and the pipeline is ported to GitLab CI (Project 5).

---

## What's in here

| Area | What it demonstrates | Where |
|---|---|---|
| Secure API | BOLA/IDOR protection, JWT hardening, Argon2id, mass-assignment protection, parameterised queries, SSRF guard with IP pinning, rate limiting, secret handling, security headers | [`app/`](app/) |
| Security regression tests | 115 tests that exercise attack patterns against each control, plus gate and image-policy tests | [`tests/`](tests/) |
| Custom SAST rules | 8 Semgrep rules encoding this codebase's security decisions, unit-tested | [`semgrep-rules/`](semgrep-rules/) |
| CI pipeline | Gitleaks, Semgrep, OWASP Dependency-Check, Trivy (image/config/fs), Syft SBOM, Grype | [`.github/workflows/project1-devsecops.yml`](../.github/workflows/project1-devsecops.yml) |
| Severity gate | Normalises every scanner, blocks on HIGH/CRITICAL, fails closed, time-boxed exceptions | [`scripts/security_gate.py`](scripts/security_gate.py), [`security-gate.toml`](security-gate.toml) |
| Vulnerability reports | One report per weakness class: OWASP, CWE, CVSS, control, verification, residual risk | [`docs/controls/`](docs/controls/) |
| Scan results | Latest local pipeline run | [`docs/scan-results.md`](docs/scan-results.md) |

## Architecture

```mermaid
flowchart LR
    client([API client]) -->|HTTPS + Bearer JWT| mw
    subgraph api[FastAPI app · non-root container]
      mw["middleware<br/>rate limit · security headers · metrics"] --> routers
      routers["routers<br/>auth · users · invoices · admin · integrations"]
      routers --> sec["security.py<br/>Argon2id · JWT verify · RBAC"]
      routers --> orm[("SQLAlchemy ORM<br/>SQLite / Postgres")]
      routers --> ssrf["ssrf.py<br/>validate → resolve → pin IP"]
    end
    ssrf -->|public IPs only, no redirects| internet([Internet])
    prom([Prometheus]) -->|/metrics| mw
```

### Endpoints

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/auth/register` | none | rate-limited; role is always `user` |
| POST | `/auth/login` | none | rate-limited per IP+account and per account; 15-min JWT |
| GET/PATCH | `/users/me` | user | PATCH accepts `full_name` only |
| GET/POST | `/invoices` | user | owner-scoped, paginated (≤100) |
| GET | `/invoices/search?q=` | user | owner-scoped, parameterised, wildcards escaped |
| GET/PATCH/DELETE | `/invoices/{id}` | owner | foreign IDs → 404 |
| GET | `/admin/users` | admin | router-level role check |
| PATCH | `/admin/users/{id}/role` | admin | audit-logged |
| POST | `/integrations/url-preview` | user | SSRF-guarded outbound fetch |
| GET | `/healthz`, `/metrics` | none | metrics restricted by NetworkPolicy in K8s |

## Security controls

| ID | Weakness designed against | OWASP | CWE | Report |
|---|---|---|---|---|
| SIA-01 | BOLA / IDOR | API1:2023 | CWE-639 | [report](docs/controls/API1-bola.md) |
| SIA-02 | Broken authentication (weak JWT) | API2:2023 · A07 | CWE-347 | [report](docs/controls/API2-broken-authentication.md) |
| SIA-03 | SQL injection | A03 | CWE-89 | [report](docs/controls/A03-sql-injection.md) |
| SIA-04 | Mass assignment | API3:2023 | CWE-915 | [report](docs/controls/API3-mass-assignment.md) |
| SIA-05 | SSRF | API7:2023 · A10 | CWE-918 | [report](docs/controls/A10-ssrf.md) |
| SIA-06 | Missing rate limiting | API4:2023 | CWE-307, CWE-770 | [report](docs/controls/API4-rate-limiting.md) |
| SIA-07 | Hard-coded secrets | A07 · A02 | CWE-798 | [report](docs/controls/A07-hardcoded-secrets.md) |
| SIA-08 | Broken function-level authorization | API5:2023 | CWE-285 | [report](docs/controls/API5-function-level-authz.md) |
| SIA-09 | Security misconfiguration | API8:2023 · A05 | CWE-16, CWE-209, CWE-250 | [report](docs/controls/A05-misconfiguration.md) |

Each control is verified twice: by regression tests on every commit, and by a
scanner or custom Semgrep rule that catches reintroduction of the pattern. See
the [coverage matrix](docs/controls/README.md#where-each-class-is-caught).

## Pipeline

```mermaid
flowchart LR
    push([push / PR / weekly]) --> t[test] & s[Gitleaks] & sa[Semgrep] & dc[Dependency-Check] & i[build → Trivy · Syft → Grype]
    t & s & sa & dc & i --> g{{security gate}}
    g --> ok([✅ merge]) & no([❌ blocked])
```

Full write-up (design decisions, supply-chain hardening, branch protection):
**[docs/pipeline.md](docs/pipeline.md)**.

---

## Quick start

### Run the API (Docker)

```bash
cp .env.example .env
python -c "import secrets; print('APP_SECRET_KEY=' + secrets.token_urlsafe(48))" >> .env
docker compose up --build
# http://127.0.0.1:8000/docs  (APP_DOCS_ENABLED=true in .env.example)
```

Create an admin (out-of-band only; there's no API path to become admin):

```bash
docker compose exec -e APP_ADMIN_PASSWORD='<12+ chars>' api python -m app.cli create-admin --email admin@example.com
```

### Try it

```bash
curl -s -X POST localhost:8000/auth/register -H 'content-type: application/json' \
  -d '{"email":"alice@example.com","full_name":"Alice","password":"a-long-passphrase-1"}'
TOKEN=$(curl -s -X POST localhost:8000/auth/login -H 'content-type: application/json' \
  -d '{"email":"alice@example.com","password":"a-long-passphrase-1"}' | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -s -X POST localhost:8000/invoices -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"customer_name":"ACME GmbH","amount_cents":125000}'
```

### Tests

```bash
docker build --target test -t secure-invoice-api:test . && docker run --rm secure-invoice-api:test pytest --cov
```

Or natively (Python 3.12+):

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install --require-hashes -r requirements.txt -r requirements-dev.txt
pytest --cov && ruff check . && ruff format --check .
```

### Run the whole security pipeline locally

Only Docker is needed. The script uses the same pinned scanner images as CI:

```bash
bash scripts/scan-local.sh                  # all scanners except Dependency-Check
NVD_API_KEY=... bash scripts/scan-local.sh --with-depcheck
```

Reports land in `reports/`, and the gate's verdict is printed at the end.

### Windows (PowerShell)

```powershell
# One-time: store the NVD key for your user (input is hidden), then open a NEW terminal
$s = Read-Host "NVD API key" -AsSecureString
[Environment]::SetEnvironmentVariable("NVD_API_KEY", [System.Net.NetworkCredential]::new("", $s).Password, "User")

# Run the API
cd project1-devsecops-api
Copy-Item .env.example .env
$key = python -c "import secrets; print(secrets.token_urlsafe(48))"
(Get-Content .env) -replace '^APP_SECRET_KEY=$', "APP_SECRET_KEY=$key" | Set-Content .env -Encoding ascii
docker compose up --build            # http://127.0.0.1:8000/docs

# Run the security pipeline (use Git Bash's bash, not WSL's)
& "C:\Program Files\Git\bin\bash.exe" scripts/scan-local.sh --with-depcheck
```

### Enable it on GitHub

1. Push to a new GitHub repository.
2. **Settings → Secrets → Actions**: add `NVD_API_KEY` (free,
   [request here](https://nvd.nist.gov/developers/request-an-api-key)).
3. Protect `main` and require the **P1 / Security gate** and
   **P1 / Lint + security regression tests** checks (settings in
   [docs/pipeline.md](docs/pipeline.md#governance-making-the-gate-binding)).
4. Set your GitHub handle in the root `.github/CODEOWNERS`.
5. Optional: public repos get SARIF results in **Security → Code scanning**
   for free.

## Demonstrating red → green

The branch `demo/red-pipeline` holds two commits.

**Commit 1 (red)** is the kind of change that gets merged on a busy day: pin
PyJWT to 2.3.0 "to match the billing service", and drop the non-root `USER` "to
debug volume permissions". All 115 tests still pass. The gate blocks it:

| Finding | Found by | Why it blocks |
|---|---|---|
| CVE-2022-29217, CVE-2026-32597, CVE-2026-48526 in `pyjwt@2.3.0` | Trivy image, Trivy fs, Grype and Dependency-Check (12 raw findings, deduplicated to 3) | HIGH, fix available |
| `IMG-001`: image runs as root | image policy check | HIGH. Trivy DS002 and Semgrep `missing-user` both **miss** it because an earlier Dockerfile stage has a `USER` line |

**Commit 2 (green)** upgrades PyJWT and restores `USER 10001:10001`; the gate
passes. Both runs are visible on [PR #1](https://github.com/abhishekshinde2104/devsecops-portfolio/pull/1).

Talking points:
- **Reachability vs policy.** This code pins `algorithms=["HS256"]`, so
  CVE-2022-29217 (algorithm confusion) isn't reachable here. The gate still
  blocks, because a fixed version exists and reachability arguments belong in
  a reviewed, time-boxed exception, not a silent pass.
- **Tests don't catch this.** Functional and security tests stay green; only
  supply-chain and configuration scanning notices.

Full run history and numbers: [docs/scan-results.md](docs/scan-results.md).

## Repository layout

```
app/                 FastAPI application (factory: app.main:create_app)
  routers/           auth, users, invoices, admin, integrations
  security.py        Argon2id, JWT issue/verify, auth dependencies
  ssrf.py            outbound HTTP guard
  ratelimit.py       sliding-window limiter
  metrics.py         Prometheus metrics (security signals for Project 3)
tests/               security regression tests + gate tests + fixtures
semgrep-rules/       custom rules + their unit tests
scripts/
  security_gate.py   severity gate (stdlib only)
  scan-local.sh      run the pipeline locally with Docker
docs/
  controls/          per-weakness security reports
  pipeline.md        pipeline design
  scan-results.md    latest scan results
(repo root) .github/  workflow, Dependabot, CODEOWNERS, PR template
security-gate.toml   gate policy
```

## Interview talking points

- **Why a separate gate?** Scanners disagree on severity names and exit codes.
  Normalising first and deciding once gives one auditable policy, complete
  results and fail-closed behaviour when a scanner crashes.
- **Why not block unfixed CVEs?** Developers can't act on them. Blocking
  teaches people to bypass the gate. They're tracked with SLAs in
  vulnerability management (Project 4), and the weekly scheduled scan catches
  the day a fix ships.
- **Why three SCA tools?** They use different data sources (NVD CPE matching
  vs GHSA/OSV package matching) and disagree in practice. Dedup in the gate
  keeps the noise down.
- **SSRF:** validating the URL string is not enough. The guard validates the
  *resolved* IPs and then connects to the validated IP, which also closes DNS
  rebinding.
- **BOLA:** the owner filter lives in the SQL `WHERE` clause, not in an `if`
  after the fetch, and foreign IDs return 404, not 403.

## License

MIT
