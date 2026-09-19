# Security control reports

One short report per weakness class the API is designed against. Each one
follows the same structure as a vulnerability report: classification (OWASP,
CWE, CVSS for the weakness *if it were present*), the threat, the control
implemented, how it is verified, and the residual risk.

| ID | Weakness | OWASP | CWE | CVSS 3.1 (if absent) | Report |
|----|----------|-------|-----|----------------------|--------|
| SIA-01 | Broken object-level authorization (BOLA/IDOR) | API1:2023, A01:2021 | CWE-639 | 8.1 High | [API1-bola.md](API1-bola.md) |
| SIA-02 | Broken authentication / weak JWT handling | API2:2023, A07:2021 | CWE-347, CWE-287 | 9.1 Critical | [API2-broken-authentication.md](API2-broken-authentication.md) |
| SIA-03 | SQL injection | A03:2021 | CWE-89 | 8.8 High | [A03-sql-injection.md](A03-sql-injection.md) |
| SIA-04 | Mass assignment | API3:2023 | CWE-915 | 8.1 High | [API3-mass-assignment.md](API3-mass-assignment.md) |
| SIA-05 | Server-side request forgery | API7:2023, A10:2021 | CWE-918 | 7.7 High | [A10-ssrf.md](A10-ssrf.md) |
| SIA-06 | Missing rate limiting / brute force | API4:2023, A07:2021 | CWE-307, CWE-770 | 6.5 Medium | [API4-rate-limiting.md](API4-rate-limiting.md) |
| SIA-07 | Hard-coded secrets | A07:2021, A02:2021 | CWE-798 | 9.1 Critical | [A07-hardcoded-secrets.md](A07-hardcoded-secrets.md) |
| SIA-08 | Broken function-level authorization | API5:2023, A01:2021 | CWE-285 | 8.1 High | [API5-function-level-authz.md](API5-function-level-authz.md) |
| SIA-09 | Security misconfiguration (headers, errors, container) | API8:2023, A05:2021 | CWE-16, CWE-209, CWE-250 | 5.3 Medium | [A05-misconfiguration.md](A05-misconfiguration.md) |

## Where each class is caught

Every control has at least two independent checks: a regression test that
runs on every commit, and a scanner or custom Semgrep rule that fires if
someone reintroduces the pattern.

| ID | Regression tests | Pipeline / runtime detection |
|----|------------------|------------------------------|
| SIA-01 | `tests/test_authorization.py` | PR checklist; `authz_denied_total` metric alerting at runtime (Project 3) |
| SIA-02 | `tests/test_auth.py` | Semgrep `jwt-decode-without-algorithms`, `jwt-signature-verification-disabled`, `p/jwt` |
| SIA-03 | `tests/test_input_handling.py` | Semgrep `raw-sql-string-building`, `p/python`, ruff `S608` |
| SIA-04 | `tests/test_input_handling.py` | Semgrep `pydantic-model-allows-extra-fields`, `orm-object-from-raw-request-body` |
| SIA-05 | `tests/test_ssrf.py` | Semgrep `outbound-http-outside-ssrf-guard`; `outbound_request_blocked_total` metric |
| SIA-06 | `tests/test_platform.py` | `rate_limit_rejections_total` and login-failure alerts (Project 3) |
| SIA-07 | `tests/test_platform.py` (fail-fast config) | Gitleaks (full history), Trivy image secret scan, Semgrep `hardcoded-signing-secret` |
| SIA-08 | `tests/test_authorization.py`, `tests/test_cli.py` | Router-level dependency; PR checklist |
| SIA-09 | `tests/test_platform.py` | Trivy config (Dockerfile, later K8s), Semgrep `cors-wildcard-with-credentials` |
