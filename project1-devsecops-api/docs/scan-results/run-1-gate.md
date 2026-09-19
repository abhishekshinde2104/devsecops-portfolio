## Security gate: FAILED
Policy: block on **CRITICAL, HIGH** (fixable only for dependency/image CVEs); missing reports block.
| Scanner | CRITICAL | HIGH | MEDIUM | LOW | INFO |
|---|---|---|---|---|---|
| grype | 0 | 48 | 52 | 51 | 0 |
| semgrep | 0 | 2 | 3 | 0 | 0 |
| trivy | 0 | 44 | 49 | 57 | 0 |
### Blocking findings (2)
| Severity | Scanner | ID | Location | Fix |
|---|---|---|---|---|
| HIGH | semgrep | `dockerfile.security.missing-user.missing-user` | `Dockerfile:27` | - |
| HIGH | semgrep | `python.lang.security.audit.network.http-not-https-connection.http-not-https-connection` | `app/ssrf.py:141` | - |

