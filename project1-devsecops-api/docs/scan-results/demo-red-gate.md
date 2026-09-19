## Security gate: FAILED

Policy: block on **CRITICAL, HIGH** (fixable only for dependency/image CVEs); missing reports block.

| Scanner | CRITICAL | HIGH | MEDIUM | LOW | INFO |
|---|---|---|---|---|---|
| grype | 0 | 51 | 53 | 52 | 0 |
| image-policy | 0 | 1 | 0 | 0 | 0 |
| trivy-fs | 0 | 3 | 1 | 1 | 0 |
| trivy-image | 0 | 47 | 50 | 58 | 0 |

### Blocking findings (4)

| Severity | Scanner | ID | Location | Fix |
|---|---|---|---|---|
| HIGH | trivy-image | `CVE-2022-29217` | `pyjwt@2.3.0` | 2.4.0 |
| HIGH | trivy-image | `CVE-2026-32597` | `pyjwt@2.3.0` | 2.12.0 |
| HIGH | trivy-image | `CVE-2026-48526` | `pyjwt@2.3.0` | 2.13.0 |
| HIGH | image-policy | `IMG-001` | `image-config:User` | - |

