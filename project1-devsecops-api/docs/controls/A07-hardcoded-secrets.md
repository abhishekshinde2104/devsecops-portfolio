# SIA-07: Hard-coded secrets

| Field | Value |
|---|---|
| OWASP | A07:2021 Identification and Authentication Failures; A02:2021 Cryptographic Failures |
| CWE | CWE-798 Use of Hard-coded Credentials; CWE-321 Use of Hard-coded Cryptographic Key |
| CVSS 3.1 (if absent) | **9.1 Critical**: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (anyone with repo or image access can mint tokens) |
| Affected surface | JWT signing key, database credentials, any future API keys |
| Status | Mitigated |

## Threat
A key committed to source ends up in every clone, fork, CI log and image
layer, and deleting it later doesn't remove it from git history. With the JWT
key, anyone can mint an admin token without an account.

## Control
- **No defaults**: `APP_SECRET_KEY` is required with no fallback. The app won't
  start if it's missing, shorter than 32 characters or a known placeholder
  ([config.py](../../app/config.py)).
- **`SecretStr`** keeps the value out of `repr()`, logs and tracebacks.
- **Local development** uses a git-ignored `.env`; only an empty
  `.env.example` is committed, and `.dockerignore` keeps `.env` out of the
  build context.
- **Kubernetes** (Project 2) mounts it from a `Secret`.
- **Pipeline prevention layers**:
  - Gitleaks scans the **full git history** (`fetch-depth: 0`), and also runs
    as a pre-commit hook;
  - the Trivy `secret` scanner inspects the built image layers;
  - the Semgrep custom rule `hardcoded-signing-secret` flags literals assigned
    to `*_SECRET_KEY` / `*_SIGNING_KEY` or passed to `jwt.encode`.
- **Any secret finding is CRITICAL in the gate.** Response procedure: rotate
  first, then purge history (rotation is what actually removes the risk).

## Verification
- `tests/test_platform.py`: missing, short and placeholder secrets refused;
  secret absent from `repr(settings)`.
- `tests/test_security_gate.py`: a Gitleaks finding blocks the build.

## Residual risk
Gitleaks allowlists cover exactly two synthetic-fixture paths, each justified
in the repo-root `.gitleaks.toml`.
