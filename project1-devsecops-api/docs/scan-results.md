# Scan results and triage log

Results from running the pipeline locally
([`scripts/scan-local.sh`](../scripts/scan-local.sh), same pinned scanner
images as CI) while building this project. Every run is listed, including the
ones that exposed problems in the pipeline itself. Raw gate outputs are in
[`scan-results/`](scan-results/).

## Current state of `main`

**Security gate: PASSED** · [gate output](scan-results/main-green-gate.md)

| Scanner | Target | Result |
|---|---|---|
| Ruff + pytest | source | 111 tests pass, 94.5% coverage, lint clean |
| Gitleaks 8.30.1 | full git history | 0 leaks |
| Semgrep 1.177.0 | app + `.github/` (p/python, p/owasp-top-ten, p/jwt, p/github-actions, 8 custom rules) | 0 findings; custom rule tests 8/8 |
| Trivy config 0.74.0 | Dockerfile, compose | 0 misconfigurations |
| Trivy fs 0.74.0 | `requirements*.txt` | 0 vulnerabilities |
| Image policy | runtime config of the built image | 0 findings (non-root, no baked-in secrets, healthcheck present) |
| Trivy image 0.74.0 | `python:3.14-slim-trixie` + app | 0 critical · 44 high · 49 medium · 57 low; **none has a fix available** |
| Syft 1.52.0 → Grype 0.119.0 | SBOM of the image (CycloneDX + SPDX) | 0 critical · 48 high · 52 medium · 51 low; all high findings are Debian `wont-fix` / `not-fixed` |
| OWASP Dependency-Check 13.0.0 | `requirements*.txt` | Runs in CI with the `NVD_API_KEY` secret; the local run is pending the key |

### Why unfixed OS CVEs don't block

All remaining HIGH findings are in Debian 13 base packages where Debian has
either no fix yet or has marked the issue `<no-dsa>` / `wont-fix` (typically
not exploitable in a container context). Developers can't act on them in
this repository, so blocking on them would only teach people to bypass the
gate. They're reported in every run, re-evaluated by the weekly scheduled
scan, and tracked with SLAs in the vulnerability-management workflow
(Project 4). The moment a fix ships, the finding becomes fixable and the gate
blocks it.

## Run history

### Run 1: first full scan → FAILED (2 blocking)
[gate output](scan-results/run-1-gate.md)

| Finding | Triage | Action |
|---|---|---|
| Semgrep `dockerfile.security.missing-user` at the Dockerfile `test` stage | True positive: the test stage ran as root | Test stage now runs as UID 10002 |
| Semgrep `http-not-https-connection` in `app/ssrf.py` | True positive for the pattern, but plain HTTP is reachable only when an operator sets `APP_OUTBOUND_ALLOW_HTTP=true` (default off), and the target still passes IP validation | Accepted: inline `nosemgrep` with justification |
| Semgrep `dependabot-missing-cooldown` ×3 (medium) | Valid supply-chain hardening | Added a 7-day cooldown so new releases aren't adopted before compromised packages get yanked |
| Semgrep parse errors on 3 workflow lines using `${{ }}` inside `run:` | Also a script-injection anti-pattern | Moved to environment variables |

### Run 2: after triage → PASSED
[gate output](scan-results/run-2-gate.md)

### Demo branch, first attempt: exposed a scanner blind spot
Removing `USER` from the **final** Dockerfile stage was expected to trip Trivy
`DS002` and Semgrep `missing-user`. **Neither fired**: both only check the
last `USER` instruction in the *file*, and the earlier `test` stage has
`USER tester`. A root production image would have shipped green.

**Fix:** [`scripts/image_policy.py`](../scripts/image_policy.py) inspects the
*built image's* config (`User`, secret-like `Env`, `Healthcheck`) and feeds
the gate (`IMG-001…003`).

The same run also showed imprecise deduplication (`PyJWT@2.3.0` vs
`pyjwt@2.3.0`; Grype's GHSA IDs vs Trivy's CVE IDs). The gate now lowercases
package names, normalises Dependency-Check purls and maps GHSA IDs to their
CVE alias, so 9 raw PyJWT findings count as 3.

### Monorepo migration run → FAILED (15 blocking), 3 more pipeline issues
1. **Semgrep scanned its own rule fixtures** (14 findings in
   `semgrep-rules/fastapi-security.py`, which are intentionally bad snippets).
   The root-level `.semgrepignore` isn't applied when explicit scan targets
   are passed. Moved to a project-level `.semgrepignore`, verified with
   `semgrep scan --x-ls` (54 → 39 targets).
2. **Grype: CVE-2026-82049 in CPython 3.13.15**, HIGH (CVSS 4.0 8.4): the
   `tarfile` extraction filters can be bypassed by a hard link to a symlink.
   **Not reachable**, since the app never extracts archives, and the fix is
   only in 3.14. Upgrading the base image to `python:3.14-slim-trixie` was
   cheaper than a documented exception: the lockfile resolves unchanged,
   111/111 tests pass.
3. **Syft exited 0 with an empty SBOM** (it hit ENOMEM reading a 215 MB
   tarball through a Docker Desktop bind mount). Grype then failed on the
   empty file, so the gate would have caught it (fail closed). But an
   empty SBOM must never pass as an artifact: CI and the local script now
   fail the step on an empty SBOM, and locally Syft reads from the Docker
   daemon instead.

### Demo branch `demo/red-pipeline` → FAILED (4 blocking) → PASSED
[red gate output](scan-results/demo-red-gate.md)

| Severity | Finding | Location | Fix |
|---|---|---|---|
| HIGH | CVE-2022-29217 (algorithm confusion) | `pyjwt@2.3.0` | 2.4.0 |
| HIGH | CVE-2026-32597 | `pyjwt@2.3.0` | 2.12.0 |
| HIGH | CVE-2026-48526 | `pyjwt@2.3.0` | 2.13.0 |
| HIGH | IMG-001: image runs as root | image config | restore `USER` |

All 111 tests pass on the red commit. The fix commit restores `main`'s
dependency set and Dockerfile, so its scan result is identical to the
current `main` result above.

## Reproduce

```bash
cd project1-devsecops-api
bash scripts/scan-local.sh                  # all scanners except Dependency-Check
bash scripts/scan-local.sh --with-depcheck  # needs NVD_API_KEY in the environment
```
