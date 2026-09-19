# DevSecOps pipeline

Workflow: [`.github/workflows/devsecops.yml`](../.github/workflows/devsecops.yml)
· Gate policy: [`security-gate.toml`](../security-gate.toml)
· Gate engine: [`scripts/security_gate.py`](../scripts/security_gate.py)
· Local equivalent: [`scripts/scan-local.sh`](../scripts/scan-local.sh)

```mermaid
flowchart LR
    push([push / PR / weekly cron]) --> test & secrets & sast & sca & image
    test["test<br/>ruff (incl. bandit rules)<br/>pytest + 85% coverage"]
    secrets["secrets<br/>Gitleaks<br/>full git history"]
    sast["SAST<br/>Semgrep: p/python, p/owasp-top-ten,<br/>p/jwt + 8 custom rules"]
    sca["SCA<br/>OWASP Dependency-Check"]
    image["image<br/>build → Trivy image/config/fs<br/>Syft SBOM → Grype"]
    test & secrets & sast & sca & image --> gate{{"security gate<br/>security-gate.toml"}}
    gate -->|no blocking findings| green([✅ mergeable])
    gate -->|blocking finding or missing report| red([❌ blocked])
```

## Stages

| Job | Tool (pinned) | Scans | Report(s) | Why this tool |
|---|---|---|---|---|
| `test` | ruff 0.16, pytest 9 | lint incl. flake8-bandit `S` rules; 100+ security regression tests; coverage ≥85% | JUnit, coverage XML | Fastest feedback; regression tests prove the controls, scanners only find patterns |
| `secrets` | Gitleaks 8.30.1 (binary, SHA-256 verified) | every commit in history | `gitleaks.json` | A secret deleted in a later commit is still leaked; only history scans find it |
| `sast` | Semgrep 1.177.0 | Python source | `semgrep.json`, SARIF → Code Scanning | Community rules + project rules that encode *this* codebase's decisions ([semgrep-rules/](../semgrep-rules/)); rules are unit-tested (`semgrep --test`) |
| `dependency-check` | OWASP Dependency-Check 13.0.0 | `requirements*.txt` (NVD CPE matching) | JSON, SARIF, HTML | The SCA tool most job descriptions name; NVD-based, so it complements GHSA/OSV-based Trivy and Grype |
| `image` | Trivy 0.74.0 | built image (OS + Python packages + secrets in layers); Dockerfile and compose misconfiguration; lockfile | `trivy-image.json`, `trivy-config.json`, `trivy-fs.json`, SARIF | One tool for container CVEs and IaC misconfiguration; reused for K8s manifests in Project 2 |
| `image` | Syft 1.52.0 + Grype 0.119.0 | SBOM of the exact image that would ship | `sbom.cdx.json` (CycloneDX), `sbom.spdx.json` (SPDX), `grype.json` | SBOMs are a supply-chain deliverable in their own right (EU CRA, US EO 14028); Grype re-scans the SBOM, so a stored SBOM can be re-checked later without rebuilding |
| `security-gate` | `security_gate.py` (stdlib only) | all of the above | step summary, `gate-result.json` | See below |

## Why a separate gate job

Each scanner has its own exit-code semantics and severity vocabulary (Semgrep
`ERROR`, Grype `Negligible`, Dependency-Check CVSS scores). Letting each job
fail itself gives inconsistent thresholds, and the first failure hides the
others. Instead:

1. **Scanners always exit 0 and produce reports.** Every run shows the
   complete picture.
2. **The gate normalises everything** into one finding model and one severity
   scale (`CRITICAL…INFO`).
3. **One policy file** ([security-gate.toml](../security-gate.toml)) decides:
   - block on `CRITICAL` and `HIGH`;
   - dependency and image CVEs **without an available fix** are reported but
     don't block (developers can't act on them; they go to vulnerability
     management, Project 4). SAST, secret and misconfiguration findings always
     block;
   - **any secret is CRITICAL** regardless of rule;
   - the same CVE on the same package reported by several scanners blocks
     once (deduplication);
   - **time-boxed exceptions** need an approver and an expiry date. Expired
     exceptions stop applying automatically and are listed in the summary.
4. **Fail closed**: a required report that is missing or unparsable blocks the
   build. A crashed or skipped scanner can't produce a false green.
5. The gate is itself tested (`tests/test_security_gate.py`): clean vs dirty
   fixtures, deduplication, fail-closed behaviour, exception expiry.

## Supply-chain hardening of the pipeline itself

- All third-party actions are **pinned to full commit SHAs** (tag in a
  comment); Dependabot bumps them.
- Scanner container images are pinned to exact versions; the Gitleaks binary is
  checksum-verified.
- `permissions: contents: read` at workflow level; only the SARIF-uploading
  jobs get `security-events: write`. `persist-credentials: false` on every
  checkout.
- Python dependencies are installed with `--require-hashes` everywhere (CI,
  Docker).
- `CODEOWNERS` makes the workflow, gate policy and scanner configs
  security-reviewed paths.

## Governance: making the gate binding

In the GitHub repository settings, under **Branches → Branch protection
rule for `main`**:
- Require a pull request before merging, with 1 approval and CODEOWNERS review.
- Require status checks: **`Security gate`** and **`Lint + security regression
  tests`**.
- Do not allow bypassing the above settings.

Without branch protection the gate only advises; with it, a red gate blocks
the merge.

## Secrets used by the workflow

| Secret | Required | Purpose |
|---|---|---|
| `NVD_API_KEY` | Strongly recommended | Dependency-Check NVD download. Without it the first run is heavily rate-limited (can take >1h). Free: <https://nvd.nist.gov/developers/request-an-api-key> |

## Extending the pipeline (next steps)

- Sign the image and attach the SBOM as an attestation (cosign /
  `actions/attest-sbom`) once it's pushed to a registry.
- DAST: an OWASP ZAP API scan against the compose stack using the OpenAPI
  spec.
- Upload all reports to DefectDojo for triage and SLA tracking (Project 4).
