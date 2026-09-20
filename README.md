# DevSecOps Portfolio

[![project1-devsecops](https://github.com/abhishekshinde2104/devsecops-portfolio/actions/workflows/project1-devsecops.yml/badge.svg)](https://github.com/abhishekshinde2104/devsecops-portfolio/actions/workflows/project1-devsecops.yml)
[![project2-k8s-hardening](https://github.com/abhishekshinde2104/devsecops-portfolio/actions/workflows/project2-k8s-hardening.yml/badge.svg)](https://github.com/abhishekshinde2104/devsecops-portfolio/actions/workflows/project2-k8s-hardening.yml)

Five connected projects that take one service through the whole security
lifecycle: secure coding and a CI security gate, container and Kubernetes
hardening, attack-focused monitoring, threat modelling with vulnerability
management, and pipeline portability to GitLab.

All five projects use the same application, a small multi-tenant FastAPI
service (the **Secure Invoice API**), so each project builds on the previous
one instead of starting from a toy example.

| # | Project | What it demonstrates | Status |
|---|---------|----------------------|--------|
| 1 | [Secure API + DevSecOps pipeline](project1-devsecops-api/) | OWASP Top 10 / API Top 10 controls with regression tests, SAST (Semgrep + custom rules), SCA (Dependency-Check, Trivy, Grype), SBOM (Syft), secret scanning (Gitleaks), container/IaC scanning, fail-closed severity gate, red → green demo | ✅ ([scan results](project1-devsecops-api/docs/scan-results.md)) |
| 2 | [Kubernetes hardening lab](project2-k8s-hardening/) | Insecure → hardened on kind: Pod Security restricted, NetworkPolicies, least-privilege RBAC, file-mounted Secrets, etcd encryption, audit logging. CIS v1.12 failures **12 → 1**, runtime checks **1/17 → 17/17**, Polaris **37 → 90** | ✅ ([report](project2-k8s-hardening/docs/hardening-report.md)) |
| 3 | [Security monitoring stack](project3-security-monitoring/) | Prometheus + Alertmanager + Grafana via Helm on the hardened cluster, 11 detections mapped to Project 1 controls + ATT&CK (brute force, BOLA probing, SSRF, privilege escalation, recon, restarts), promtool-tested, routed to a webhook sink, optional Falco runtime detection | ✅ ([README](project3-security-monitoring/README.md)) |
| 4 | Threat model + vulnerability management | STRIDE per trust boundary with a data-flow diagram, DefectDojo triage of all scanner output, vulnerability management policy with SLAs | 🚧 |
| 5 | GitLab CI port | The Project 1 pipeline expressed in `.gitlab-ci.yml` with GitLab's security templates and MR widgets | 🚧 |

## Repository layout

```
.github/
  workflows/project1-devsecops.yml   CI for Project 1
  workflows/project2-k8s-hardening.yml  CI for Project 2 (kind cluster e2e)
  branch-protection.json             required checks for main, as code
  dependabot.yml, CODEOWNERS, pull_request_template.md
.gitleaks.toml                       secret-scanning config for the whole repo
.pre-commit-config.yaml              gitleaks + ruff + custom Semgrep rules before commit
project1-devsecops-api/              secure API + DevSecOps pipeline
project2-k8s-hardening/              Kubernetes hardening lab
```

Each workflow starts with a change-detection job, so a change to one project
runs only that project's scanners, while every project's gate still reports. Secret scanning always covers the full history
of the whole repository.

## Getting started

Every project has its own README with a quick start. The common prerequisites
are Docker, plus `kind`, `kubectl` and `helm` for Projects 2 and 3.

```bash
cd project1-devsecops-api
bash scripts/scan-local.sh      # run the complete security pipeline locally
```

## License

MIT
