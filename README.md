# DevSecOps Portfolio

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
| 2 | Kubernetes hardening lab | kind cluster, insecure → hardened deployment, Pod Security, NetworkPolicies, RBAC, Secrets, kube-bench (CIS) and Kubescape before/after scores | 🚧 |
| 3 | Security monitoring stack | Prometheus + Grafana via Helm, app security metrics, alerts for brute force / BOLA probing / SSRF attempts / restarts, Falco runtime detection | 🚧 |
| 4 | Threat model + vulnerability management | STRIDE per trust boundary with a data-flow diagram, DefectDojo triage of all scanner output, vulnerability management policy with SLAs | 🚧 |
| 5 | GitLab CI port | The Project 1 pipeline expressed in `.gitlab-ci.yml` with GitLab's security templates and MR widgets | 🚧 |

## Repository layout

```
.github/
  workflows/project1-devsecops.yml   CI for Project 1 (runs only when its folder changes)
  dependabot.yml, CODEOWNERS, pull_request_template.md
.gitleaks.toml                       secret-scanning config for the whole repo
.pre-commit-config.yaml              gitleaks + ruff + custom Semgrep rules before commit
project1-devsecops-api/              ...one folder per project
```

Each workflow is scoped with `paths:` filters, so a change to one project runs
only that project's pipeline. Secret scanning always covers the full history
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
