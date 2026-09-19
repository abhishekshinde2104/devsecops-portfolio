# Kubernetes hardening lab

[![project2-k8s-hardening](https://github.com/abhishekshinde2104/devsecops-portfolio/actions/workflows/project2-k8s-hardening.yml/badge.svg)](https://github.com/abhishekshinde2104/devsecops-portfolio/actions/workflows/project2-k8s-hardening.yml)

The Project 1 API deployed to Kubernetes twice. First the **wrong way**: a
privileged root container in `default`, with a plaintext secret in an env
var, `cluster-admin` on the default ServiceAccount, no limits and no network
policy, on a default cluster. Then **hardened**, at both the workload and
control-plane layers. Both states are measured with the same tools.

| | Before | After |
|---|---|---|
| Runtime security checks (proved on the live cluster) | 1/17 | **17/17** |
| CIS Kubernetes Benchmark v1.12 failures (kube-bench) | 12 | **1** (accepted) |
| Kubescape failed controls caused by app resources | 46 | **3** (triaged) |
| Kubescape NSA/CISA guidance | 50% | **100%** |
| Polaris score | 37 | **90** |
| Trivy HIGH/CRITICAL misconfigurations | 3 | **0** |

**Full write-up:** [docs/hardening-report.md](docs/hardening-report.md): what
changed, the CIS mapping, deviations and residual risks, and the problems
found along the way. Generated numbers are in
[docs/results/comparison.md](docs/results/comparison.md).

## What's hardened

**Workload** ([manifests/hardened](manifests/hardened))
- Namespace enforcing Pod Security Standard **restricted**
- Non-root UID 10001, read-only root filesystem, no privilege escalation, all capabilities dropped, seccomp `RuntimeDefault`
- Own ServiceAccount with no RBAC and no mounted token; the namespace's `default` SA is neutered too
- Secret created at deploy time from a random value and **mounted as a file**, never in env or git
- NetworkPolicies: default-deny both ways; ingress only from labelled client namespaces and `monitoring`; egress only DNS and 443 to public IPs (the network half of Project 1's SSRF defence)
- Requests and limits, `ResourceQuota` (no NodePorts/LoadBalancers), `LimitRange`, probes
- A separate least-privilege deployer identity for CD

**Control plane** ([cluster/kind-hardened.yaml.tmpl](cluster/kind-hardened.yaml.tmpl))
- Audit logging with a [policy](cluster/hardening/audit-policy.yaml) that never logs Secret contents
- Secrets encrypted at rest in etcd (per-cluster key, never committed)
- Cluster-wide Pod Security defaults and `EventRateLimit` via an [AdmissionConfiguration](cluster/hardening/admission-config.yaml)
- Profiling off, strong TLS ciphers, kubelet serving certs verified against the cluster CA, token-expiry and GC settings, node file permissions

## How it's verified

[`scripts/verify.sh`](scripts/verify.sh) doesn't read YAML; it tests the running cluster:

| Check | How |
|---|---|
| Non-root, read-only rootfs, no capabilities, no token, secret not in env | `kubectl exec` into the pod: UID, write attempt, `CapEff` from `/proc/self/status`, token path, `os.environ` |
| RBAC | `kubectl auth can-i list secrets -A --as=system:serviceaccount:…` |
| Admission control | server-side dry run of a privileged pod, which must be rejected |
| Network policy | curl from an allowed and a denied namespace; connect from the pod to the API server and the node's kubelet |
| Encryption at rest | create a canary Secret, read the raw value from etcd with `etcdctl` |
| Audit logging | audit log present and growing on the control-plane node |

Scanners: **kube-bench** (CIS v1.12, as an in-cluster Job), **Kubescape**
(NSA, MITRE, CIS v1.12, both live and on the manifests), **Trivy** and
**Polaris** (manifests).

## Run it

Needs Docker, [kind](https://kind.sigs.k8s.io/), kubectl and Python 3, plus
about 2 GB of free memory for Docker. Run the scripts from Git Bash on
Windows, or any shell on Linux/macOS.

```bash
cd project2-k8s-hardening

# "Before": kind defaults + insecure manifests
scripts/cluster-up.sh baseline && scripts/deploy.sh insecure
scripts/verify.sh baseline && scripts/scan.sh baseline
kind delete cluster --name p2-baseline

# "After": CIS-hardened control plane + hardened manifests
scripts/cluster-up.sh hardened && scripts/deploy.sh hardened
scripts/verify.sh hardened && scripts/scan.sh hardened

# Compare and gate
python scripts/report.py compare reports/baseline reports/hardened --markdown docs/results/comparison.md
python scripts/policy_gate.py reports/hardened/summary.json
```

Try the API through the hardened stack:

```bash
kubectl -n invoice-api port-forward svc/invoice-api 8080:80
curl -s localhost:8080/healthz
```

## CI

[`.github/workflows/project2-k8s-hardening.yml`](../.github/workflows/project2-k8s-hardening.yml):
kubeconform schema validation, shellcheck and unit tests; then a real kind
cluster on the runner with the full hardened deploy, runtime checks and
scanners; then **`P2 / Policy gate`** enforces
[`hardening-policy.toml`](hardening-policy.toml). A regression in any control,
score or threshold fails the build, and `main` requires the gate.

## Layout

```
cluster/          kind configs (baseline, hardened template) + audit/admission policy
manifests/
  insecure/       the "before" deployment (deliberately misconfigured)
  hardened/       the "after" deployment
  tools/          kube-bench Job, network-policy probes, admission test pod
  .trivyignore.yaml  triaged scanner findings, each with a reason
scripts/          cluster-up, deploy, verify, scan, report, policy_gate
hardening-policy.toml  thresholds enforced in CI
docs/             hardening report + generated before/after results
tests/            unit tests for report and gate
```
