# Kubernetes hardening report: Secure Invoice API

**Scope:** the Project 1 API (`secure-invoice-api:1.0.0`, the same image in
both runs) deployed to a local single-node kind cluster, Kubernetes 1.34.11.
**Method:** deploy it the "wrong way" on a default cluster, harden both the
workload and the control plane, and measure both states with the same
tooling: 17 runtime checks, kube-bench (CIS Kubernetes Benchmark v1.12),
Kubescape (NSA, MITRE, CIS v1.12), Trivy and Polaris.
**Date:** 2026-09-19.

## Results

| Measure | Before | After |
|---|---|---|
| Runtime security checks passing ([`verify.sh`](../scripts/verify.sh)) | 1/17 | **17/17** |
| CIS Kubernetes Benchmark v1.12, automated checks failing (kube-bench) | 12 | **1** (accepted, see D1) |
| CIS Kubernetes Benchmark v1.12, checks passing | 63 | **81** |
| Kubescape live scan: failed controls caused by app resources | 46 | **3** (all triaged, see D6–D8) |
| Kubescape manifests: NSA/CISA hardening guidance | 50% | **100%** |
| Kubescape manifests: overall compliance | 67.2% | **88.5%** |
| Polaris score | 37 | **90** |
| Polaris danger-level findings | 6 | **0** |
| Trivy HIGH/CRITICAL misconfigurations | 3 | **0** |

Full generated table, including every runtime check with its evidence:
[results/comparison.md](results/comparison.md).

**On the live Kubescape percentage (47 → 63%).** A live scan also grades
kubeadm's own ClusterRoleBindings (`cluster-admin` → `system:masters`,
`kubeadm:cluster-admins`, `system:kube-controller-manager`, …), which exist
in every kubeadm cluster and which the control plane needs. 16 of the 19
controls still failing after hardening are only those built-ins, so the
report attributes each failure to its resource and tracks the ones caused by
the application (46 → 3).

## What changed

### Workload (manifests/insecure → manifests/hardened)

| Insecure baseline | Hardened | Verified by | Maps to |
|---|---|---|---|
| `privileged: true` | `privileged: false`, `allowPrivilegeEscalation: false`, all capabilities dropped | V03, V04 | CIS 5.2.2, 5.2.6, 5.2.9 · NSA |
| `runAsUser: 0` overrides the image's non-root user | `runAsNonRoot`, UID/GID 10001, `fsGroup` | V01 | CIS 5.2.7 |
| Writable root filesystem | `readOnlyRootFilesystem: true`; `emptyDir` only for `/data` and `/tmp` (size-capped) | V02 | NSA |
| No seccomp profile | `seccompProfile: RuntimeDefault` | admission (V11) | CIS 5.6.2 |
| `hostPath` volume onto the node | none | V09 | NSA (host access) |
| No requests/limits | CPU, memory and ephemeral-storage requests and limits, plus namespace `ResourceQuota` and `LimitRange` | V08 | NSA (resource exhaustion) |
| No probes | startup, readiness and liveness on `/healthz` | – | reliability |
| Workload in `default` | dedicated `invoice-api` namespace | – | CIS 5.6.4 |
| Secret as a plaintext env var committed in the manifest | `Secret` created at deploy time from a random value, **mounted as a file** (`0440`), read via `APP_SECRETS_DIR` | V07 | CIS 5.4.1 |
| Default ServiceAccount bound to `cluster-admin` | own ServiceAccount with **no** permissions; token not mounted; namespace `default` SA also has auto-mount off | V05, V06 | CIS 5.1.1/5.1.5/5.1.6 |
| No NetworkPolicies | default-deny both directions, DNS allowed, ingress only from labelled client namespaces and `monitoring`, egress only 443 to public IPs | V12–V15 | CIS 5.3.2 |
| `NodePort` service | `ClusterIP`; quota forbids NodePorts/LoadBalancers | V10 | – |
| No admission guard rails | namespace enforces Pod Security Standard **restricted** | V11 | CIS 5.2.1 |

The egress policy is the network-layer half of Project 1's SSRF defence
(SIA-05). Even if the application guard were bypassed, the pod can't reach
the Kubernetes API (V14), the node's kubelet (V15), RFC 1918, CGNAT or cloud
metadata ranges.

A deployment identity with a narrowly scoped Role (`invoice-api-deployer`:
patch the one Deployment, read pods and logs, nothing else) shows what least
privilege looks like for a CD pipeline.

### Control plane (kind-baseline.yaml → kind-hardened.yaml.tmpl)

| CIS v1.12 | Setting |
|---|---|
| 1.2.5 | `--kubelet-certificate-authority`; kubelets use CA-signed serving certs (`serverTLSBootstrap`), CSRs approved only for `system:node:*` requesters |
| 1.2.9 | `EventRateLimit` admission plugin (per-namespace and per-user limits) |
| 1.2.15, 1.3.2, 1.4.1 | profiling disabled on API server, controller manager, scheduler |
| 1.2.16–1.2.19 | audit logging with rotation; [policy](../cluster/hardening/audit-policy.yaml) records metadata only for Secrets and tokens, full request/response for RBAC changes |
| 1.2.27–1.2.28 | Secrets encrypted at rest (`aescbc`) with a per-cluster key that's generated locally and never committed (V16 reads etcd directly) |
| 1.2.29, 4.2.12 | strong TLS cipher suites only (API server and kubelet) |
| 1.2.30 | `--service-account-extend-token-expiration=false` |
| 1.3.1 | `--terminated-pod-gc-threshold` |
| 4.1.1, 4.1.9 | kubelet unit and config files `600` |
| 4.2.13 and 4.2.x | `podPidsLimit` (4.2.13), event QPS; anonymous auth off, webhook authorisation and read-only port 0 were already kind defaults |
| 5.2.x (cluster-wide) | [AdmissionConfiguration](../cluster/hardening/admission-config.yaml): every namespace defaults to enforce **baseline**, audit/warn **restricted**. The only exempt namespaces are `kube-system` and `local-path-storage`; the scanner namespace opts out explicitly and is deleted after each scan |

## Deviations and residual risks

| ID | Item | Decision |
|---|---|---|
| D1 | CIS 1.1.12: etcd data directory not owned by `etcd:etcd` | **Accepted.** kind runs etcd as root and the node image has no `etcd` user. On a managed or self-built cluster, fix it in the node image |
| D2 | `AlwaysPullImages` admission plugin (CIS 1.2.11) not enabled | **Accepted for the lab.** The image is side-loaded into kind, with no registry to pull from. In production, enable it together with a private registry |
| D3 | Anonymous authentication on the API server (CIS 1.2.1, manual) | kubeadm's liveness probes rely on anonymous `/livez`. Production answer: `AuthenticationConfiguration` with anonymous access limited to health endpoints |
| D4 | Encryption key on the local disk (`aescbc`) | Fine for a lab. Production answer: a KMS v2 provider (cloud KMS or Vault) so the key never sits next to etcd |
| D5 | One replica, `Recreate` strategy | SQLite on an emptyDir and an in-process rate limiter don't scale horizontally. Prerequisites for HA: Postgres plus a shared limiter (Redis), then 2+ replicas, a PDB and topology spread (Polaris's remaining availability warnings) |
| D6 | Kubescape C-0053 (deployer SA has RBAC) | **By design**, and scoped to one Deployment in one namespace |
| D7 | Kubescape C-0211 asks for SELinux options | **Not applicable**: kind/WSL nodes don't run SELinux, so labels would have no effect. `fsGroupChangePolicy` (the other half of the finding) was added |
| D8 | Kubescape C-0209 | Manual-review control that lists every namespace |
| D9 | Trivy KSV-0039/0040 | False positives: Trivy evaluates each document in isolation even though the namespace has a LimitRange and ResourceQuota. Suppressed with reasons in [`.trivyignore.yaml`](../manifests/.trivyignore.yaml); raw counts are still reported |
| D10 | No image signature or provenance enforcement | Next step: sign images in CI (cosign) and verify at admission (Kyverno or Sigstore policy-controller) |
| D11 | Audit logs stay on the node; no runtime threat detection | Covered in Project 3 (log shipping, alerting, Falco) |
| D12 | No Ingress/TLS | Access is via `kubectl port-forward`; a real deployment adds an ingress controller with TLS and forwards client IPs for the app's rate limiter |

## Problems found while doing the hardening

Each of these is small, and each would have produced a wrong result silently:

1. **kube-bench benchmarked the wrong Kubernetes version.** Its Job
   deliberately mounts no ServiceAccount token, so kube-bench couldn't query
   the API for the version, fell back to 1.18 and ran **CIS 1.6** without
   failing. Fix: pin `--benchmark cis-1.12` (and pin the cluster to 1.34, the
   newest version that benchmark covers).
2. **`kubectl apply` of a Secret leaks it into an annotation.** `apply` stores
   the full object, including the Secret data, in
   `last-applied-configuration`. Secrets are created with `kubectl create`
   from stdin instead.
3. **The auto-created `default` ServiceAccount mounts tokens.** It's easy to
   miss because the workload uses its own ServiceAccount. Found by the live
   Kubescape scan (C-0189) and fixed by declaring `default` with auto-mount
   off.
4. **kind renders kubeadm `v1beta3` for this version**, where `extraArgs` is a
   map; the `v1beta4` list syntax failed `kubeadm init`.
5. **The CI policy gate failed open.** On the first CI run Kubescape couldn't
   read its kubeconfig (a mode-600 file owned by the runner user; the image
   runs as another user, and Windows mounts ignore ownership, so it only
   broke in CI). The e2e job failed, yet `P2 / Policy gate` was **green**:
   the gate ran `policy_gate.py | tee`, and GitHub's implicit shell is
   `bash -e` *without* `pipefail`, so the step took `tee`'s exit code. Fixes:
   `shell: bash` (which adds `pipefail`) in every workflow, the gate now
   also requires the e2e job itself to succeed, and Kubescape runs as the
   invoking user. The unit test for "missing scanner fails closed" existed;
   the plumbing around it is what failed.
6. **Scanner false positives** (Polaris flagging a variable *named*
   `APP_SECRETS_DIR`; Trivy's per-document quota checks) were triaged with
   in-place, reasoned exemptions rather than by weakening thresholds.

## Reproduce

See the [README](../README.md#run-it). The whole "after" path also runs in
CI on every change: the `P2 / Hardened cluster e2e + scans` job creates the
hardened cluster on a GitHub runner, deploys, runs all 17 runtime checks and
all four scanners, and `P2 / Policy gate` enforces
[`hardening-policy.toml`](../hardening-policy.toml).
