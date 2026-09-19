| Measure | Before (kind defaults + insecure manifests) | After (hardened) |
|---|---|---|
| Runtime checks secure (scripts/verify.sh) | 1/17 | 17/17 |
| kube-bench CIS v1.12: FAIL | 12 | 1 |
| kube-bench CIS v1.12: WARN (manual checks) | 56 | 49 |
| kube-bench CIS v1.12: PASS | 63 | 81 |
| Kubescape live namespace: compliance % | 47.2 | 62.7 |
| Kubescape live: failed controls caused by the app's own resources | 46 | 3 |
| Kubescape live: failed controls in total (incl. kubeadm built-ins) | 46 | 19 |
| Kubescape manifests: compliance % | 67.2 | 88.5 |
| Kubescape manifests: NSA % | 50 | 100 |
| Kubescape manifests: MITRE % | 76.5 | 94.1 |
| Kubescape manifests: CIS v1.12 % | 75 | 81.2 |
| Polaris score (0-100) | 37 | 90 |
| Polaris danger-level findings | 6 | 0 |
| Trivy HIGH+CRITICAL misconfigurations | 3 | 0 |
| Trivy MEDIUM (raw / after triage) | 5 / 5 | 1 / 1 |
| Trivy LOW (raw / after triage) | 12 / 12 | 15 / 0 |

| Runtime check | Before | After | Evidence (after) |
|---|---|---|---|
| V01 Container runs as non-root | ❌ | ✅ | uid=10001 |
| V02 Root filesystem is read-only | ❌ | ✅ | write to /app denied |
| V03 Container is not privileged | ❌ | ✅ | privileged unset/false |
| V04 No effective Linux capabilities | ❌ | ✅ | CapEff=0000000000000000 |
| V05 No ServiceAccount token mounted | ❌ | ✅ | token absent |
| V06 Workload identity cannot read Secrets cluster-wide | ❌ | ✅ | can-i list secrets -A: no |
| V07 Secret not exposed as environment variable | ❌ | ✅ | read from mounted file |
| V08 CPU/memory limits set | ❌ | ✅ | memory limit 256Mi |
| V09 No hostPath volumes | ❌ | ✅ | none |
| V10 Service not exposed on node ports | ❌ | ✅ | type ClusterIP |
| V11 Privileged pod rejected at admission | ❌ | ✅ | violates PodSecurity "restricted:v1.34" |
| V12 Unauthorised namespace cannot reach the API | ❌ | ✅ | HTTP 000 |
| V13 Authorised client namespace can reach the API (control) | ✅ | ✅ | HTTP 200 |
| V14 Pod cannot reach the Kubernetes API server | ❌ | ✅ | 10.96.0.1:443 blocked |
| V15 Pod cannot reach the node's kubelet (SSRF pivot) | ❌ | ✅ | 172.20.0.2:10250 blocked |
| V16 Secrets encrypted at rest in etcd | ❌ | ✅ | etcd value starts k8s:enc:aescbc:v1 |
| V17 API server audit log is written | ❌ | ✅ | 1319 events |

**kube-bench checks still failing after hardening** (1):

- 1.1.12 Ensure that the etcd data directory ownership is set to etcd:etcd (Automated)

**Kubescape live controls still failing on app resources** (3):

- C-0053 Access container service account
- C-0209 CIS-5.6.1 Create administrative boundaries between resources using namespaces
- C-0211 CIS-5.6.3 Apply Security Context to Your Pods and Containers
