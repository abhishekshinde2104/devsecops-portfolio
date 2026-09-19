#!/usr/bin/env bash
# Prove the hardening on the *running* cluster, not just in YAML.
#
#   scripts/verify.sh baseline   # expected: most checks fail (the "before")
#   scripts/verify.sh hardened   # expected: every check passes; exit 1 otherwise
#
# Results go to reports/<cluster>/verify.tsv for scripts/report.py.
source "$(dirname "$0")/lib.sh"

which="${1:?usage: verify.sh baseline|hardened}"
use_cluster "$which"
node="$(cluster_name "$which")-control-plane"
if [[ $which == baseline ]]; then ns=default; sa=default; else ns=invoice-api; sa=invoice-api; fi

out="$P2_DIR/reports/$which"
mkdir -p "$out"
tsv="$out/verify.tsv"
printf 'id\tcheck\tsecure\tevidence\n' > "$tsv"
failed=0

record() { # id, description, secure(true|false), evidence
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$tsv"
  if [[ $3 == true ]]; then ok "$1 $2 ($4)"; else bad "$1 $2 ($4)"; failed=$((failed + 1)); fi
}

pod="$(kubectl -n "$ns" get pods -o name | grep '/invoice-api-' | head -1 | cut -d/ -f2)"
[[ -n $pod ]] || { echo "no invoice-api pod in namespace $ns; run scripts/deploy.sh first" >&2; exit 1; }
inpod() { kubectl -n "$ns" exec "$pod" -c api -- python -c "$1" 2>/dev/null; }
field() { kubectl -n "$ns" get pod "$pod" -o jsonpath="$1"; }

step "Workload identity and privileges ($which: $ns/$pod)"
uid="$(inpod 'import os; print(os.getuid())')"
if [[ $uid != 0 ]]; then record V01 "Container runs as non-root" true "uid=$uid"
else record V01 "Container runs as non-root" false "uid=0"; fi

if inpod "open('/app/.write-test', 'w')" >/dev/null; then
  record V02 "Root filesystem is read-only" false "wrote /app/.write-test"
else
  record V02 "Root filesystem is read-only" true "write to /app denied"
fi

if [[ "$(field '{.spec.containers[0].securityContext.privileged}')" == true ]]; then record V03 "Container is not privileged" false "privileged: true"
else record V03 "Container is not privileged" true "privileged unset/false"; fi

capeff="$(inpod "print([l.split()[1] for l in open('/proc/self/status') if l.startswith('CapEff')][0])")"
if [[ $capeff == 0000000000000000 ]]; then record V04 "No effective Linux capabilities" true "CapEff=$capeff"
else record V04 "No effective Linux capabilities" false "CapEff=$capeff"; fi

token="$(inpod "import os; print(os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount/token'))")"
if [[ $token == False ]]; then record V05 "No ServiceAccount token mounted" true "token absent"
else record V05 "No ServiceAccount token mounted" false "token mounted in pod"; fi

canlist="$(kubectl auth can-i list secrets --all-namespaces --as="system:serviceaccount:$ns:$sa" 2>/dev/null || true)"
if [[ $canlist == no ]]; then record V06 "Workload identity cannot read Secrets cluster-wide" true "can-i list secrets -A: no"
else record V06 "Workload identity cannot read Secrets cluster-wide" false "can-i list secrets -A: $canlist"; fi

inenv="$(inpod "import os; print('APP_SECRET_KEY' in os.environ)")"
if [[ $inenv == False ]]; then record V07 "Secret not exposed as environment variable" true "read from mounted file"
else record V07 "Secret not exposed as environment variable" false "APP_SECRET_KEY in env"; fi

limits="$(field '{.spec.containers[0].resources.limits.memory}')"
if [[ -n $limits ]]; then record V08 "CPU/memory limits set" true "memory limit $limits"
else record V08 "CPU/memory limits set" false "no limits"; fi

hostpath="$(field '{.spec.volumes[*].hostPath.path}')"
if [[ -z $hostpath ]]; then record V09 "No hostPath volumes" true "none"
else record V09 "No hostPath volumes" false "hostPath $hostpath"; fi

svctype="$(kubectl -n "$ns" get svc invoice-api -o jsonpath='{.spec.type}')"
if [[ $svctype == ClusterIP ]]; then record V10 "Service not exposed on node ports" true "type ClusterIP"
else record V10 "Service not exposed on node ports" false "type $svctype"; fi

step "Admission control"
if kubectl -n "$ns" apply --dry-run=server -f "$P2_DIR/manifests/tools/privileged-pod.yaml" >/dev/null 2>"$out/psa.err"; then
  record V11 "Privileged pod rejected at admission" false "API server accepted it"
else
  record V11 "Privileged pod rejected at admission" true "$(grep -o 'violates PodSecurity "[a-z]*:[^"]*"' "$out/psa.err" | head -1)"
fi

step "Network policy enforcement"
kubectl apply -f "$P2_DIR/manifests/tools/probes.yaml" >/dev/null
kubectl -n netpol-allowed wait pod/probe --for=condition=Ready --timeout=120s >/dev/null
kubectl -n netpol-denied wait pod/probe --for=condition=Ready --timeout=120s >/dev/null
url="http://invoice-api.$ns.svc.cluster.local/healthz"
probe() { kubectl -n "$1" exec probe -- curl -s -o /dev/null -m 5 -w '%{http_code}' "$url" 2>/dev/null || true; }

code="$(probe netpol-denied)"
if [[ $code != 200 ]]; then record V12 "Unauthorised namespace cannot reach the API" true "HTTP ${code:-timeout}"
else record V12 "Unauthorised namespace cannot reach the API" false "HTTP 200 from netpol-denied"; fi
code="$(probe netpol-allowed)"
if [[ $code == 200 ]]; then record V13 "Authorised client namespace can reach the API (control)" true "HTTP 200"
else record V13 "Authorised client namespace can reach the API (control)" false "HTTP ${code:-timeout}"; fi

connect() { inpod "import socket; socket.create_connection(('$1', $2), 3); print('open')" || true; }
apiip="$(kubectl get svc kubernetes -n default -o jsonpath='{.spec.clusterIP}')"
if [[ "$(connect "$apiip" 443)" != open ]]; then record V14 "Pod cannot reach the Kubernetes API server" true "$apiip:443 blocked"
else record V14 "Pod cannot reach the Kubernetes API server" false "$apiip:443 reachable"; fi
nodeip="$(kubectl get node "$node" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
if [[ "$(connect "$nodeip" 10250)" != open ]]; then record V15 "Pod cannot reach the node's kubelet (SSRF pivot)" true "$nodeip:10250 blocked"
else record V15 "Pod cannot reach the node's kubelet (SSRF pivot)" false "$nodeip:10250 reachable"; fi

step "Control plane"
# `create`, not `apply`: apply would also copy the Secret into a
# last-applied-configuration annotation.
kubectl -n "$ns" delete secret etcd-canary --ignore-not-found >/dev/null
kubectl -n "$ns" create secret generic etcd-canary --from-literal=canary=plaintext-canary-value >/dev/null
etcdpod="etcd-$node"
raw="$(kubectl -n kube-system exec "$etcdpod" -- etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key get "/registry/secrets/$ns/etcd-canary" --print-value-only 2>/dev/null \
  | tr -c '[:print:]' '.')"
kubectl -n "$ns" delete secret etcd-canary --ignore-not-found >/dev/null
if [[ $raw == *k8s:enc:aescbc* ]]; then
  record V16 "Secrets encrypted at rest in etcd" true "etcd value starts k8s:enc:aescbc:v1"
elif [[ $raw == *plaintext-canary-value* ]]; then
  record V16 "Secrets encrypted at rest in etcd" false "canary value readable in etcd"
else
  record V16 "Secrets encrypted at rest in etcd" false "could not read etcd value"
fi

if docker exec "$node" test -s /var/log/kubernetes/audit/audit.log 2>/dev/null; then
  record V17 "API server audit log is written" true "$(docker exec "$node" sh -c 'wc -l < /var/log/kubernetes/audit/audit.log') events"
else
  record V17 "API server audit log is written" false "no audit log"
fi

kubectl delete -f "$P2_DIR/manifests/tools/probes.yaml" --wait=false >/dev/null 2>&1 || true

total=$(($(wc -l < "$tsv") - 1))
step "$which: $((total - failed))/$total checks secure (results: ${tsv#"$P2_DIR"/})"
if [[ $which == hardened && $failed -gt 0 ]]; then exit 1; fi
exit 0
