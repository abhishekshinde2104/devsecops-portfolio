#!/usr/bin/env bash
# Run every scanner against one cluster + its manifests and write
# reports/<cluster>/summary.json.
#
#   scripts/scan.sh baseline    # kind defaults + insecure manifests
#   scripts/scan.sh hardened    # hardened control plane + hardened manifests
#
# Scanners:
#   kube-bench  CIS Kubernetes Benchmark v1.12 on the node (Job in-cluster)
#   Kubescape   NSA, MITRE and CIS v1.12 frameworks, live namespace + manifests
#   Trivy       misconfiguration scan of the manifests
#   Polaris     best-practice score of the manifests
source "$(dirname "$0")/lib.sh"

which="${1:?usage: scan.sh baseline|hardened}"
name="$(cluster_name "$which")"
use_cluster "$which"
if [[ $which == baseline ]]; then ns=default; variant=insecure; else ns=invoice-api; variant=hardened; fi
out="$P2_DIR/reports/$which"
mkdir -p "$out"
OUT_ABS="$(abspath "$out")"
MANIFESTS_ABS="$(abspath "$P2_DIR/manifests")"

step "kube-bench (CIS Kubernetes Benchmark)"
kubectl apply -f "$P2_DIR/manifests/tools/kube-bench.yaml" >/dev/null
kubectl -n security-tools wait --for=condition=complete job/kube-bench --timeout=300s >/dev/null
kubectl -n security-tools logs job/kube-bench | grep '^{' > "$out/kube-bench.json"   # drop warning lines
kubectl delete namespace security-tools --wait=false >/dev/null   # remove the privileged namespace again

step "Kubescape: live namespace '$ns'"
kc_dir="$(mktemp -d)"
trap 'rm -rf "$kc_dir"' EXIT   # the internal kubeconfig holds admin credentials
kind get kubeconfig --internal --name "$name" > "$kc_dir/config"
docker run --rm --network kind -v "$(abspath "$kc_dir"):/kc:ro" -e KUBECONFIG=/kc/config -v "$OUT_ABS:/out" \
  "$KUBESCAPE_IMAGE" scan framework nsa,mitre,cis-v1.12.0 --include-namespaces "$ns" \
  --format json --output /out/kubescape-cluster.json --keep-local >/dev/null

step "Kubescape: manifests/$variant"
docker run --rm -v "$MANIFESTS_ABS:/m:ro" -v "$OUT_ABS:/out" \
  "$KUBESCAPE_IMAGE" scan framework nsa,mitre,cis-v1.12.0 "/m/$variant" \
  --format json --output /out/kubescape-manifests.json --keep-local >/dev/null

step "Trivy: manifests/$variant"
docker run --rm -v "$MANIFESTS_ABS:/m:ro" -v "$OUT_ABS:/out" -v devsecops-trivy-cache:/root/.cache/trivy \
  "$TRIVY_IMAGE" config --quiet --format json --output /out/trivy-config-raw.json "/m/$variant"
# Same scan with the documented triage in manifests/.trivyignore.yaml applied.
docker run --rm -v "$MANIFESTS_ABS:/m:ro" -v "$OUT_ABS:/out" -v devsecops-trivy-cache:/root/.cache/trivy \
  "$TRIVY_IMAGE" config --quiet --ignorefile /m/.trivyignore.yaml --format json --output /out/trivy-config.json "/m/$variant"

step "Polaris: manifests/$variant"
# Release binary, SHA-256 verified against the release checksums, cached in a volume.
docker run --rm -v devsecops-polaris:/opt/polaris -v "$MANIFESTS_ABS:/m:ro" alpine:3.24 sh -c "
  set -e; cd /opt/polaris
  if [ ! -x polaris-$POLARIS_VERSION ]; then
    base=https://github.com/FairwindsOps/polaris/releases/download/v$POLARIS_VERSION
    wget -q \$base/polaris_${POLARIS_VERSION}_linux_amd64.tar.gz \$base/checksums.txt
    grep ' polaris_${POLARIS_VERSION}_linux_amd64.tar.gz\$' checksums.txt | sha256sum -c - >/dev/null
    tar -xzf polaris_${POLARIS_VERSION}_linux_amd64.tar.gz polaris && mv polaris polaris-$POLARIS_VERSION
  fi
  ./polaris-$POLARIS_VERSION audit --audit-path /m/$variant --format json" > "$out/polaris.json"

step "Summary"
"$PY" "$P2_DIR/scripts/report.py" summarise "$out"
