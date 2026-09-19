#!/usr/bin/env bash
# Create the "baseline" (kind defaults) or "hardened" (CIS-hardened control
# plane) cluster and side-load the Project 1 image.
#
#   scripts/cluster-up.sh baseline|hardened
source "$(dirname "$0")/lib.sh"

which="${1:?usage: cluster-up.sh baseline|hardened}"
name="$(cluster_name "$which")"

if kind get clusters 2>/dev/null | grep -qx "$name"; then
  echo "cluster $name already exists"
else
  config="$P2_DIR/cluster/kind-baseline.yaml"
  if [[ $which == hardened ]]; then
    step "Generate the etcd encryption key for Secrets (git-ignored)"
    gen="$P2_DIR/cluster/.generated"
    mkdir -p "$gen"
    # 32 random bytes for AES-CBC. The key only ever exists on this machine
    # and inside the kind node; rotate by re-creating the cluster.
    key="$(head -c 32 /dev/urandom | base64 | tr -d '\n')"
    umask 077
    cat > "$gen/encryption-config.yaml" <<YAML
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: [secrets]
    providers:
      - aescbc:
          keys:
            - name: key-$(date +%Y%m%d)
              secret: $key
      - identity: {}
YAML
    unset key
    config="$P2_DIR/cluster/kind-hardened.yaml"
    sed -e "s#__HARDENING_DIR__#$(abspath "$P2_DIR/cluster/hardening")#" \
        -e "s#__GENERATED_DIR__#$(abspath "$gen")#" \
        "$P2_DIR/cluster/kind-hardened.yaml.tmpl" > "$config"
  fi
  step "Create kind cluster $name"
  kind create cluster --config "$config" --wait 180s

  if [[ $which == hardened ]]; then
    use_cluster hardened
    step "Approve kubelet serving certificates (CIS 1.2.5)"
    # With serverTLSBootstrap the kubelet asks the cluster CA for its serving
    # cert. Approve only kubernetes.io/kubelet-serving CSRs requested by a
    # node identity (system:node:*), never arbitrary CSRs.
    for _ in $(seq 1 30); do
      mapfile -t pending < <(kubectl get csr -o jsonpath='{range .items[?(@.spec.signerName=="kubernetes.io/kubelet-serving")]}{.metadata.name}{" "}{.spec.username}{" "}{.status.conditions[0].type}{"\n"}{end}' \
        | awk '$2 ~ /^system:node:/ && $3 == "" {print $1}')
      if (( ${#pending[@]} )); then kubectl certificate approve "${pending[@]}"; break; fi
      sleep 2
    done
    node="$name-control-plane"
    step "Node file permissions (CIS 4.1.1, 4.1.9)"
    # On a real fleet this is baked into the node image or applied by config
    # management; kind nodes are containers, so apply it after creation.
    docker exec "$node" sh -c 'chmod 600 /etc/systemd/system/kubelet.service.d/*.conf /var/lib/kubelet/config.yaml'
  fi
fi

step "Build and side-load $APP_IMAGE"
if ! docker image inspect "$APP_IMAGE" >/dev/null 2>&1; then
  docker build -q --target runtime -t "$APP_IMAGE" "$P1_DIR" >/dev/null
fi
kind load docker-image "$APP_IMAGE" --name "$name"
use_cluster "$which"
kubectl get nodes -o wide
