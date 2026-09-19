#!/usr/bin/env bash
# Deploy the insecure baseline or the hardened manifests.
#
#   scripts/deploy.sh insecure   (into the baseline cluster, namespace default)
#   scripts/deploy.sh hardened   (into the hardened cluster, namespace invoice-api)
source "$(dirname "$0")/lib.sh"

variant="${1:?usage: deploy.sh insecure|hardened}"
case "$variant" in
  insecure)
    use_cluster baseline
    ns=default
    kubectl apply -k "$P2_DIR/manifests/insecure"
    ;;
  hardened)
    use_cluster hardened
    ns=invoice-api
    kubectl apply -f "$P2_DIR/manifests/hardened/namespace.yaml"
    step "Create the app Secret from a random value (never written to disk or argv)"
    if ! kubectl -n "$ns" get secret invoice-api-secrets >/dev/null 2>&1; then
      # Piped straight into `kubectl create` (not `apply`, which would also copy
      # the value into a last-applied-configuration annotation).
      "$PY" -c "
import json, secrets
print(json.dumps({'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque',
                  'metadata': {'name': 'invoice-api-secrets', 'namespace': '$ns',
                               'labels': {'app.kubernetes.io/name': 'invoice-api'}},
                  'stringData': {'APP_SECRET_KEY': secrets.token_urlsafe(48)}}))" \
        | kubectl create -f -
    fi
    kubectl apply -k "$P2_DIR/manifests/hardened"
    ;;
  *) echo "usage: deploy.sh insecure|hardened" >&2; exit 2 ;;
esac

step "Wait for rollout"
kubectl -n "$ns" rollout status deployment/invoice-api --timeout=180s
kubectl -n "$ns" get pods -o wide
