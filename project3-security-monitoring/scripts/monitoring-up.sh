#!/usr/bin/env bash
# Install the security monitoring stack into the hardened Project 2 cluster.
#
#   scripts/monitoring-up.sh            # Prometheus, Alertmanager, Grafana, rules, dashboard, alert sink
#   scripts/monitoring-up.sh --falco    # ...plus Falco runtime detection
#
# Prerequisite: the Project 2 hardened cluster with the app deployed:
#   ../project2-k8s-hardening/scripts/cluster-up.sh hardened
#   ../project2-k8s-hardening/scripts/deploy.sh hardened
source "$(dirname "$0")/lib.sh"

with_falco=0
[[ "${1:-}" == "--falco" ]] && with_falco=1

kube get deployment -n invoice-api invoice-api >/dev/null 2>&1 || {
  echo "invoice-api is not deployed in $CLUSTER_CONTEXT; run the Project 2 scripts first" >&2; exit 1; }

step "Helm repositories"
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts --force-update >/dev/null
helm repo add falcosecurity https://falcosecurity.github.io/charts --force-update >/dev/null
helm repo update prometheus-community falcosecurity >/dev/null

step "Namespaces"
kube apply -f "$P3_DIR/manifests/namespaces.yaml"

step "Grafana admin credentials (random, stored only in a Secret)"
if ! kube -n monitoring get secret grafana-admin >/dev/null 2>&1; then
  "$PY" -c "
import json, secrets
print(json.dumps({'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque',
                  'metadata': {'name': 'grafana-admin', 'namespace': 'monitoring'},
                  'stringData': {'admin-user': 'admin', 'admin-password': secrets.token_urlsafe(24)}}))" \
    | kube create -f -
fi

step "kube-prometheus-stack $KPS_CHART_VERSION"
helm upgrade --install kps prometheus-community/kube-prometheus-stack --kube-context "$CLUSTER_CONTEXT" \
  --version "$KPS_CHART_VERSION" --namespace monitoring \
  -f "$P3_DIR/helm/kube-prometheus-stack.values.yaml" --wait --timeout 10m

step "Security detections (PrometheusRule), scrape config, alert sink, dashboard"
{
  printf 'apiVersion: monitoring.coreos.com/v1\nkind: PrometheusRule\nmetadata:\n'
  printf '  name: invoice-api-security\n  namespace: monitoring\n'
  printf '  labels: {app.kubernetes.io/part-of: devsecops-portfolio}\nspec:\n'
  sed 's/^/  /' "$P3_DIR/rules/security-alerts.rules.yaml"
} | kube apply -f -
kube apply -f "$P3_DIR/manifests/servicemonitor.yaml" -f "$P3_DIR/manifests/alert-sink.yaml"
kube -n monitoring create configmap invoice-api-security-dashboard \
  --from-file=invoice-api-security.json="$P3_DIR/dashboards/invoice-api-security.json" \
  --dry-run=client -o yaml \
  | kube label --local -f - grafana_dashboard=1 -o yaml \
  | kube apply -f -
kube -n monitoring rollout status deployment/alert-sink --timeout=120s

if [[ $with_falco == 1 ]]; then
  step "Falco $FALCO_CHART_VERSION (modern eBPF, least privileged) + falcosidekick"
  helm upgrade --install falco falcosecurity/falco --kube-context "$CLUSTER_CONTEXT" \
    --version "$FALCO_CHART_VERSION" --namespace falco \
    -f "$P3_DIR/helm/falco.values.yaml" --wait --timeout 10m
fi

step "Status"
kube -n monitoring get pods
[[ $with_falco == 1 ]] && kube -n falco get pods
cat <<MSG

Grafana:     kubectl -n monitoring port-forward svc/kps-grafana 3000:80   -> http://127.0.0.1:3000
             user admin, password: kubectl -n monitoring get secret grafana-admin -o jsonpath='{.data.admin-password}' | base64 -d
Prometheus:  kubectl -n monitoring port-forward svc/kps-prometheus 9090:9090
MSG
