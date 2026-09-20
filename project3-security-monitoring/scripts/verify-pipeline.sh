#!/usr/bin/env bash
# Port-forward the stack and run the end-to-end pipeline checks.
#
#   scripts/verify-pipeline.sh            # C01-C07
#   scripts/verify-pipeline.sh --falco    # + C08 (needs monitoring-up.sh --falco)
source "$(dirname "$0")/lib.sh"

falco_flag=""
[[ "${1:-}" == "--falco" ]] && falco_flag="--falco"

trap stop_port_forwards EXIT

step "Port-forwarding Prometheus, Alertmanager, Grafana, the API and the sink"
port_forward monitoring   svc/kps-prometheus              9090:9090
port_forward monitoring   svc/kps-alertmanager            9093:9093
port_forward monitoring   svc/kps-grafana                 3000:80
port_forward invoice-api  svc/invoice-api                 18000:80
port_forward monitoring   svc/alert-sink                  18080:8080

gpass="$(kube -n monitoring get secret grafana-admin -o jsonpath='{.data.admin-password}' | "$PY" -c 'import sys,base64;print(base64.b64decode(sys.stdin.read()).decode())')"

step "Running checks"
"$PY" "$P3_DIR/scripts/verify_pipeline.py" \
  --prometheus http://127.0.0.1:9090 \
  --alertmanager http://127.0.0.1:9093 \
  --grafana http://127.0.0.1:3000 \
  --api http://127.0.0.1:18000 \
  --sink http://127.0.0.1:18080 \
  --grafana-password "$gpass" \
  $falco_flag
