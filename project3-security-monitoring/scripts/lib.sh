#!/usr/bin/env bash
# shellcheck disable=SC2034  # variables are consumed by the scripts that source this file
# Shared helpers for Project 3. Reuses the Project 2 cluster tooling: the
# monitoring stack is installed into the CIS-hardened cluster from Project 2.
set -euo pipefail

P3_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && (pwd -W 2>/dev/null || pwd))"
REPO_DIR="$(cd "$P3_DIR/.." && (pwd -W 2>/dev/null || pwd))"
P2_SCRIPTS="$REPO_DIR/project2-k8s-hardening/scripts"
export MSYS_NO_PATHCONV=1

KPS_CHART_VERSION="91.4.1"
FALCO_CHART_VERSION="9.1.0"
CLUSTER_CONTEXT="kind-p2-hardened"

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

PY=python3
"$PY" -c "pass" >/dev/null 2>&1 || PY=python

kube() { kubectl --context "$CLUSTER_CONTEXT" "$@"; }

# Start a port-forward in the background and wait until it accepts connections.
# usage: port_forward <namespace> <svc/name> <local>:<remote>
PF_PIDS=()
port_forward() {
  kube -n "$1" port-forward "$2" "$3" >/dev/null 2>&1 &
  PF_PIDS+=("$!")
  local port="${3%%:*}"
  for _ in $(seq 1 30); do
    if "$PY" -c "import socket; socket.create_connection(('127.0.0.1', $port), 1)" 2>/dev/null; then return 0; fi
    sleep 1
  done
  echo "port-forward to $2 did not come up" >&2
  return 1
}
stop_port_forwards() { for pid in "${PF_PIDS[@]:-}"; do [[ -n $pid ]] && kill "$pid" 2>/dev/null || true; done; }
