#!/usr/bin/env bash
# shellcheck disable=SC2034  # variables are consumed by the scripts that source this file
# Shared helpers for the Project 2 scripts. Works on Linux/macOS (CI) and
# Git Bash on Windows.
set -euo pipefail

# D:/... on Windows: understood by bash, Docker and native kind/kubectl alike
# (Git Bash's automatic /d/... translation is off because of MSYS_NO_PATHCONV).
P2_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && (pwd -W 2>/dev/null || pwd))"
REPO_DIR="$(cd "$P2_DIR/.." && (pwd -W 2>/dev/null || pwd))"
P1_DIR="$REPO_DIR/project1-devsecops-api"
export MSYS_NO_PATHCONV=1   # keep /container/paths intact in Git Bash

APP_IMAGE="secure-invoice-api:1.0.0"
KUBESCAPE_IMAGE="quay.io/kubescape/kubescape-cli:v4.0.14"
TRIVY_IMAGE="aquasec/trivy:0.74.0"
POLARIS_VERSION="10.2.5"

# Absolute path usable by Docker/kind on every platform (D:/... on Windows).
abspath() { (cd "$1" && (pwd -W 2>/dev/null || pwd)); }

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; }

cluster_name() {
  case "$1" in
    baseline) echo p2-baseline ;;
    hardened) echo p2-hardened ;;
    *) echo "unknown cluster '$1' (baseline|hardened)" >&2; exit 2 ;;
  esac
}

use_cluster() { kubectl config use-context "kind-$(cluster_name "$1")" >/dev/null; }

# python3 on Linux; on Windows "python3" is often the Microsoft Store stub.
PY=python3
"$PY" -c "pass" >/dev/null 2>&1 || PY=python
