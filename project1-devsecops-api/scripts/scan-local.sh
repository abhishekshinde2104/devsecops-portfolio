#!/usr/bin/env bash
# Run the full Project 1 CI security pipeline locally, using the same pinned
# scanner images as .github/workflows/project1-devsecops.yml. Only Docker is
# required.
#
#   scripts/scan-local.sh                 # everything except Dependency-Check
#   scripts/scan-local.sh --with-depcheck # include OWASP Dependency-Check
#                                         # (reads NVD_API_KEY from the environment)
#
# Works on Linux/macOS and Git Bash on Windows.
set -euo pipefail

TRIVY_IMAGE=aquasec/trivy:0.74.0
SEMGREP_IMAGE=semgrep/semgrep:1.177.0
SYFT_IMAGE=anchore/syft:v1.52.0
GRYPE_IMAGE=anchore/grype:v0.119.0
GITLEAKS_IMAGE=zricethezav/gitleaks:v8.30.1
DEPCHECK_IMAGE=owasp/dependency-check:13.0.0
IMAGE=secure-invoice-api:scan
P1=project1-devsecops-api

WITH_DEPCHECK=0
[[ "${1:-}" == "--with-depcheck" ]] && WITH_DEPCHECK=1

cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1 # stop Git Bash rewriting /container/paths
ROOT="$(pwd -W 2>/dev/null || pwd)"                 # this project
REPO="$(cd .. && (pwd -W 2>/dev/null || pwd))"      # monorepo root
# Scanner databases live in named Docker volumes: bind-mounting a Windows
# folder makes the multi-hundred-MB DB downloads very slow.
mkdir -p reports
rm -rf reports/*.json reports/*.sarif reports/dependency-check

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

step "Build runtime image"
docker build -q --target runtime -t "$IMAGE" . >/dev/null
docker save "$IMAGE" -o reports/image.tar

step "Gitleaks (whole repository history)"
docker run --rm -v "$REPO:/repo" -w /repo --entrypoint sh "$GITLEAKS_IMAGE" -c \
  "git config --global --add safe.directory /repo && gitleaks git . --config .gitleaks.toml --redact --report-format json --report-path $P1/reports/gitleaks.json --exit-code 0"

step "Semgrep (rule tests + scan from repo root)"
docker run --rm -v "$ROOT:/src" -w /src "$SEMGREP_IMAGE" semgrep --test --metrics=off semgrep-rules/
docker run --rm -v "$REPO:/src" -w /src "$SEMGREP_IMAGE" semgrep scan --quiet \
  --config p/python --config p/owasp-top-ten --config p/jwt --config p/github-actions \
  --config "$P1/semgrep-rules/fastapi-security.yml" \
  --metrics=off --json-output="$P1/reports/semgrep.json" --sarif-output="$P1/reports/semgrep.sarif" \
  "$P1" .github

step "Trivy (image, config, filesystem)"
trivy() { docker run --rm -v "$ROOT:/src" -v devsecops-trivy-cache:/root/.cache/trivy -w /src "$TRIVY_IMAGE" "$@"; }
trivy image --quiet --input reports/image.tar --scanners vuln,secret --format json --output reports/trivy-image.json
trivy config --quiet --format json --output reports/trivy-config.json .
trivy fs --quiet --scanners vuln --skip-db-update --format json --output reports/trivy-fs.json .

step "Syft SBOM + Grype"
# Syft reads the image from the Docker daemon: streaming a 200 MB tarball
# through a Docker Desktop bind mount fails with ENOMEM on Windows.
docker run --rm -v //var/run/docker.sock:/var/run/docker.sock -v "$ROOT/reports:/out" "$SYFT_IMAGE" \
  "docker:$IMAGE" -o cyclonedx-json=/out/sbom.cdx.json -o spdx-json=/out/sbom.spdx.json -q
# Syft can exit 0 with an empty file; an empty SBOM must never pass silently.
[[ -s reports/sbom.cdx.json && -s reports/sbom.spdx.json ]] || { echo "SBOM generation failed" >&2; exit 1; }
docker run --rm -v "$ROOT/reports:/work" -v devsecops-grype-cache:/root/.cache/grype -e GRYPE_DB_CACHE_DIR=/root/.cache/grype \
  "$GRYPE_IMAGE" sbom:/work/sbom.cdx.json -o json -q > reports/grype.json

step "Image policy"
python scripts/image_policy.py --image-tar reports/image.tar --output reports/image-policy.json
rm -f reports/image.tar

ALLOW_MISSING=()
if [[ $WITH_DEPCHECK == 1 ]]; then
  step "OWASP Dependency-Check"
  key_arg=()
  # The key is passed through the environment only; it is never echoed.
  [[ -n "${NVD_API_KEY:-}" ]] && key_arg=(-e NVD_API_KEY)
  docker run --rm --user 0:0 "${key_arg[@]}" -v "$ROOT:/src" -v devsecops-depcheck-data:/usr/share/dependency-check/data \
    --entrypoint sh "$DEPCHECK_IMAGE" -c \
    '/usr/share/dependency-check/bin/dependency-check.sh --project secure-invoice-api \
       --scan /src/requirements.txt --scan /src/requirements-dev.txt \
       --enableExperimental --disableOssIndex --format JSON --format HTML \
       --out /src/reports/dependency-check ${NVD_API_KEY:+--nvdApiKey "$NVD_API_KEY"}'
else
  ALLOW_MISSING=(--allow-missing dependency-check)
fi

step "Security gate"
python scripts/security_gate.py --policy security-gate.toml --reports reports \
  --output reports/gate-result.json "${ALLOW_MISSING[@]}"
