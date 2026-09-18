#!/usr/bin/env bash
# Run the full CI security pipeline locally, using the same pinned scanner
# images as .github/workflows/devsecops.yml. Only Docker is required.
#
#   scripts/scan-local.sh                 # everything except Dependency-Check
#   scripts/scan-local.sh --with-depcheck # include OWASP Dependency-Check
#                                         # (first run downloads the NVD, set NVD_API_KEY)
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

WITH_DEPCHECK=0
[[ "${1:-}" == "--with-depcheck" ]] && WITH_DEPCHECK=1

cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1 # stop Git Bash rewriting /container/paths
ROOT="$(pwd -W 2>/dev/null || pwd)"
CACHE="${HOME}/.cache/devsecops-scan"
mkdir -p reports "$CACHE/trivy" "$CACHE/grype" "$CACHE/depcheck"
rm -f reports/*.json reports/*.sarif

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

step "Build runtime image"
docker build -q --target runtime -t "$IMAGE" . >/dev/null
docker save "$IMAGE" -o reports/image.tar

step "Gitleaks (git history)"
docker run --rm -v "$ROOT:/repo" -w /repo --entrypoint sh "$GITLEAKS_IMAGE" -c \
  'git config --global --add safe.directory /repo && gitleaks git . --config .gitleaks.toml --redact --report-format json --report-path reports/gitleaks.json --exit-code 0'

step "Semgrep (rule tests + scan)"
docker run --rm -v "$ROOT:/src" -w /src "$SEMGREP_IMAGE" semgrep --test --metrics=off semgrep-rules/
docker run --rm -v "$ROOT:/src" -w /src "$SEMGREP_IMAGE" semgrep scan --quiet \
  --config p/python --config p/owasp-top-ten --config p/jwt --config semgrep-rules/fastapi-security.yml \
  --metrics=off --json-output=reports/semgrep.json --sarif-output=reports/semgrep.sarif

step "Trivy (image, config, filesystem)"
trivy() { docker run --rm -v "$ROOT:/src" -v "$CACHE/trivy:/root/.cache/trivy" -w /src "$TRIVY_IMAGE" "$@"; }
trivy image --quiet --input reports/image.tar --scanners vuln,secret --format json --output reports/trivy-image.json
trivy config --quiet --format json --output reports/trivy-config.json .
trivy fs --quiet --scanners vuln --skip-db-update --format json --output reports/trivy-fs.json .

step "Syft SBOM + Grype"
docker run --rm -v "$ROOT/reports:/out" "$SYFT_IMAGE" docker-archive:/out/image.tar \
  -o cyclonedx-json=/out/sbom.cdx.json -o spdx-json=/out/sbom.spdx.json -q
docker run --rm -v "$ROOT/reports:/work" -v "$CACHE/grype:/root/.cache/grype" -e GRYPE_DB_CACHE_DIR=/root/.cache/grype \
  "$GRYPE_IMAGE" sbom:/work/sbom.cdx.json -o json -q > reports/grype.json
rm -f reports/image.tar

ALLOW_MISSING=()
if [[ $WITH_DEPCHECK == 1 ]]; then
  step "OWASP Dependency-Check"
  key_arg=()
  [[ -n "${NVD_API_KEY:-}" ]] && key_arg=(--nvdApiKey "$NVD_API_KEY")
  docker run --rm --user 0:0 -v "$ROOT:/src" -v "$CACHE/depcheck:/usr/share/dependency-check/data" "$DEPCHECK_IMAGE" \
    --project secure-invoice-api --scan /src/requirements.txt --scan /src/requirements-dev.txt \
    --enableExperimental --disableOssIndex --format JSON --format HTML --out /src/reports/dependency-check \
    "${key_arg[@]}"
else
  ALLOW_MISSING=(--allow-missing dependency-check)
fi

step "Security gate"
python scripts/security_gate.py --policy security-gate.toml --reports reports \
  --output reports/gate-result.json "${ALLOW_MISSING[@]}"
