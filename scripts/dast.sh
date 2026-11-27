#!/usr/bin/env bash
# Scan only the calculator built from this checkout, never an external URL.
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
mode=${1:-baseline}
case "$mode" in baseline|full) ;; *) echo 'Usage: bash scripts/dast.sh [baseline|full]' >&2; exit 2 ;; esac
for tool in docker python3 timeout; do command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 2; }; done

# Resolved from the official GHCR stable manifest on 2026-11-27 (amd64/arm64 index).
scanner_image=ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af
report_dir="$root/.local/dast/$mode"
if [[ -e "$report_dir" ]]; then echo "Report directory already exists: $report_dir. Move it before a new run." >&2; exit 2; fi
mkdir -p "$report_dir"
# Only this new report directory is writable by the scanner's unprivileged user.
chmod 777 "$report_dir"
run_name="calculator-dast-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$"
network="$run_name"
target_container="$run_name-app"
scanner_container="$run_name-zap"
target_image="$run_name:target"
cleanup() {
  docker rm -f "$scanner_container" "$target_container" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker image rm "$target_image" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker pull "$scanner_image"
docker build -t "$target_image" src/python
docker network create --internal "$network"
docker run -d --name "$target_container" --network "$network" --network-alias calculator \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL --security-opt no-new-privileges "$target_image"
ready=false
for ((attempt=0; attempt<40; attempt++)); do
  if docker exec "$target_container" python -c \
    'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:5000/healthz", timeout=2).status == 200' >/dev/null 2>&1; then
    ready=true; break
  fi
  sleep 1
done
if [[ "$ready" != true ]]; then docker logs "$target_container"; echo 'Calculator did not become healthy.' >&2; exit 2; fi

scan_script=zap-baseline.py
if [[ "$mode" == full ]]; then scan_script=zap-full-scan.py; fi
scan=("$scan_script" -t http://calculator:5000 -m 1 -T 5 -r zap.html -J zap.json
  -z '-config autoupdate.checkOnStart=false -config autoupdate.downloadNewRelease=false -config autoupdate.installAddonUpdates=false')
if [[ "$mode" == baseline ]]; then scan+=(--autooff); fi
set +e
timeout --signal=TERM --kill-after=20s 600s docker run --rm --name "$scanner_container" \
  --network "$network" --cap-drop ALL --security-opt no-new-privileges \
  -v "$report_dir:/zap/wrk:rw" "$scanner_image" "${scan[@]}" 2>&1 | tee "$report_dir/scanner.log"
scanner_status=${PIPESTATUS[0]}
set -e
docker logs "$target_container" > "$report_dir/application.log" 2>&1
python3 scripts/dast_report.py "$report_dir/zap.json" --scanner-exit "$scanner_status" \
  --mode "$mode" --image "$scanner_image" --commit "$(git rev-parse HEAD)"
