#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

interval_seconds=${VULNBENCH_STATUS_INTERVAL_SECONDS:-300}
out="results/logs/missing_latest_status.log"
mkdir -p "$(dirname "$out")"

while true; do
  {
    echo "============================================================"
    ./status_missing_latest.sh
    echo
  } >> "$out" 2>&1
  sleep "$interval_seconds"
done
