#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p results/logs

while true; do
  {
    echo "===== remaining best3 status ====="
    ./status_remaining_best3.sh
    echo
  } >> results/logs/remaining_best3_status.log 2>&1
  sleep "${VULNBENCH_STATUS_INTERVAL_SECONDS:-300}"
done
