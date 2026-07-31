#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p results/logs

while true; do
  {
    echo "===== full latest status ====="
    ./status_full_latest_resume.sh
    echo
  } >> results/logs/full_latest_status.log 2>&1
  sleep "${VULNBENCH_STATUS_INTERVAL_SECONDS:-300}"
done
