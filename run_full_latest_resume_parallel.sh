#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

set -a
source .env
set +a

source "$ROOT_DIR/benchmark/model_suites.sh"

MAX_PARALLEL=${VULNBENCH_FULL_MAX_PARALLEL:-3}
MODEL_TIMEOUT_SECONDS=${VULNBENCH_FULL_RUN_TIMEOUT_SECONDS:-86400}
BENCHMARK_PATH=${VULNBENCH_FULL_BENCHMARK_PATH:-data/benchmark/vulnbench_full.json}
EXPECTED_TOTAL=${VULNBENCH_FULL_EXPECTED_TOTAL:-1650}

LOGDIR="$ROOT_DIR/results/logs"
mkdir -p "$LOGDIR"

models=("${VULNBENCH_LATEST_MODELS[@]}")

is_complete() {
  local output="$1"
  [[ -f "$output" ]] && .venv/bin/python - "$output" "$EXPECTED_TOTAL" <<'PY'
import json
import sys
from pathlib import Path

p = Path(sys.argv[1])
expected = int(sys.argv[2])
try:
    d = json.loads(p.read_text())
    sys.exit(0 if d.get("aggregate", {}).get("total_instances") == expected else 1)
except Exception:
    sys.exit(1)
PY
}

run_model() {
  local model="$1"
  local safe_name="${model#openrouter/}"
  safe_name="${safe_name//\//_}"
  safe_name="${safe_name//:/_}"
  local outfile="results/full_${safe_name}.json"
  local logfile="$LOGDIR/full_resume_${safe_name}.log"

  if is_complete "$outfile"; then
    echo "[SKIP] $model already complete"
    return 0
  fi

  echo "[START] $model output=$outfile log=$logfile"
  local start
  start=$(date +%s)

  .venv/bin/python -m benchmark.run_eval \
    --benchmark "$BENCHMARK_PATH" \
    --model "$model" \
    --include-source \
    --file-hint-mode description \
    --resume \
    --output "$outfile" > "$logfile" 2>&1 &
  local child=$!

  while kill -0 "$child" 2>/dev/null; do
    local now
    now=$(date +%s)
    if (( now - start > MODEL_TIMEOUT_SECONDS )); then
      echo "[TIMEOUT] $model exceeded ${MODEL_TIMEOUT_SECONDS}s; terminating pid=${child}" >> "$logfile"
      kill -TERM "$child" 2>/dev/null || true
      sleep 10
      kill -KILL "$child" 2>/dev/null || true
      wait "$child" || true
      return 124
    fi
    sleep 30
  done

  wait "$child"
  local rc=$?
  echo "[EXIT] $model rc=${rc}" >> "$logfile"
  return "$rc"
}

echo "=== VulnBench Full latest resume batch ==="
echo "benchmark=$BENCHMARK_PATH expected_total=$EXPECTED_TOTAL max_parallel=$MAX_PARALLEL"
echo "logs=$LOGDIR"

active_pids=()
batch_rc=0

for model in "${models[@]}"; do
  while (( ${#active_pids[@]} >= MAX_PARALLEL )); do
    for i in "${!active_pids[@]}"; do
      if ! kill -0 "${active_pids[$i]}" 2>/dev/null; then
        wait "${active_pids[$i]}" || batch_rc=1
        unset 'active_pids[$i]'
        active_pids=("${active_pids[@]}")
        break
      fi
    done
    sleep 1
  done

  run_model "$model" &
  active_pids+=("$!")
done

for pid in "${active_pids[@]}"; do
  wait "$pid" || batch_rc=1
done

echo "[DONE] full latest resume batch status=${batch_rc}"
exit "$batch_rc"
