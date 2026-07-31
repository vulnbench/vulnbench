#!/usr/bin/env bash
set -euo pipefail

MAX_PARALLEL=10

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

source .venv/bin/activate
source "$ROOT_DIR/benchmark/model_suites.sh"

if [[ ! -f ".env" ]]; then
  echo "Missing .env"; exit 1
fi
vulnbench_require_openrouter_auth

LOGDIR="$ROOT_DIR/results/logs"
mkdir -p "$LOGDIR"

models=("${VULNBENCH_LATEST_MODELS[@]}")

run_model() {
  local model="$1"
  local safe_name="${model#openrouter/}"
  safe_name="${safe_name//\//_}"
  local outfile="results/full_${safe_name}.json"
  local logfile="$LOGDIR/full_${safe_name}.log"

  # Skip if already completed with 1650 instances
  if [[ -f "$outfile" ]] && grep -q '"total_instances": 1650' "$outfile" 2>/dev/null; then
    echo "[SKIP] $model (already done)"
    return 0
  fi

  echo "[START] $model"

  if python -m benchmark.run_eval \
    --benchmark data/benchmark/vulnbench_full.json \
    --model "$model" \
    --include-source \
    --file-hint-mode description \
    --output "$outfile" \
    > "$logfile" 2>&1; then
    echo "[DONE] $model"
  else
    echo "[FAIL] $model (see $logfile)"
  fi
}

export -f run_model
export LOGDIR

echo "=== VulnBench Full (1,650 instances) — single pass, $MAX_PARALLEL parallel ==="
echo

active_pids=()

for model in "${models[@]}"; do
  while (( ${#active_pids[@]} >= MAX_PARALLEL )); do
    for i in "${!active_pids[@]}"; do
      if ! kill -0 "${active_pids[$i]}" 2>/dev/null; then
        wait "${active_pids[$i]}" || true
        unset 'active_pids[$i]'
        active_pids=("${active_pids[@]}")
        break
      fi
    done
    sleep 1
  done

  run_model "$model" &
  active_pids+=($!)
done

for pid in "${active_pids[@]}"; do
  wait "$pid" || true
done

echo
echo "=== All models complete ==="
