#!/usr/bin/env bash
# VulnBench v3 — latency-outlier models (VULNBENCH_SLOW_MODELS), run SEPARATELY
# from the main suite so they do not block the leaderboard. Same Protocol v2
# harness (best-of-3, in-process LLM, pinned judge panel), but low parallelism
# and a patient timeout because these models run 5-16 min per patch. Results
# land in results/v3 alongside the main suite and are folded in when complete.
set -uo pipefail

MAX_PARALLEL="${VULNBENCH_SLOW_PARALLEL:-4}"
MODEL_TIMEOUT_SECONDS="${VULNBENCH_MODEL_TIMEOUT_SECONDS:-864000}"  # 10 days
MIN_CREDITS="${VULNBENCH_MIN_CREDITS:-100}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
source .venv/bin/activate
source "$ROOT_DIR/benchmark/model_suites.sh"
export VULNBENCH_INPROCESS_LLM=1

vulnbench_require_openrouter_auth
vulnbench_require_credits "$MIN_CREDITS"

models=("${VULNBENCH_SLOW_MODELS[@]}")
OUTDIR="$ROOT_DIR/results/v3"
LOGDIR="$OUTDIR/logs"
mkdir -p "$LOGDIR"

run_model() {
  local model="$1"
  local safe_name="${model#openrouter/}"; safe_name="${safe_name//\//_}"
  local outfile="$OUTDIR/mean3_${safe_name}.json"
  local logfile="$LOGDIR/${safe_name}.log"
  if [[ -f "$outfile" ]] && grep -q '"across_runs"' "$outfile" 2>/dev/null; then
    echo "[SKIP] $model (already complete)"; return 0
  fi
  echo "[START-SLOW] $model → $logfile"
  python -m benchmark.run_best_of_n \
    --benchmark data/benchmark/vulnbench_200.json \
    --model "$model" --runs 3 \
    --completion-timeout 1200 \
    --adapter-max-attempts 10 --adapter-retry-backoff-base-s 10 --adapter-retry-backoff-max-s 90 \
    --include-source --file-hint-mode description \
    --output "$outfile" >> "$logfile" 2>&1 \
    && echo "[DONE-SLOW] $model ✓" || echo "[FAIL-SLOW] $model ✗ (see $logfile)"
}
export -f run_model
export OUTDIR LOGDIR

echo "VulnBench v3 SLOW suite: ${#models[@]} models, $MAX_PARALLEL parallel → $OUTDIR"
active_pids=()
for model in "${models[@]}"; do
  while (( ${#active_pids[@]} >= MAX_PARALLEL )); do
    for i in "${!active_pids[@]}"; do
      kill -0 "${active_pids[$i]}" 2>/dev/null || { wait "${active_pids[$i]}" 2>/dev/null || true; unset 'active_pids[$i]'; active_pids=("${active_pids[@]}"); break; }
    done
    sleep 5
  done
  run_model "$model" & active_pids+=($!)
done
for pid in "${active_pids[@]}"; do wait "$pid" 2>/dev/null || true; done
echo "[SLOW] all slow models finished"
