#!/usr/bin/env bash
# VulnBench v3: curated-200 suite, 3 independent runs per model, Protocol v2
# harness (16k escalating budget, pinned cross-vendor judge panel with
# adjudicated ties, self-judging exclusion). Results land in results/v3/.
set -euo pipefail

MAX_PARALLEL="${VULNBENCH_MAX_PARALLEL:-10}"
# Per-model wall-clock guard. Protocol v2's 16k reasoning budgets run
# ~50-140s/instance, so 600 instances can legitimately take ~20h+ for slow
# models; 12h (the old default) killed healthy first-wave runs mid-flight.
MODEL_TIMEOUT_SECONDS="${VULNBENCH_MODEL_TIMEOUT_SECONDS:-129600}"
# Full-suite estimate is ~$1,700; refuse to start a run that will 402 midway.
MIN_CREDITS="${VULNBENCH_MIN_CREDITS:-1700}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ ! -d ".venv" ]]; then
  echo "Missing .venv in $ROOT_DIR" >&2
  exit 1
fi
source .venv/bin/activate
source "$ROOT_DIR/benchmark/model_suites.sh"

if [[ ! -f ".env" ]]; then
  echo "Missing .env with OPENROUTER_API_KEY" >&2
  exit 1
fi
vulnbench_require_openrouter_auth
vulnbench_require_credits "$MIN_CREDITS"

models=("${VULNBENCH_LATEST_MODELS[@]}")

OUTDIR="$ROOT_DIR/results/v3"
LOGDIR="$OUTDIR/logs"
mkdir -p "$LOGDIR"

run_model() {
  local model="$1"
  local safe_name="${model#openrouter/}"
  safe_name="${safe_name//\//_}"
  local outfile="$OUTDIR/mean3_${safe_name}.json"
  local logfile="$LOGDIR/${safe_name}.log"

  # Completed v3 rows are validated by run_best_of_n's own config check on
  # resume; a finished summary file means all 3 runs completed under this
  # protocol.
  if [[ -f "$outfile" ]] && grep -q '"across_runs"' "$outfile" 2>/dev/null; then
    echo "[SKIP] $model (v3 summary already present)"
    return 0
  fi

  echo "[START] $model → $logfile"

  # Ride out multi-minute local network/DNS outages: 10 attempts with a 10s
  # base and 90s cap ≈ 10+ min of coverage. Connection errors cost no tokens,
  # so extra attempts are free insurance; genuine model failures still record
  # as artifact rows. Any outage longer than this aborts the model, but its
  # checkpoint is preserved and the supervisor loop re-runs it.
  # 600s per-request timeout: fast models never approach it, but slow
  # reasoning models (e.g. some Moonshot endpoints average ~9 min/patch)
  # succeed on the first attempt instead of hitting the old 300s cap and
  # triggering kill/retry storms that leak child-process semaphores and
  # abort the whole model. Uniform for every model — no special-casing.
  local command=(python -m benchmark.run_best_of_n
    --benchmark data/benchmark/vulnbench_200.json
    --model "$model"
    --runs 3
    --completion-timeout 600
    --adapter-max-attempts 10
    --adapter-retry-backoff-base-s 10
    --adapter-retry-backoff-max-s 90
    --include-source
    --file-hint-mode description
    --output "$outfile")

  "${command[@]}" > "$logfile" 2>&1 &
  local cmd_pid=$!
  local start_ts
  start_ts="$(date +%s)"
  local rc=0

  while kill -0 "$cmd_pid" 2>/dev/null; do
    if (( $(date +%s) - start_ts > MODEL_TIMEOUT_SECONDS )); then
      echo "[TIMEOUT] $model exceeded ${MODEL_TIMEOUT_SECONDS}s" >> "$logfile"
      kill -TERM "$cmd_pid" 2>/dev/null || true
      sleep 10
      kill -KILL "$cmd_pid" 2>/dev/null || true
      wait "$cmd_pid" 2>/dev/null || true
      rc=124
      break
    fi
    sleep 5
  done

  if (( rc == 0 )); then
    if wait "$cmd_pid"; then rc=0; else rc=$?; fi
  fi

  if (( rc == 0 )); then
    echo "[DONE] $model ✓"
  else
    echo "[FAIL] $model ✗  (see $logfile)"
  fi
}

export -f run_model
export OUTDIR LOGDIR MODEL_TIMEOUT_SECONDS

echo "VulnBench v3: ${#models[@]} models, $MAX_PARALLEL in parallel → $OUTDIR"
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
echo "Suite complete. Building analysis + leaderboard…"
python -m benchmark.model_report \
  --benchmark data/benchmark/vulnbench_200.json \
  --reports "$OUTDIR"/run?_openrouter_*.json \
  --output-dir "$OUTDIR/analysis"
echo "Leaderboard: $OUTDIR/analysis/README.md"
