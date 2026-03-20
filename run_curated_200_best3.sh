#!/usr/bin/env bash
set -euo pipefail

MAX_PARALLEL=10

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ ! -d ".venv" ]]; then
  echo "Missing .venv in $ROOT_DIR"
  echo "Create it first, then install requirements."
  exit 1
fi

source .venv/bin/activate

if [[ ! -f ".env" ]]; then
  echo "Missing .env in $ROOT_DIR"
  echo "Add OPENROUTER_API_KEY before running."
  exit 1
fi

models=(
  openrouter/openai/gpt-5-mini
  openrouter/openai/gpt-5.2
  openrouter/openai/gpt-5.3-codex
  openrouter/openai/gpt-5.4
  openrouter/x-ai/grok-4.1-fast
  openrouter/minimax/minimax-m2.5
  openrouter/minimax/minimax-m2.7
  openrouter/google/gemini-3-flash-preview
  openrouter/deepseek/deepseek-v3.2
  openrouter/moonshotai/kimi-k2.5
  openrouter/anthropic/claude-opus-4.6
  openrouter/anthropic/claude-sonnet-4.6
  openrouter/anthropic/claude-haiku-4.5
  openrouter/stepfun/step-3.5-flash:free


  openrouter/google/gemini-3.1-pro-preview
  openrouter/z-ai/glm-5
)

LOGDIR="$ROOT_DIR/results/logs"
mkdir -p "$LOGDIR"

run_model() {
  local model="$1"
  local safe_name="${model#openrouter/}"
  safe_name="${safe_name//\//_}"
  local outfile="results/best3_${safe_name}.json"
  local logfile="$LOGDIR/${safe_name}.log"

  # Skip if already completed with 200 instances
  if [[ -f "$outfile" ]] && grep -q '"total_instances": 200' "$outfile" 2>/dev/null; then
    echo "[SKIP] $model (already 200)"
    return 0
  fi

  echo "[START] $model → $logfile"

  if python -m benchmark.run_best_of_n \
    --benchmark data/benchmark/vulnbench_200.json \
    --model "$model" \
    --runs 3 \
    --include-source \
    --file-hint-mode description \
    --output "$outfile" \
    > "$logfile" 2>&1; then
    echo "[DONE] $model ✓"
  else
    echo "[FAIL] $model ✗  (see $logfile)"
  fi
}

export -f run_model
export LOGDIR

echo "Running ${#models[@]} models, $MAX_PARALLEL in parallel"
echo "Logs: $LOGDIR"
echo

# Run models in parallel, MAX_PARALLEL at a time
active_pids=()

for model in "${models[@]}"; do
  # Wait if we've hit the parallelism limit
  while (( ${#active_pids[@]} >= MAX_PARALLEL )); do
    # Wait for any one child to finish
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

# Wait for all remaining jobs
for pid in "${active_pids[@]}"; do
  wait "$pid" || true
done

echo
echo "=== All models complete ==="
