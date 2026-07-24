#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'EOF'
Run the impacted-model VulnBench retry rerun.

Environment overrides:
  VULNBENCH_IMPACTED_MODELS           Space-separated model IDs to run
  VULNBENCH_IMPACTED_MAX_PARALLEL     Parallel models (default: 3)
  VULNBENCH_IMPACTED_RUNS             Best-of-N runs per model (default: 3)
  VULNBENCH_JUDGE_MODELS              Space-separated judge model IDs
  VULNBENCH_IMPACTED_OUTPUT_DIR       Output directory
  VULNBENCH_REASONING_EXCLUDE         Exclude reasoning from responses (default: false)
  VULNBENCH_REASONING_MAX_TOKENS      Optional OpenRouter reasoning.max_tokens
EOF
  exit 0
fi

if [[ ! -d ".venv" ]]; then
  echo "Missing .venv in $ROOT_DIR"
  echo "Create it first, then install requirements."
  exit 1
fi

if [[ ! -f ".env" ]]; then
  echo "Missing .env in $ROOT_DIR"
  echo "Add OPENROUTER_API_KEY before running."
  exit 1
fi

source .venv/bin/activate
set -a
source .env
set +a
source "$ROOT_DIR/benchmark/model_suites.sh"
vulnbench_require_openrouter_auth

BENCHMARK_PATH="${VULNBENCH_IMPACTED_BENCHMARK_PATH:-data/benchmark/vulnbench_200.json}"
OUTPUT_DIR="${VULNBENCH_IMPACTED_OUTPUT_DIR:-results/rerun_fixes_multijudge}"
LOGDIR="${VULNBENCH_IMPACTED_LOGDIR:-results/logs/rerun_fixes_multijudge}"
RUNS="${VULNBENCH_IMPACTED_RUNS:-3}"
MAX_PARALLEL="${VULNBENCH_IMPACTED_MAX_PARALLEL:-3}"
MAX_TOKENS="${VULNBENCH_IMPACTED_MAX_TOKENS:-4096}"
ADAPTER_MAX_ATTEMPTS="${VULNBENCH_ADAPTER_MAX_ATTEMPTS:-3}"
BACKOFF_BASE_S="${VULNBENCH_ADAPTER_BACKOFF_BASE_S:-2.0}"
BACKOFF_MAX_S="${VULNBENCH_ADAPTER_BACKOFF_MAX_S:-60.0}"
BACKOFF_JITTER_S="${VULNBENCH_ADAPTER_BACKOFF_JITTER_S:-0.5}"
MODEL_TIMEOUT_SECONDS="${VULNBENCH_IMPACTED_MODEL_TIMEOUT_SECONDS:-86400}"
JUDGE_MODELS="${VULNBENCH_JUDGE_MODELS:-openrouter/anthropic/claude-opus-4.8 openrouter/openai/gpt-5.5}"
REASONING_EXCLUDE="${VULNBENCH_REASONING_EXCLUDE:-false}"
REASONING_MAX_TOKENS="${VULNBENCH_REASONING_MAX_TOKENS:-}"
read -r -a judge_models <<< "$JUDGE_MODELS"

default_models=(
  openrouter/stepfun/step-3.5-flash
  openrouter/qwen/qwen3.5-27b
  openrouter/qwen/qwen3.5-35b-a3b
  openrouter/stepfun/step-3.7-flash
  openrouter/deepseek/deepseek-v3.2
  openrouter/moonshotai/kimi-k2.7-code
  openrouter/moonshotai/kimi-k2.6
  openrouter/z-ai/glm-5.1
  openrouter/openai/gpt-5.5
  openrouter/minimax/minimax-m2.7
  openrouter/moonshotai/kimi-k2.5
  openrouter/openai/gpt-5.2
  openrouter/minimax/minimax-m3
  openrouter/google/gemini-3.1-pro-preview
  openrouter/anthropic/claude-fable-5
  openrouter/z-ai/glm-5
  openrouter/anthropic/claude-opus-4.6
  openrouter/google/gemini-3-flash-preview
  openrouter/x-ai/grok-4.1-fast
  openrouter/minimax/minimax-m2.5
  openrouter/qwen/qwen3.7-max
  openrouter/openai/gpt-5.3-codex
  openrouter/qwen/qwen3.7-plus
  openrouter/deepseek/deepseek-v4-pro
  openrouter/anthropic/claude-sonnet-4.6
)

if [[ -n "${VULNBENCH_IMPACTED_MODELS:-}" ]]; then
  read -r -a models <<< "$VULNBENCH_IMPACTED_MODELS"
else
  models=("${default_models[@]}")
fi

mkdir -p "$OUTPUT_DIR" "$LOGDIR"

is_complete() {
  local output="$1"
  [[ -f "$output" ]] && .venv/bin/python - "$output" "$BENCHMARK_PATH" <<'PY'
import json
import sys
from pathlib import Path

output = Path(sys.argv[1])
benchmark = Path(sys.argv[2])

try:
    report = json.loads(output.read_text())
    bench = json.loads(benchmark.read_text())
except Exception:
    sys.exit(1)

expected = len(bench.get("instances", []))
metadata = report.get("metadata", {})
aggregate = report.get("aggregate", {})

complete = (
    aggregate.get("total_instances") == expected
    and metadata.get("adapter_max_attempts", 0) >= 3
    and metadata.get("retry_empty_responses") is True
    and len(metadata.get("judge_models", [])) >= 2
)
sys.exit(0 if complete else 1)
PY
}

run_model() {
  local model="$1"
  local safe_name="${model#openrouter/}"
  safe_name="${safe_name//\//_}"
  safe_name="${safe_name//:/_}"
  local outfile="$OUTPUT_DIR/best${RUNS}_${safe_name}.json"
  local logfile="$LOGDIR/${safe_name}.log"

  if is_complete "$outfile"; then
    echo "[SKIP] $model already complete with retry metadata"
    return 0
  fi

  echo "[START] $model output=$outfile log=$logfile"
  local start
  start="$(date +%s)"

  command=(python -m benchmark.run_best_of_n
    --benchmark "$BENCHMARK_PATH" \
    --model "$model" \
    --runs "$RUNS" \
    --max-tokens "$MAX_TOKENS" \
    --adapter-max-attempts "$ADAPTER_MAX_ATTEMPTS" \
    --adapter-retry-backoff-base-s "$BACKOFF_BASE_S" \
    --adapter-retry-backoff-max-s "$BACKOFF_MAX_S" \
    --adapter-retry-backoff-jitter-s "$BACKOFF_JITTER_S" \
    --include-source \
    --file-hint-mode description \
    --judge-models "${judge_models[@]}" \
    --output "$outfile")
  if [[ "$REASONING_EXCLUDE" == "true" ]]; then
    command+=(--reasoning-exclude)
  fi
  if [[ -n "$REASONING_MAX_TOKENS" ]]; then
    command+=(--reasoning-max-tokens "$REASONING_MAX_TOKENS")
  fi
  "${command[@]}" > "$logfile" 2>&1 &
  local child=$!

  while kill -0 "$child" 2>/dev/null; do
    if (( $(date +%s) - start > MODEL_TIMEOUT_SECONDS )); then
      echo "[TIMEOUT] $model exceeded ${MODEL_TIMEOUT_SECONDS}s; terminating pid=${child}" >> "$logfile"
      kill -TERM "$child" 2>/dev/null || true
      sleep 10
      kill -KILL "$child" 2>/dev/null || true
      wait "$child" 2>/dev/null || true
      return 124
    fi
    sleep 30
  done

  wait "$child"
  local rc=$?
  echo "[EXIT] $model rc=${rc}" >> "$logfile"
  if (( rc == 0 )); then
    echo "[DONE] $model"
  else
    echo "[FAIL] $model rc=$rc"
  fi
  return "$rc"
}

echo "=== VulnBench impacted-model retry rerun ==="
echo "benchmark=$BENCHMARK_PATH"
echo "output_dir=$OUTPUT_DIR"
echo "models=${#models[@]} runs=$RUNS max_parallel=$MAX_PARALLEL"
echo "adapter_max_attempts=$ADAPTER_MAX_ATTEMPTS retry_empty=true"
echo "reasoning_exclude=$REASONING_EXCLUDE reasoning_max_tokens=${REASONING_MAX_TOKENS:-unset}"
echo "judges=${judge_models[*]}"
echo

pids=()
batch_rc=0

for model in "${models[@]}"; do
  while (( ${#pids[@]} >= MAX_PARALLEL )); do
    for i in "${!pids[@]}"; do
      if ! kill -0 "${pids[$i]}" 2>/dev/null; then
        wait "${pids[$i]}" || batch_rc=1
        unset 'pids[$i]'
        pids=("${pids[@]}")
        break
      fi
    done
    sleep 1
  done

  run_model "$model" &
  pids+=("$!")
done

for pid in "${pids[@]}"; do
  wait "$pid" || batch_rc=1
done

echo
echo "[DONE] impacted retry rerun status=${batch_rc}"
exit "$batch_rc"
