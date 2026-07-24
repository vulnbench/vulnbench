#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

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

MODEL="${VULNBENCH_EFFORT_MODEL:-openrouter/openai/gpt-5.5}"
BENCHMARK_PATH="${VULNBENCH_EFFORT_BENCHMARK_PATH:-data/benchmark/vulnbench_200.json}"
OUTPUT_DIR="${VULNBENCH_EFFORT_OUTPUT_DIR:-results/effort}"
RUNS="${VULNBENCH_EFFORT_RUNS:-3}"
MAX_TOKENS="${VULNBENCH_EFFORT_MAX_TOKENS:-4096}"
ADAPTER_MAX_ATTEMPTS="${VULNBENCH_ADAPTER_MAX_ATTEMPTS:-3}"
BACKOFF_BASE_S="${VULNBENCH_ADAPTER_BACKOFF_BASE_S:-2.0}"
BACKOFF_MAX_S="${VULNBENCH_ADAPTER_BACKOFF_MAX_S:-60.0}"
BACKOFF_JITTER_S="${VULNBENCH_ADAPTER_BACKOFF_JITTER_S:-0.5}"
EFFORT_LEVELS="${VULNBENCH_EFFORT_LEVELS:-none minimal low medium high}"
JUDGE_MODELS="${VULNBENCH_JUDGE_MODELS:-openrouter/anthropic/claude-opus-4.8 openrouter/openai/gpt-5.5}"
read -r -a judge_models <<< "$JUDGE_MODELS"

mkdir -p "$OUTPUT_DIR" "$ROOT_DIR/results/logs"

safe_model="${MODEL#openrouter/}"
safe_model="${safe_model//\//_}"
safe_model="${safe_model//:/_}"

echo "=== VulnBench GPT-5.5 effort sweep ==="
echo "model=$MODEL"
echo "benchmark=$BENCHMARK_PATH"
echo "runs=$RUNS"
echo "efforts=$EFFORT_LEVELS"
echo "adapter_max_attempts=$ADAPTER_MAX_ATTEMPTS"
echo "judges=${judge_models[*]}"
echo

for effort in $EFFORT_LEVELS; do
  outfile="$OUTPUT_DIR/best${RUNS}_${safe_model}_effort-${effort}.json"
  logfile="$ROOT_DIR/results/logs/effort_${safe_model}_${effort}.log"

  echo "[START] effort=$effort output=$outfile log=$logfile"
  python -m benchmark.run_best_of_n \
    --benchmark "$BENCHMARK_PATH" \
    --model "$MODEL" \
    --runs "$RUNS" \
    --max-tokens "$MAX_TOKENS" \
    --reasoning-effort "$effort" \
    --adapter-max-attempts "$ADAPTER_MAX_ATTEMPTS" \
    --adapter-retry-backoff-base-s "$BACKOFF_BASE_S" \
    --adapter-retry-backoff-max-s "$BACKOFF_MAX_S" \
    --adapter-retry-backoff-jitter-s "$BACKOFF_JITTER_S" \
    --include-source \
    --file-hint-mode description \
    --judge-models "${judge_models[@]}" \
    --output "$outfile" > "$logfile" 2>&1
  echo "[DONE] effort=$effort"
done

echo
echo "=== Effort sweep complete ==="
