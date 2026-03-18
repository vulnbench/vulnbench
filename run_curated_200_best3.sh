#!/usr/bin/env bash
set -euo pipefail

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
  openrouter/qwen/qwen3.5-35b-a3b
  openrouter/qwen/qwen3.5-27b
  openrouter/google/gemini-3.1-pro-preview
  openrouter/z-ai/glm-5
)

for model in "${models[@]}"; do
  safe_name="${model#openrouter/}"
  safe_name="${safe_name//\//_}"

  echo
  echo "=== Running curated 200 best-of-3 for: $model ==="

  python -m benchmark.run_best_of_n \
    --benchmark data/benchmark/vulnbench_200.json \
    --model "$model" \
    --runs 3 \
    --include-source \
    --file-hint-mode description \
    --output "results/best3_${safe_name}.json"
done
