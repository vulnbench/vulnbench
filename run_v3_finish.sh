#!/usr/bin/env bash
# Serial finisher for the remaining v3 MAIN models. Runs ONE model at a time,
# ONE completion at a time, with the child-process timeout (reliably killable).
# Serial execution avoids the shared litellm/httpx connection-pool lock that
# deadlocks the parallel in-process/thread-timeout modes, and one-child-at-a-
# time keeps semaphore accumulation far below the wedge threshold. Slower but
# reliable. Prioritized so the models we care about land first.
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
source .venv/bin/activate
# In-process thread-timeout: the process-timeout child-spawn path degraded to
# ~5 instances/day on the long-lived finisher (each call re-imports litellm in
# a fresh child). Serial execution means only ONE completion runs at a time,
# so the shared connection-pool lock that deadlocked the PARALLEL thread-timeout
# mode is never contended here. Direct API calls return in ~12s, so this is the
# fast, reliable path for the remaining models.
export VULNBENCH_INPROCESS_LLM=1

OUTDIR="$ROOT_DIR/results/v3"
LOGDIR="$OUTDIR/logs"
mkdir -p "$LOGDIR"

# Priority order: Anthropic flagships first, then the rest.
MODELS=(
  openrouter/anthropic/claude-opus-5
  openrouter/anthropic/claude-fable-5
  openrouter/deepseek/deepseek-v4-pro
  openrouter/z-ai/glm-5.2
  openrouter/z-ai/glm-5.1
  openrouter/qwen/qwen3.7-plus
  openrouter/stepfun/step-3.7-flash
  openrouter/tencent/hy3
)

for model in "${MODELS[@]}"; do
  safe="${model#openrouter/}"; safe="${safe//\//_}"
  outfile="$OUTDIR/mean3_${safe}.json"
  logfile="$LOGDIR/${safe}.log"
  if [[ -f "$outfile" ]] && grep -q '"across_runs"' "$outfile" 2>/dev/null; then
    echo "[SKIP] $model (already complete)"; continue
  fi
  echo "[START-FINISH] $model → $logfile"
  "$ROOT_DIR/.venv/bin/python" -m benchmark.run_best_of_n \
    --benchmark data/benchmark/vulnbench_200.json \
    --model "$model" --runs 3 \
    --completion-timeout 600 \
    --no-adapter-process-timeout \
    --adapter-max-attempts 6 --adapter-retry-backoff-base-s 8 --adapter-retry-backoff-max-s 60 \
    --include-source --file-hint-mode description \
    --output "$outfile" >> "$logfile" 2>&1 \
    && echo "[DONE-FINISH] $model ✓" || echo "[FAIL-FINISH] $model ✗ (see $logfile)"
done
echo "[FINISH] serial finisher complete"
