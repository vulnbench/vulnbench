#!/usr/bin/env bash
set -euo pipefail

MAX_PARALLEL=10

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

source .venv/bin/activate

if [[ ! -f ".env" ]]; then
  echo "Missing .env"; exit 1
fi

LOGDIR="$ROOT_DIR/results/logs"
mkdir -p "$LOGDIR"

run_single() {
  local model="$1"
  local run_idx="$2"
  local safe_name="${model//\//_}"
  local outfile="results/run${run_idx}_${safe_name}.json"
  local logfile="$LOGDIR/resume_${safe_name}_run${run_idx}.log"

  echo "[RUN] $model run $run_idx"

  if python -m benchmark.run_eval \
    --benchmark data/benchmark/vulnbench_200.json \
    --model "$model" \
    --include-source \
    --file-hint-mode description \
    --output "$outfile" \
    > "$logfile" 2>&1; then
    echo "[DONE] $model run $run_idx"
  else
    echo "[FAIL] $model run $run_idx (see $logfile)"
  fi
}

recompute_best() {
  local model="$1"
  local safe_name="${model//\//_}"
  local short_name="${model#openrouter/}"
  short_name="${short_name//\//_}"

  python3 - "$safe_name" "$model" "$short_name" << 'PYEOF'
import json, sys
from pathlib import Path
from benchmark.eval_models import EvalReport

safe, model, short = sys.argv[1], sys.argv[2], sys.argv[3]

runs = []
for i in [1, 2, 3]:
    p = Path(f"results/run{i}_{safe}.json")
    if p.exists():
        d = json.loads(p.read_text())
        report = EvalReport(**d)
        agg = report.aggregate
        if agg.total_cost_usd > 0 or agg.total_passed > 0:
            runs.append((i, report))

if not runs:
    print(f"  [SKIP] No valid runs for {model}")
    sys.exit(0)

best_idx, best_report = max(runs, key=lambda x: (x[1].aggregate.pass_rate, x[1].aggregate.mean_score))
best_report.metadata["best_of_n"] = 3
best_report.metadata["best_run"] = best_idx
best_report.metadata["all_runs"] = []
for i in [1, 2, 3]:
    p = Path(f"results/run{i}_{safe}.json")
    if p.exists():
        d = json.loads(p.read_text())
        r = EvalReport(**d)
        best_report.metadata["all_runs"].append({
            "run": i,
            "pass_rate": r.aggregate.pass_rate,
            "mean_score": r.aggregate.mean_score,
            "total_cost_usd": r.aggregate.total_cost_usd,
        })

out = Path(f"results/best3_{short}.json")
out.write_text(json.dumps(best_report.model_dump(), indent=2))
print(f"  [BEST] {model}: run {best_idx} pass_rate={best_report.aggregate.pass_rate:.1%}")
PYEOF
}

export -f run_single
export LOGDIR

# Each line: model|run_indices
jobs=(
  "openrouter/anthropic/claude-opus-4.6|2 3"
  "openrouter/anthropic/claude-sonnet-4.6|2 3"
  "openrouter/openai/gpt-5.2|2 3"
  "openrouter/openai/gpt-5.3-codex|2 3"
  "openrouter/deepseek/deepseek-v3.2|2 3"
  "openrouter/x-ai/grok-4.1-fast|2 3"
  "openrouter/moonshotai/kimi-k2.5|2 3"
  "openrouter/minimax/minimax-m2.5|2 3"
  "openrouter/minimax/minimax-m2.7|2 3"
  "openrouter/google/gemini-3-flash-preview|3"
  "openrouter/stepfun/step-3.5-flash:free|1 2 3"
)

models_to_recompute=()

echo "=== Resuming failed runs (parallel=$MAX_PARALLEL) ==="
echo

active_pids=()

for entry in "${jobs[@]}"; do
  model="${entry%%|*}"
  runs="${entry##*|}"
  models_to_recompute+=("$model")

  for run_idx in $runs; do
    # Wait if at parallelism limit
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

    run_single "$model" "$run_idx" &
    active_pids+=($!)
  done
done

# Wait for all
for pid in "${active_pids[@]}"; do
  wait "$pid" || true
done

echo
echo "=== All runs complete. Recomputing best-of-3... ==="
echo

for model in "${models_to_recompute[@]}"; do
  recompute_best "$model"
done

echo
echo "=== Done ==="
