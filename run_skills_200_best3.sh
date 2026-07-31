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

models=("${VULNBENCH_LATEST_MODELS[@]}")

LOGDIR="$ROOT_DIR/results/skills/logs"
mkdir -p "$LOGDIR"

run_single() {
  local model="$1"
  local run_idx="$2"
  local safe_name="${model#openrouter/}"
  safe_name="${safe_name//\//_}"
  local outfile="results/skills/run${run_idx}_${safe_name}.json"
  local logfile="$LOGDIR/run${run_idx}_${safe_name}.log"

  # Skip if already completed
  if [[ -f "$outfile" ]] && grep -q '"total_instances": 200' "$outfile" 2>/dev/null; then
    echo "[SKIP] $model run $run_idx"
    return 0
  fi

  echo "[RUN] $model run $run_idx"

  if python -m benchmark.run_eval_skills \
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
  local safe_name="${model#openrouter/}"
  safe_name="${safe_name//\//_}"

  python3 - "$safe_name" "$model" << 'PYEOF'
import json, sys
from pathlib import Path
from benchmark.eval_models import EvalReport

safe, model = sys.argv[1], sys.argv[2]

runs = []
for i in [1, 2, 3]:
    p = Path(f"results/skills/run{i}_{safe}.json")
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
    p = Path(f"results/skills/run{i}_{safe}.json")
    if p.exists():
        d = json.loads(p.read_text())
        r = EvalReport(**d)
        best_report.metadata["all_runs"].append({
            "run": i,
            "pass_rate": r.aggregate.pass_rate,
            "mean_score": r.aggregate.mean_score,
            "total_cost_usd": r.aggregate.total_cost_usd,
        })

out = Path(f"results/skills/best3_{safe}.json")
out.write_text(json.dumps(best_report.model_dump(), indent=2))
print(f"  [BEST] {model}: run {best_idx} pass_rate={best_report.aggregate.pass_rate:.1%}")
PYEOF
}

export -f run_single
export LOGDIR

echo "=== VulnBench-200 Skills — runs 2 & 3 (parallel=$MAX_PARALLEL) ==="
echo

# First rename existing run1 results from eval_ to run1_ format
for model in "${models[@]}"; do
  safe_name="${model#openrouter/}"
  safe_name="${safe_name//\//_}"
  old="results/skills/eval_${safe_name}.json"
  new="results/skills/run1_${safe_name}.json"
  if [[ -f "$old" ]] && [[ ! -f "$new" ]]; then
    cp "$old" "$new"
    echo "[COPY] $old → $new"
  fi
done

echo

active_pids=()

for model in "${models[@]}"; do
  for run_idx in 2 3; do
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

for pid in "${active_pids[@]}"; do
  wait "$pid" || true
done

echo
echo "=== All runs complete. Recomputing best-of-3... ==="
echo

for model in "${models[@]}"; do
  recompute_best "$model"
done

echo
echo "=== Done ==="
