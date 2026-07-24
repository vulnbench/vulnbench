#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

set -a
source .env
set +a

mkdir -p results/logs

MODEL_TIMEOUT_SECONDS=${VULNBENCH_PARALLEL_RUN_TIMEOUT_SECONDS:-43200}

jobs=(
  "2|openrouter/z-ai/glm-5.1"
  "3|openrouter/z-ai/glm-5.1"
  "2|openrouter/moonshotai/kimi-k2.6"
  "3|openrouter/moonshotai/kimi-k2.6"
  "2|openrouter/x-ai/grok-build-0.1"
  "3|openrouter/x-ai/grok-build-0.1"
  "2|openrouter/qwen/qwen3.7-max"
  "3|openrouter/qwen/qwen3.7-max"
  "2|openrouter/qwen/qwen3.7-plus"
  "3|openrouter/qwen/qwen3.7-plus"
)

models=(
  "openrouter/z-ai/glm-5.1"
  "openrouter/moonshotai/kimi-k2.6"
  "openrouter/x-ai/grok-build-0.1"
  "openrouter/qwen/qwen3.7-max"
  "openrouter/qwen/qwen3.7-plus"
)

is_complete() {
  local output="$1"
  [[ -f "$output" ]] && .venv/bin/python - "$output" <<'PY'
import json
import sys
from pathlib import Path

p = Path(sys.argv[1])
try:
    d = json.loads(p.read_text())
    sys.exit(0 if d.get("aggregate", {}).get("total_instances") == 200 else 1)
except Exception:
    sys.exit(1)
PY
}

pids=()
for item in "${jobs[@]}"; do
  run="${item%%|*}"
  model="${item#*|}"
  safe=${model//\//_}
  safe=${safe//:/_}
  output="results/run${run}_${safe}.json"
  logfile="results/logs/remaining_best3_run${run}_${safe}.log"

  if is_complete "$output"; then
    echo "[SKIP] run${run} ${model} already complete"
    continue
  fi

  echo "[START] run${run} ${model} output=${output} log=${logfile}"
  (
    start=$(date +%s)
    .venv/bin/python -m benchmark.run_eval \
      --benchmark data/benchmark/vulnbench_200.json \
      --model "$model" \
      --include-source \
      --file-hint-mode description \
      --resume \
      --output "$output" > "$logfile" 2>&1 &
    child=$!

    while kill -0 "$child" 2>/dev/null; do
      now=$(date +%s)
      if (( now - start > MODEL_TIMEOUT_SECONDS )); then
        echo "[TIMEOUT] run${run} ${model} exceeded ${MODEL_TIMEOUT_SECONDS}s; terminating pid=${child}" >> "$logfile"
        kill -TERM "$child" 2>/dev/null || true
        sleep 10
        kill -KILL "$child" 2>/dev/null || true
        wait "$child" || true
        exit 124
      fi
      sleep 30
    done

    wait "$child"
    rc=$?
    echo "[EXIT] run${run} ${model} rc=${rc}" >> "$logfile"
    exit "$rc"
  ) &
  pids+=("$!")
done

batch_rc=0
for pid in "${pids[@]}"; do
  if ! wait "$pid"; then
    batch_rc=1
  fi
done

.venv/bin/python - <<'PY'
import json
from pathlib import Path

models = [
    "openrouter/z-ai/glm-5.1",
    "openrouter/moonshotai/kimi-k2.6",
    "openrouter/x-ai/grok-build-0.1",
    "openrouter/qwen/qwen3.7-max",
    "openrouter/qwen/qwen3.7-plus",
]

for model in models:
    safe = model.replace("/", "_").replace(":", "_")
    safe_short = model.removeprefix("openrouter/").replace("/", "_").replace(":", "_")
    reports = []
    missing = []
    for run in range(1, 4):
        path = Path(f"results/run{run}_{safe}.json")
        if not path.exists():
            missing.append(str(path))
            continue
        data = json.loads(path.read_text())
        if data.get("aggregate", {}).get("total_instances") != 200:
            missing.append(str(path))
            continue
        reports.append((run, data))

    if missing:
        print(f"[BEST3-SKIP] {model} missing/incomplete: {', '.join(missing)}")
        continue

    best_run, best = max(
        reports,
        key=lambda item: (
            item[1]["aggregate"]["pass_rate"],
            item[1]["aggregate"]["mean_score"],
        ),
    )
    best.setdefault("metadata", {})
    best["metadata"]["best_of_n"] = 3
    best["metadata"]["best_run"] = best_run
    best["metadata"]["all_runs"] = [
        {
            "run": run,
            "pass_rate": data["aggregate"]["pass_rate"],
            "mean_score": data["aggregate"]["mean_score"],
            "total_cost_usd": data["aggregate"].get("total_cost_usd", 0),
        }
        for run, data in reports
    ]
    out = Path(f"results/best3_{safe_short}.json")
    out.write_text(json.dumps(best, indent=2))
    agg = best["aggregate"]
    print(
        f"[BEST3] {model} best_run={best_run} "
        f"passed={agg['total_passed']}/200 mean={agg['mean_score']:.3f} -> {out}"
    )
PY

echo "[DONE] remaining best3 batch status=${batch_rc}"
exit "$batch_rc"
