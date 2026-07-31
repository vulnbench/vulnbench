#!/usr/bin/env bash
set -u

set -a
source .env
set +a

mkdir -p results/logs

MODEL_TIMEOUT_SECONDS=${VULNBENCH_PARALLEL_RUN_TIMEOUT_SECONDS:-43200}

jobs=(
  "1|openrouter/z-ai/glm-5.1"
  "1|openrouter/moonshotai/kimi-k2.6"
  "1|openrouter/x-ai/grok-build-0.1"
  "1|openrouter/qwen/qwen3.7-max"
  "1|openrouter/qwen/qwen3.7-plus"
  "2|openrouter/deepseek/deepseek-v4-flash"
  "3|openrouter/deepseek/deepseek-v4-flash"
)

pids=()
for item in "${jobs[@]}"; do
  run="${item%%|*}"
  model="${item#*|}"
  safe=${model//\//_}
  safe=${safe//:/_}
  output="results/run${run}_${safe}.json"
  logfile="results/logs/parallel_run${run}_${safe}.log"

  if [ -f "$output" ] && .venv/bin/python - "$output" <<'PY'
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
  then
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

echo "[DONE] parallel missing latest batch status=${batch_rc}"
exit "$batch_rc"
