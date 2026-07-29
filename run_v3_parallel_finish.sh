#!/usr/bin/env bash
# Parallel finisher for the last few v3 MAIN models, with a STALL WATCHDOG.
# Runs the models N-at-a-time in-process (fast, no child-spawn), and if the
# shared connection-pool lock deadlocks the whole batch (the known parallel
# failure mode — signalled by NO checkpoint write across ANY worker for
# STALL_SECONDS), it kills the batch and relaunches, resuming from checkpoints.
# Repeats until every target model has a mean3 summary. This trades a little
# babysitting for ~Nx the serial speed.
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
export VULNBENCH_INPROCESS_LLM=1

MAX_PARALLEL="${VULNBENCH_FINISH_PARALLEL:-4}"
STALL_SECONDS="${VULNBENCH_STALL_SECONDS:-480}"   # no write anywhere => deadlock
MAX_RESTARTS="${VULNBENCH_MAX_RESTARTS:-200}"

OUTDIR="$ROOT_DIR/results/v3"
LOGDIR="$OUTDIR/logs"
mkdir -p "$LOGDIR"

MODELS=(
  openrouter/z-ai/glm-5.2
  openrouter/z-ai/glm-5.1
  openrouter/qwen/qwen3.7-plus
  openrouter/stepfun/step-3.7-flash
  openrouter/tencent/hy3
)

pending_models() {
  for m in "${MODELS[@]}"; do
    local s="${m#openrouter/}"; s="${s//\//_}"
    if [[ -f "$OUTDIR/mean3_${s}.json" ]] && grep -q '"across_runs"' "$OUTDIR/mean3_${s}.json" 2>/dev/null; then
      continue
    fi
    echo "$m"
  done
}

launch_one() {
  local model="$1"
  local s="${model#openrouter/}"; s="${s//\//_}"
  "$ROOT_DIR/.venv/bin/python" -m benchmark.run_best_of_n \
    --benchmark data/benchmark/vulnbench_200.json \
    --model "$model" --runs 3 \
    --completion-timeout 600 --no-adapter-process-timeout \
    --adapter-max-attempts 6 --adapter-retry-backoff-base-s 8 --adapter-retry-backoff-max-s 60 \
    --include-source --file-hint-mode description \
    --output "$OUTDIR/mean3_${s}.json" >> "$LOGDIR/${s}.log" 2>&1
}
export -f launch_one
export ROOT_DIR OUTDIR LOGDIR

newest_partial_age() {
  # seconds since the most recently modified run*.partial for a target model
  local newest=0 now; now=$(date +%s)
  for m in "${MODELS[@]}"; do
    local s="${m#openrouter/}"; s="${s//\//_}"
    for f in "$OUTDIR"/run*_openrouter_"${s}".json.partial; do
      [[ -f "$f" ]] || continue
      local mt; mt=$(stat -f %m "$f" 2>/dev/null || echo 0)
      (( mt > newest )) && newest=$mt
    done
  done
  (( newest == 0 )) && { echo 999999; return; }
  echo $(( now - newest ))
}

restarts=0
while :; do
  # bash 3.2 (macOS default) has no mapfile — read into the array manually.
  todo=()
  while IFS= read -r line; do
    [[ -n "$line" ]] && todo+=("$line")
  done < <(pending_models)
  if (( ${#todo[@]} == 0 )); then
    echo "[pfinish] all target models complete"
    break
  fi
  echo "[pfinish] round $restarts: ${#todo[@]} pending → ${todo[*]}"

  active_pids=()
  for model in "${todo[@]}"; do
    while (( ${#active_pids[@]} >= MAX_PARALLEL )); do
      for i in "${!active_pids[@]}"; do
        kill -0 "${active_pids[$i]}" 2>/dev/null || { unset 'active_pids[$i]'; active_pids=("${active_pids[@]}"); break; }
      done
      sleep 2
    done
    echo "[pfinish] launch $model"
    bash -c "launch_one '$model'" & active_pids+=($!)
  done

  # Watchdog: while any worker runs, watch for a global stall.
  stalled=0
  while :; do
    alive=0
    for pid in "${active_pids[@]}"; do kill -0 "$pid" 2>/dev/null && alive=1; done
    (( alive == 0 )) && break
    age=$(newest_partial_age)
    if (( age > STALL_SECONDS )); then
      echo "[pfinish] STALL: no checkpoint write in ${age}s (> ${STALL_SECONDS}) — deadlock; restarting batch"
      stalled=1
      break
    fi
    sleep 30
  done

  # Kill this batch's workers (and their python children) before next round.
  for pid in "${active_pids[@]}"; do kill -9 "$pid" 2>/dev/null; done
  pkill -9 -f "run_best_of_n" 2>/dev/null || true
  pkill -9 -f "resource_tracker" 2>/dev/null || true
  sleep 3

  restarts=$((restarts+1))
  if (( restarts > MAX_RESTARTS )); then
    echo "[pfinish] hit MAX_RESTARTS=${MAX_RESTARTS}; stopping"
    exit 1
  fi
  (( stalled == 0 )) && sleep 5   # normal batch end (models finished), loop re-checks pending
done

echo "[pfinish] building analysis + leaderboard for completed set"
"$ROOT_DIR/.venv/bin/python" -m benchmark.model_report \
  --benchmark data/benchmark/vulnbench_200.json \
  --reports "$OUTDIR"/mean3_*.json \
  --output-dir "$OUTDIR/analysis" >> "$OUTDIR/pfinish.log" 2>&1 || true
echo "[pfinish] done"
