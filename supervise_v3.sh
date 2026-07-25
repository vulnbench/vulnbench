#!/usr/bin/env bash
# Supervisor for the VulnBench v3 suite. Waits for any running suite to drain,
# then re-runs run_v3_200.sh in a loop until every model has a completed
# mean3_*.json summary — healing transient network outages that abort
# individual models. Each pass skips already-complete models, so repeated
# passes only work on what's left. Stops when the suite is complete, when
# credits fall below the floor, or after MAX_PASSES.
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

MAX_PASSES="${VULNBENCH_MAX_PASSES:-40}"
# Lower floor for resume passes: most expensive models are already done, and
# refusing to heal a nearly-finished suite over a small balance is worse than
# a partial top-up reminder.
export VULNBENCH_MIN_CREDITS="${VULNBENCH_MIN_CREDITS:-150}"

SUITE_MODELS=$(grep -cE '^\s+openrouter/' benchmark/model_suites.sh || echo 32)

echo "[supervisor] waiting for any in-flight suite to drain…"
while pgrep -f "bash run_v3_200.sh" > /dev/null; do
  sleep 60
done
echo "[supervisor] no suite running; beginning resume loop (target ${SUITE_MODELS} models)"

pass=0
while (( pass < MAX_PASSES )); do
  complete=$(ls results/v3/mean3_*.json 2>/dev/null | wc -l | tr -d ' ')
  if (( complete >= SUITE_MODELS )); then
    echo "[supervisor] all ${complete}/${SUITE_MODELS} models complete after ${pass} resume pass(es)"
    break
  fi
  pass=$((pass + 1))
  echo "[supervisor] === resume pass ${pass}: ${complete}/${SUITE_MODELS} complete ==="
  bash run_v3_200.sh >> results/v3/suite_supervised.log 2>&1 || {
    rc=$?
    echo "[supervisor] pass ${pass} exited rc=${rc} (likely credit floor or auth); pausing 300s"
    # If run_v3_200 refused to start (credits/auth), don't hot-loop.
    sleep 300
  }
  sleep 15
done

complete=$(ls results/v3/mean3_*.json 2>/dev/null | wc -l | tr -d ' ')
if (( complete < SUITE_MODELS )); then
  echo "[supervisor] STOPPED at ${complete}/${SUITE_MODELS} after ${pass} passes (hit MAX_PASSES or credit floor)"
  echo "[supervisor] incomplete models:"
  bash -c 'source benchmark/model_suites.sh; for m in "${VULNBENCH_LATEST_MODELS[@]}"; do s="${m#openrouter/}"; s="${s//\//_}"; [[ -f "results/v3/mean3_${s}.json" ]] || echo "  - $m"; done'
  exit 1
fi

echo "[supervisor] building final analysis + leaderboard…"
python -m benchmark.model_report \
  --benchmark data/benchmark/vulnbench_200.json \
  --reports results/v3/run?_openrouter_*.json \
  --output-dir results/v3/analysis >> results/v3/suite_supervised.log 2>&1
echo "[supervisor] DONE — leaderboard at results/v3/analysis/README.md"
