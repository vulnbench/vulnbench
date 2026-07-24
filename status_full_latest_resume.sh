#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

source benchmark/model_suites.sh

EXPECTED_TOTAL=${VULNBENCH_FULL_EXPECTED_TOTAL:-1650}

date '+%Y-%m-%d %H:%M:%S %Z'

.venv/bin/python - "$EXPECTED_TOTAL" "${VULNBENCH_LATEST_MODELS[@]}" <<'PY'
import json
import sys
from pathlib import Path

expected = int(sys.argv[1])
models = sys.argv[2:]

for model in models:
    safe = model.removeprefix("openrouter/").replace("/", "_").replace(":", "_")
    final = Path(f"results/full_{safe}.json")
    partial = Path(str(final) + ".partial")
    label = model.removeprefix("openrouter/")
    if final.exists():
        data = json.loads(final.read_text())
        aggregate = data["aggregate"]
        total = aggregate["total_instances"]
        state = "FINAL" if total == expected else "INCOMPLETE"
        print(
            f"{label}: {state} {total}/{expected} "
            f"passed={aggregate['total_passed']} mean={aggregate['mean_score']:.3f}"
        )
    elif partial.exists():
        data = json.loads(partial.read_text())
        aggregate = data["aggregate"]
        print(
            f"{label}: {aggregate['total_instances']}/{expected} "
            f"passed={aggregate['total_passed']} mean={aggregate['mean_score']:.3f}"
        )
    else:
        print(f"{label}: no checkpoint yet")
PY

launchctl list | grep -E 'com\.vulnbench\.full_latest\.(parallel|status)' || true
ps -axo pid,ppid,state,etime,command \
  | grep -E 'benchmark\.run_eval.*vulnbench_full|run_full_latest_resume' \
  | grep -v grep \
  || true
