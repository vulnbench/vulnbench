#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

date '+%Y-%m-%d %H:%M:%S %Z'

.venv/bin/python - <<'PY'
import json
from pathlib import Path

jobs = [
    ("GLM 5.1 r1", "run1", "openrouter_z-ai_glm-5.1"),
    ("Kimi K2.6 r1", "run1", "openrouter_moonshotai_kimi-k2.6"),
    ("Grok Build r1", "run1", "openrouter_x-ai_grok-build-0.1"),
    ("Qwen 3.7 Max r1", "run1", "openrouter_qwen_qwen3.7-max"),
    ("Qwen 3.7 Plus r1", "run1", "openrouter_qwen_qwen3.7-plus"),
    ("DeepSeek v4 Flash r2", "run2", "openrouter_deepseek_deepseek-v4-flash"),
    ("DeepSeek v4 Flash r3", "run3", "openrouter_deepseek_deepseek-v4-flash"),
]

for label, run, safe in jobs:
    final = Path(f"results/{run}_{safe}.json")
    partial = Path(str(final) + ".partial")
    if final.exists():
        data = json.loads(final.read_text())
        aggregate = data["aggregate"]
        print(
            f"{label}: FINAL {aggregate['total_instances']}/200 "
            f"passed={aggregate['total_passed']} mean={aggregate['mean_score']:.3f}"
        )
    elif partial.exists():
        data = json.loads(partial.read_text())
        aggregate = data["aggregate"]
        print(
            f"{label}: {aggregate['total_instances']}/200 "
            f"passed={aggregate['total_passed']} mean={aggregate['mean_score']:.3f}"
        )
    else:
        print(f"{label}: no checkpoint yet")
PY

launchctl list | grep -E 'com\.vulnbench\.missinglatest\.parallel' || true
ps -axo pid,ppid,state,etime,command \
  | grep -E 'benchmark\.run_eval.*(glm-5\.1|kimi-k2\.6|grok-build-0\.1|qwen3\.7|max|qwen3\.7-plus|deepseek-v4-flash)' \
  || true
