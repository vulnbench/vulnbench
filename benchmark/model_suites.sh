#!/usr/bin/env bash

# VulnBench v3 OpenRouter model suite.
# Refreshed from https://openrouter.ai/api/v1/models on 2026-07-23.
VULNBENCH_LATEST_MODELS=(
  openrouter/openai/gpt-5.6-sol
  openrouter/openai/gpt-5.6-luna
  openrouter/openai/gpt-5.6-terra
  openrouter/openai/gpt-5.5
  openrouter/openai/gpt-5.4-mini
  openrouter/openai/gpt-5.3-codex
  openrouter/anthropic/claude-fable-5
  openrouter/anthropic/claude-opus-5
  openrouter/anthropic/claude-sonnet-5
  openrouter/anthropic/claude-opus-4.8
  openrouter/anthropic/claude-sonnet-4.6
  openrouter/anthropic/claude-haiku-4.5
  openrouter/google/gemini-3.6-flash
  openrouter/google/gemini-3.5-flash
  openrouter/google/gemini-3.5-flash-lite
  openrouter/google/gemini-3.1-pro-preview
  openrouter/x-ai/grok-4.5
  openrouter/x-ai/grok-build-0.1
  openrouter/x-ai/grok-4.3
  openrouter/deepseek/deepseek-v4-pro
  openrouter/deepseek/deepseek-v4-flash
  openrouter/moonshotai/kimi-k3
  openrouter/moonshotai/kimi-k2.7-code
  openrouter/moonshotai/kimi-k2.6
  openrouter/minimax/minimax-m3
  openrouter/qwen/qwen3.7-max
  openrouter/qwen/qwen3.7-plus
  openrouter/z-ai/glm-5.2
  openrouter/z-ai/glm-5.1
  openrouter/stepfun/step-3.7-flash
  openrouter/nvidia/nemotron-3-ultra-550b-a55b
  openrouter/mistralai/mistral-medium-3-5
  openrouter/tencent/hy3
)

# High-cost variants. Keep separate so accidental full-suite runs do not silently
# multiply spend; add them to the array above when intentionally benchmarking.
# ":free" model tiers are excluded from the suite entirely — their rate limits
# produced 100% API-failure rows in v1 (see REVIEW_FINDINGS.md).
VULNBENCH_OPTIONAL_EXPENSIVE_MODELS=(
  openrouter/openai/gpt-5.5-pro
  openrouter/openai/gpt-5.6-sol-pro
  openrouter/openai/gpt-5.6-luna-pro
  openrouter/openai/gpt-5.6-terra-pro
)

# Refuse to launch a suite when remaining OpenRouter credits are below the
# given floor — a mid-suite 402 turns funding failures into fake model
# failures (v1 audit finding). Usage: vulnbench_require_credits <min_usd>
vulnbench_require_credits() {
  local min_usd="$1"
  python3 - "$min_usd" <<'PY'
import json
import sys
import urllib.request
from pathlib import Path

from dotenv import dotenv_values

min_usd = float(sys.argv[1])
key = dotenv_values(Path(".env")).get("OPENROUTER_API_KEY")
req = urllib.request.Request(
    "https://openrouter.ai/api/v1/credits",
    headers={"Authorization": f"Bearer {key}"},
)
data = json.load(urllib.request.urlopen(req, timeout=30))["data"]
remaining = data["total_credits"] - data["total_usage"]
print(f"OpenRouter credits remaining: ${remaining:.2f} (floor: ${min_usd:.2f})")
if remaining < min_usd:
    print(
        f"INSUFFICIENT CREDITS: top up before launching, or lower the floor "
        f"deliberately with VULNBENCH_MIN_CREDITS.",
        file=sys.stderr,
    )
    sys.exit(1)
PY
}

vulnbench_require_openrouter_auth() {
  python3 - <<'PY'
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from dotenv import dotenv_values

env_path = Path(".env")
key = dotenv_values(env_path).get("OPENROUTER_API_KEY") if env_path.exists() else None
if not key:
    print("Missing OPENROUTER_API_KEY in .env", file=sys.stderr)
    sys.exit(1)

request = urllib.request.Request(
    "https://openrouter.ai/api/v1/auth/key",
    headers={"Authorization": f"Bearer {key}"},
)

try:
    with urllib.request.urlopen(request, timeout=30) as response:
        response.read()
except urllib.error.HTTPError as exc:
    body = exc.read().decode("utf-8", "replace")
    try:
        message = json.loads(body).get("error", {}).get("message", body)
    except json.JSONDecodeError:
        message = body
    print(f"OpenRouter auth check failed ({exc.code}): {message}", file=sys.stderr)
    sys.exit(1)
except Exception as exc:
    print(f"OpenRouter auth check failed: {exc}", file=sys.stderr)
    sys.exit(1)
PY
}
