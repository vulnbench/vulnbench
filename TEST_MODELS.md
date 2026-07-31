# Test Models (OpenRouter) — v3 Suite

All models are accessed via OpenRouter. Use `openrouter/` prefix with LiteLLM.

Refreshed from the OpenRouter model catalog on 2026-07-23. The shared runner
suite lives in `benchmark/model_suites.sh`; the v3 runner is `run_v3_200.sh`.

| Model ID (OpenRouter) | Notes |
|------------------------|-------|
| openai/gpt-5.6-sol | GPT-5.6 Sol — new in v3 |
| openai/gpt-5.6-luna | GPT-5.6 Luna — new in v3 |
| openai/gpt-5.6-terra | GPT-5.6 Terra — new in v3 |
| openai/gpt-5.5 | Previous flagship GPT |
| openai/gpt-5.4-mini | OpenAI mini-class model |
| openai/gpt-5.3-codex | Codex-specialized OpenAI model |
| anthropic/claude-fable-5 | Anthropic top-line release |
| anthropic/claude-sonnet-5 | Claude Sonnet 5 — new in v3 |
| anthropic/claude-opus-4.8 | Also a judge-panel member (never judges its own patches) |
| anthropic/claude-sonnet-4.6 | Previous Sonnet |
| anthropic/claude-haiku-4.5 | Latest Haiku |
| google/gemini-3.6-flash | Gemini 3.6 Flash — new in v3 |
| google/gemini-3.5-flash | Also the tie-breaker judge (never judges its own patches) |
| google/gemini-3.5-flash-lite | Gemini Flash Lite — new in v3 |
| google/gemini-3.1-pro-preview | Gemini Pro text model |
| x-ai/grok-4.5 | Grok 4.5 — new in v3 |
| x-ai/grok-build-0.1 | xAI coding-focused model |
| x-ai/grok-4.3 | Previous standard Grok |
| deepseek/deepseek-v4-pro | DeepSeek Pro |
| deepseek/deepseek-v4-flash | DeepSeek Flash |
| moonshotai/kimi-k3 | Kimi K3 — new in v3 |
| moonshotai/kimi-k2.7-code | Kimi code-specialized |
| moonshotai/kimi-k2.6 | Previous Kimi |
| minimax/minimax-m3 | MiniMax M3 |
| qwen/qwen3.7-max | Flagship Qwen |
| qwen/qwen3.7-plus | Cost-effective Qwen |
| z-ai/glm-5.2 | Latest GLM |
| z-ai/glm-5.1 | Previous GLM |
| stepfun/step-3.7-flash | StepFun Flash (paid tier only) |
| nvidia/nemotron-3-ultra-550b-a55b | Nemotron Ultra |
| mistralai/mistral-medium-3-5 | Mistral Medium |
| tencent/hy3 | Tencent Hy3 — new in v3 |

Notes:

- `:free` model tiers are excluded — their rate limits produced 100%
  API-failure rows in v1 (see `REVIEW_FINDINGS.md`).
- High-cost `-pro` variants (gpt-5.6-sol-pro, -luna-pro, -terra-pro,
  gpt-5.5-pro) live in `VULNBENCH_OPTIONAL_EXPENSIVE_MODELS` and are not run
  by default.
- Judge panel: claude-opus-4.8 + gpt-5.5, gemini-3.5-flash adjudicates
  splits and substitutes for any panel judge whose own patches are being
  scored (`resolve_judge_panel`).
