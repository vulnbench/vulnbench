# VulnBench model analyses

## Configuration: judges=openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hints=description · source=True · voting=majority_median_adjudicated · dataset=vulnbench_200.json

| Rank | Model | Pass rate (mean of runs) | 95% CI (pooled) | pass@k | Answer rate | Runs | Artifact failures | Report |
|---:|---|---:|---|---:|---:|---:|---:|---|
| 1 (tie group 1) | anthropic/claude-opus-5 | 60.5% | 53.6%–67.0% | 60.5% | 96% | 1 | 6 | [anthropic_claude-opus-5.md](anthropic_claude-opus-5.md) |
| 2 (tie group 2) | openai/gpt-5.6-sol | 43.5% | 36.8%–50.4% | 43.5% | 100% | 1 | 0 | [openai_gpt-5.6-sol.md](openai_gpt-5.6-sol.md) |
| 3 (tie group 2) | openai/gpt-5.3-codex | 38.5% | 32.0%–45.4% | 38.5% | 100% | 1 | 0 | [openai_gpt-5.3-codex.md](openai_gpt-5.3-codex.md) |
| 4 (tie group 3) | openai/gpt-5.5 | 35.5% | 29.2%–42.4% | 35.5% | 100% | 1 | 0 | [openai_gpt-5.5.md](openai_gpt-5.5.md) |
| 5 (tie group 3) | google/gemini-3.1-pro-preview | 33.5% | 27.3%–40.3% | 33.5% | 96% | 1 | 0 | [google_gemini-3.1-pro-preview.md](google_gemini-3.1-pro-preview.md) |
| 6 (tie group 3) | openai/gpt-5.6-terra | 33.0% | 26.9%–39.8% | 33.0% | 100% | 1 | 0 | [openai_gpt-5.6-terra.md](openai_gpt-5.6-terra.md) |
| 7 (tie group 3) | google/gemini-3.5-flash | 29.5% | 23.6%–36.2% | 29.5% | 82% | 1 | 0 | [google_gemini-3.5-flash.md](google_gemini-3.5-flash.md) |
| 8 (tie group 4) | anthropic/claude-fable-5 | 25.5% | 20.0%–32.0% | 25.5% | 39% | 1 | 121 | [anthropic_claude-fable-5.md](anthropic_claude-fable-5.md) |
| 9 (tie group 4) | openai/gpt-5.6-luna | 25.5% | 20.0%–32.0% | 25.5% | 100% | 1 | 0 | [openai_gpt-5.6-luna.md](openai_gpt-5.6-luna.md) |
| 10 (tie group 4) | google/gemini-3.6-flash | 24.0% | 18.6%–30.4% | 24.0% | 72% | 1 | 4 | [google_gemini-3.6-flash.md](google_gemini-3.6-flash.md) |
| 11 (tie group 4) | x-ai/grok-4.5 | 24.0% | 18.6%–30.4% | 24.0% | 56% | 1 | 0 | [x-ai_grok-4.5.md](x-ai_grok-4.5.md) |
| 12 (tie group 4) | anthropic/claude-sonnet-5 | 22.5% | 17.3%–28.8% | 22.5% | 100% | 1 | 0 | [anthropic_claude-sonnet-5.md](anthropic_claude-sonnet-5.md) |
| 13 (tie group 4) | x-ai/grok-build-0.1 | 22.0% | 16.8%–28.2% | 22.0% | 98% | 1 | 2 | [x-ai_grok-build-0.1.md](x-ai_grok-build-0.1.md) |
| 14 (tie group 5) | anthropic/claude-opus-4.8 | 17.5% | 12.9%–23.4% | 17.5% | 100% | 1 | 0 | [anthropic_claude-opus-4.8.md](anthropic_claude-opus-4.8.md) |
| 15 (tie group 5) | anthropic/claude-sonnet-4.6 | 16.0% | 11.6%–21.7% | 16.0% | 100% | 1 | 0 | [anthropic_claude-sonnet-4.6.md](anthropic_claude-sonnet-4.6.md) |
| 16 (tie group 5) | deepseek/deepseek-v4-pro | 15.0% | 10.7%–20.6% | 15.0% | 100% | 1 | 0 | [deepseek_deepseek-v4-pro.md](deepseek_deepseek-v4-pro.md) |
| 17 (tie group 5) | nvidia/nemotron-3-ultra-550b-a55b | 13.0% | 9.0%–18.4% | 13.0% | 98% | 1 | 0 | [nvidia_nemotron-3-ultra-550b-a55b.md](nvidia_nemotron-3-ultra-550b-a55b.md) |
| 18 (tie group 5) | openai/gpt-5.4-mini | 12.5% | 8.6%–17.8% | 12.5% | 85% | 1 | 0 | [openai_gpt-5.4-mini.md](openai_gpt-5.4-mini.md) |
| 19 (tie group 5) | minimax/minimax-m3 | 12.0% | 8.2%–17.2% | 12.0% | 98% | 1 | 0 | [minimax_minimax-m3.md](minimax_minimax-m3.md) |
| 20 (tie group 5) | x-ai/grok-4.3 | 12.0% | 8.2%–17.2% | 12.0% | 100% | 1 | 0 | [x-ai_grok-4.3.md](x-ai_grok-4.3.md) |
| 21 (tie group 6) | google/gemini-3.5-flash-lite | 11.0% | 7.4%–16.1% | 11.0% | 97% | 1 | 0 | [google_gemini-3.5-flash-lite.md](google_gemini-3.5-flash-lite.md) |
| 22 (tie group 6) | anthropic/claude-haiku-4.5 | 8.5% | 5.4%–13.2% | 8.5% | 98% | 1 | 0 | [anthropic_claude-haiku-4.5.md](anthropic_claude-haiku-4.5.md) |
| 23 (tie group 7) | deepseek/deepseek-v4-flash | 5.5% | 3.1%–9.6% | 5.5% | 98% | 1 | 3 | [deepseek_deepseek-v4-flash.md](deepseek_deepseek-v4-flash.md) |
| 24 (tie group 7) | mistralai/mistral-medium-3-5 | 5.5% | 3.1%–9.6% | 5.5% | 100% | 1 | 0 | [mistralai_mistral-medium-3-5.md](mistralai_mistral-medium-3-5.md) |

*Models in the same tie group are statistically indistinguishable (paired bootstrap over instances, p ≥ 0.05). pass@k = passed in at least one run — report it separately from single-run pass rate.*
