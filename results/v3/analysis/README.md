# VulnBench model analyses

## Configuration: judges=openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hints=description · source=True · voting=majority_median_adjudicated · dataset=vulnbench_200.json

| Rank | Model | Pass rate (mean of runs) | 95% CI (pooled) | pass@k | Answer rate | Runs | Artifact failures | Report |
|---:|---|---:|---|---:|---:|---:|---:|---|
| 1 (tie group 1) | anthropic/claude-opus-5 | 64.3% | 60.4%–68.1% | 80.5% | 96% | 3 | 6 | [anthropic_claude-opus-5.md](anthropic_claude-opus-5.md) |
| 2 (tie group 2) | openai/gpt-5.6-sol | 42.2% | 38.3%–46.2% | 56.5% | 100% | 3 | 0 | [openai_gpt-5.6-sol.md](openai_gpt-5.6-sol.md) |
| 3 (tie group 2) | openai/gpt-5.3-codex | 35.7% | 31.9%–39.6% | 50.5% | 100% | 3 | 0 | [openai_gpt-5.3-codex.md](openai_gpt-5.3-codex.md) |
| 4 (tie group 3) | openai/gpt-5.6-terra | 33.3% | 29.7%–37.2% | 47.5% | 100% | 3 | 0 | [openai_gpt-5.6-terra.md](openai_gpt-5.6-terra.md) |
| 5 (tie group 3) | openai/gpt-5.5 | 32.2% | 28.5%–36.0% | 53.0% | 100% | 3 | 0 | [openai_gpt-5.5.md](openai_gpt-5.5.md) |
| 6 (tie group 3) | google/gemini-3.1-pro-preview | 31.2% | 27.6%–35.0% | 45.0% | 96% | 3 | 0 | [google_gemini-3.1-pro-preview.md](google_gemini-3.1-pro-preview.md) |
| 7 (tie group 3) | google/gemini-3.5-flash | 28.5% | 25.0%–32.2% | 41.0% | 82% | 3 | 0 | [google_gemini-3.5-flash.md](google_gemini-3.5-flash.md) |
| 8 (tie group 4) | google/gemini-3.6-flash | 26.7% | 23.3%–30.3% | 40.5% | 72% | 3 | 4 | [google_gemini-3.6-flash.md](google_gemini-3.6-flash.md) |
| 9 (tie group 4) | openai/gpt-5.6-luna | 25.7% | 22.3%–29.3% | 36.5% | 100% | 3 | 0 | [openai_gpt-5.6-luna.md](openai_gpt-5.6-luna.md) |
| 10 (tie group 4) | anthropic/claude-fable-5 | 24.7% | 21.4%–28.3% | 33.0% | 39% | 3 | 121 | [anthropic_claude-fable-5.md](anthropic_claude-fable-5.md) |
| 11 (tie group 4) | x-ai/grok-build-0.1 | 23.7% | 20.4%–27.2% | 37.0% | 98% | 3 | 2 | [x-ai_grok-build-0.1.md](x-ai_grok-build-0.1.md) |
| 12 (tie group 4) | x-ai/grok-4.5 | 21.8% | 18.7%–25.3% | 40.0% | 56% | 3 | 0 | [x-ai_grok-4.5.md](x-ai_grok-4.5.md) |
| 13 (tie group 4) | anthropic/claude-opus-4.8 | 20.8% | 17.8%–24.3% | 35.0% | 100% | 3 | 0 | [anthropic_claude-opus-4.8.md](anthropic_claude-opus-4.8.md) |
| 14 (tie group 4) | anthropic/claude-sonnet-5 | 19.7% | 16.7%–23.0% | 33.0% | 100% | 3 | 0 | [anthropic_claude-sonnet-5.md](anthropic_claude-sonnet-5.md) |
| 15 (tie group 5) | anthropic/claude-sonnet-4.6 | 17.2% | 14.4%–20.4% | 29.0% | 100% | 3 | 0 | [anthropic_claude-sonnet-4.6.md](anthropic_claude-sonnet-4.6.md) |
| 16 (tie group 5) | deepseek/deepseek-v4-pro | 16.0% | 13.3%–19.1% | 26.5% | 100% | 3 | 0 | [deepseek_deepseek-v4-pro.md](deepseek_deepseek-v4-pro.md) |
| 17 (tie group 5) | minimax/minimax-m3 | 12.3% | 9.9%–15.2% | 21.0% | 98% | 3 | 0 | [minimax_minimax-m3.md](minimax_minimax-m3.md) |
| 18 (tie group 5) | x-ai/grok-4.3 | 12.0% | 9.6%–14.8% | 19.0% | 100% | 3 | 0 | [x-ai_grok-4.3.md](x-ai_grok-4.3.md) |
| 19 (tie group 5) | google/gemini-3.5-flash-lite | 11.8% | 9.5%–14.7% | 19.0% | 97% | 3 | 0 | [google_gemini-3.5-flash-lite.md](google_gemini-3.5-flash-lite.md) |
| 20 (tie group 5) | nvidia/nemotron-3-ultra-550b-a55b | 10.8% | 8.6%–13.6% | 19.5% | 98% | 3 | 0 | [nvidia_nemotron-3-ultra-550b-a55b.md](nvidia_nemotron-3-ultra-550b-a55b.md) |
| 21 (tie group 5) | openai/gpt-5.4-mini | 10.3% | 8.1%–13.0% | 19.5% | 85% | 3 | 0 | [openai_gpt-5.4-mini.md](openai_gpt-5.4-mini.md) |
| 22 (tie group 6) | anthropic/claude-haiku-4.5 | 8.8% | 6.8%–11.4% | 12.0% | 98% | 3 | 0 | [anthropic_claude-haiku-4.5.md](anthropic_claude-haiku-4.5.md) |
| 23 (tie group 6) | stepfun/step-3.7-flash | 8.8% | 6.8%–11.4% | 15.5% | 94% | 3 | 9 | [stepfun_step-3.7-flash.md](stepfun_step-3.7-flash.md) |
| 24 (tie group 6) | deepseek/deepseek-v4-flash | 7.8% | 5.9%–10.3% | 15.5% | 98% | 3 | 3 | [deepseek_deepseek-v4-flash.md](deepseek_deepseek-v4-flash.md) |
| 25 (tie group 6) | mistralai/mistral-medium-3-5 | 5.8% | 4.2%–8.0% | 9.0% | 100% | 3 | 0 | [mistralai_mistral-medium-3-5.md](mistralai_mistral-medium-3-5.md) |

*Models in the same tie group are statistically indistinguishable (paired bootstrap over instances, p ≥ 0.05). pass@k = passed in at least one run — report it separately from single-run pass rate.*
