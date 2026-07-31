# VulnBench model analyses

> ⚠ **Comparability notice:** the analyses below were produced under more than one evaluation configuration (different judge panels or prompt settings). Models are only ranked against models that share their configuration; cross-table comparisons are not valid.

## Configuration: judges=openrouter/anthropic/claude-opus-4.8 · hints=description · source=True · voting=score_threshold · dataset=vulnbench_200.json

| Rank | Model | Pass rate (mean of runs) | 95% CI (pooled) | pass@k | Answer rate | Runs | Artifact failures | Report |
|---:|---|---:|---|---:|---:|---:|---:|---|
| 1 (tie group 1) | anthropic/claude-fable-5 | 36.7% | 32.9%–40.6% | 56.0% | 64% | 3 | 59 | [anthropic_claude-fable-5.md](anthropic_claude-fable-5.md) |
| 2 (tie group 2) | anthropic/claude-opus-4.8 | 26.8% | 23.4%–30.5% | 44.5% | 99% | 3 | 0 | [anthropic_claude-opus-4.8.md](anthropic_claude-opus-4.8.md) |
| 3 (tie group 2) | qwen/qwen3.7-max | 22.3% | 19.2%–25.8% | 41.0% | 96% | 3 | 3 | [qwen_qwen3.7-max.md](qwen_qwen3.7-max.md) |
| 4 (tie group 3) | openai/gpt-5.5 | 16.5% | 13.7%–19.7% | 30.5% | 42% | 3 | 117 | [openai_gpt-5.5.md](openai_gpt-5.5.md) |
| 5 (tie group 3) | x-ai/grok-build-0.1 | 15.3% | 12.7%–18.4% | 28.0% | 97% | 3 | 4 | [x-ai_grok-build-0.1.md](x-ai_grok-build-0.1.md) |
| 6 (tie group 3) | qwen/qwen3.7-plus | 13.5% | 11.0%–16.5% | 24.5% | 93% | 3 | 4 | [qwen_qwen3.7-plus.md](qwen_qwen3.7-plus.md) |
| 7 (tie group 3) | openai/gpt-5.4-mini | 11.3% | 9.0%–14.1% | 20.5% | 83% | 3 | 0 | [openai_gpt-5.4-mini.md](openai_gpt-5.4-mini.md) |
| 8 (tie group 4) | deepseek/deepseek-v4-pro | 11.0% | 8.7%–13.8% | 22.0% | 80% | 3 | 39 | [deepseek_deepseek-v4-pro.md](deepseek_deepseek-v4-pro.md) |
| 9 (tie group 4) | x-ai/grok-4.3 | 10.7% | 8.4%–13.4% | 19.5% | 100% | 3 | 0 | [x-ai_grok-4.3.md](x-ai_grok-4.3.md) |
| 10 (tie group 4) | z-ai/glm-5.1 | 9.8% | 7.7%–12.5% | 17.0% | 27% | 3 | 144 | [z-ai_glm-5.1.md](z-ai_glm-5.1.md) |
| 11 (tie group 4) | nvidia/nemotron-3-ultra-550b-a55b | 9.7% | 7.5%–12.3% | 18.0% | 88% | 3 | 2 | [nvidia_nemotron-3-ultra-550b-a55b.md](nvidia_nemotron-3-ultra-550b-a55b.md) |
| 12 (tie group 4) | deepseek/deepseek-v4-flash | 8.5% | 6.5%–11.0% | 19.0% | 98% | 3 | 2 | [deepseek_deepseek-v4-flash.md](deepseek_deepseek-v4-flash.md) |
| 13 (tie group 4) | minimax/minimax-m3 | 8.3% | 6.4%–10.8% | 15.0% | 54% | 3 | 86 | [minimax_minimax-m3.md](minimax_minimax-m3.md) |
| 14 (tie group 4) | mistralai/mistral-medium-3-5 | 6.3% | 4.7%–8.6% | 12.0% | 98% | 3 | 0 | [mistralai_mistral-medium-3-5.md](mistralai_mistral-medium-3-5.md) |
| 15 (tie group 4) | moonshotai/kimi-k2.6 | 6.0% | 4.4%–8.2% | 15.0% | 18% | 3 | 161 | [moonshotai_kimi-k2.6.md](moonshotai_kimi-k2.6.md) |
| 16 (tie group 5) | google/gemini-3.5-flash | 3.7% | 2.4%–5.5% | 7.0% | 17% | 3 | 1 | [google_gemini-3.5-flash.md](google_gemini-3.5-flash.md) |
| 17 (tie group 5) | stepfun/step-3.7-flash | 1.0% | 0.5%–2.2% | 2.5% | 4% | 3 | 192 | [stepfun_step-3.7-flash.md](stepfun_step-3.7-flash.md) |

*Models in the same tie group are statistically indistinguishable (paired bootstrap over instances, p ≥ 0.05). pass@k = passed in at least one run — report it separately from single-run pass rate.*

## Configuration: judges=openrouter/anthropic/claude-opus-4-6 · hints=description · source=True · voting=score_threshold · dataset=vulnbench_200.json

| Rank | Model | Pass rate (mean of runs) | 95% CI (pooled) | pass@k | Answer rate | Runs | Artifact failures | Report |
|---:|---|---:|---|---:|---:|---:|---:|---|
| 1 (tie group 1) | openai/gpt-5.3-codex | 17.3% | 14.5%–20.6% | 29.0% | 99% | 3 | 2 | [openai_gpt-5.3-codex.md](openai_gpt-5.3-codex.md) |
| 2 (tie group 1) | openai/gpt-5.4 | 15.8% | 13.1%–19.0% | 27.0% | 94% | 3 | 0 | [openai_gpt-5.4.md](openai_gpt-5.4.md) |
| 3 (tie group 2) | anthropic/claude-opus-4.6 | 13.7% | 11.2%–16.7% | 20.5% | 98% | 3 | 0 | [anthropic_claude-opus-4.6.md](anthropic_claude-opus-4.6.md) |
| 4 (tie group 2) | openai/gpt-5.2 | 11.5% | 9.2%–14.3% | 22.0% | 78% | 3 | 45 | [openai_gpt-5.2.md](openai_gpt-5.2.md) |
| 5 (tie group 3) | anthropic/claude-sonnet-4.6 | 8.8% | 6.8%–11.4% | 14.5% | 96% | 3 | 0 | [anthropic_claude-sonnet-4.6.md](anthropic_claude-sonnet-4.6.md) |
| 6 (tie group 3) | google/gemini-3-flash-preview | 6.5% | 4.8%–8.8% | 7.5% | 100% | 3 | 0 | [google_gemini-3-flash-preview.md](google_gemini-3-flash-preview.md) |
| 7 (tie group 3) | z-ai/glm-5 | 5.5% | 3.9%–7.6% | 10.0% | 72% | 3 | 46 | [z-ai_glm-5.md](z-ai_glm-5.md) |
| 8 (tie group 3) | openai/gpt-5-mini | 4.7% | 3.2%–6.7% | 8.0% | 0% | 3 | 1 | [openai_gpt-5-mini.md](openai_gpt-5-mini.md) |
| 9 (tie group 3) | moonshotai/kimi-k2.5 | 4.3% | 3.0%–6.3% | 9.0% | 57% | 3 | 84 | [moonshotai_kimi-k2.5.md](moonshotai_kimi-k2.5.md) |
| 10 (tie group 3) | x-ai/grok-4.1-fast | 3.8% | 2.6%–5.7% | 9.0% | 99% | 3 | 2 | [x-ai_grok-4.1-fast.md](x-ai_grok-4.1-fast.md) |
| 11 (tie group 3) | anthropic/claude-haiku-4.5 | 3.5% | 2.3%–5.3% | 4.0% | 94% | 3 | 0 | [anthropic_claude-haiku-4.5.md](anthropic_claude-haiku-4.5.md) |
| 12 (tie group 4) | deepseek/deepseek-v3.2 | 3.0% | 1.9%–4.7% | 5.0% | 98% | 3 | 0 | [deepseek_deepseek-v3.2.md](deepseek_deepseek-v3.2.md) |
| 13 (tie group 4) | google/gemini-3.1-pro-preview | 1.8% | 1.0%–3.2% | 3.5% | 44% | 3 | 64 | [google_gemini-3.1-pro-preview.md](google_gemini-3.1-pro-preview.md) |
| 14 (tie group 4) | minimax/minimax-m2.5 | 1.3% | 0.7%–2.6% | 2.5% | 71% | 3 | 8 | [minimax_minimax-m2.5.md](minimax_minimax-m2.5.md) |
| 15 (tie group 4) | qwen/qwen3.5-27b | 1.2% | 0.6%–2.4% | 3.5% | 98% | 3 | 0 | [qwen_qwen3.5-27b.md](qwen_qwen3.5-27b.md) |
| 16 (tie group 5) | minimax/minimax-m2.7 | 1.0% | 0.5%–2.2% | 2.5% | 28% | 3 | 115 | [minimax_minimax-m2.7.md](minimax_minimax-m2.7.md) |
| 17 (tie group 5) | qwen/qwen3.5-35b-a3b | 0.5% | 0.2%–1.5% | 1.5% | 94% | 3 | 6 | [qwen_qwen3.5-35b-a3b.md](qwen_qwen3.5-35b-a3b.md) |
| 18 (tie group 5) | stepfun/step-3.5-flash:free | 0.0% | 0.0%–0.6% | 0.0% | 0% | 3 | 200 | [stepfun_step-3.5-flash:free.md](stepfun_step-3.5-flash:free.md) |

*Models in the same tie group are statistically indistinguishable (paired bootstrap over instances, p ≥ 0.05). pass@k = passed in at least one run — report it separately from single-run pass rate.*

## Configuration: judges=openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hints=description · source=True · voting=score_threshold · dataset=vulnbench_200.json

| Rank | Model | Pass rate (mean of runs) | 95% CI (pooled) | pass@k | Answer rate | Runs | Artifact failures | Report |
|---:|---|---:|---|---:|---:|---:|---:|---|
| 1 | z-ai/glm-5.2 | 4.0% | 2.7%–5.9% | 8.5% | 98% | 3 | 0 | [z-ai_glm-5.2.md](z-ai_glm-5.2.md) |

*Models in the same tie group are statistically indistinguishable (paired bootstrap over instances, p ≥ 0.05). pass@k = passed in at least one run — report it separately from single-run pass rate.*
