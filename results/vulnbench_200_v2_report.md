# VulnBench-200 Merged Harness-Fix Report

Merged leaderboard preserving the prior curated-200 best-of-3 baseline and replacing only rows with clear material improvement from the fixed adapter retry/empty-response harness.

## Summary

- Rows included: 37
- Updated from fixed harness: 6
- Added new fixed-harness rows: 4
- Carried forward from prior baseline: 27
- Leader: Claude Fable 5 at 37.5% (75/200)
- Median pass rate: 10.0%

## Merge Rule

- A prior row is replaced only when the fixed-harness row improves mean score by at least 0.02 and pass count by at least 1.
- New models with no prior 200-instance baseline are added as fixed-harness rows.
- Regressions and ambiguous changes are kept from the prior baseline, even if one metric improved.
- Fixed-harness rows used adapter exception retries, empty-response retries, and two judges: Claude Opus 4.8 plus GPT-5.5.
- Under the current consensus rule, a split two-judge vote passes when either judge votes pass.

## Leaderboard

| Rank | Model | Org | Source | Pass Rate | Mean Score | Passed | Best Run | Cost |
|:----:|-------|-----|--------|:---------:|:----------:|:------:|:--------:|-----:|
| 1 | Claude Fable 5 | Anthropic | prior baseline | 37.5% | 0.443 | 75/200 | 1 | $34.80 |
| 2 | GPT-5.5 | OpenAI | fixed harness | 33.0% | 0.338 | 66/200 | 1 | $53.83 |
| 3 | Claude Opus 4.8 | Anthropic | prior baseline | 29.5% | 0.418 | 59/200 | 1 | $12.34 |
| 4 | Qwen 3.7 Max | Qwen | prior baseline | 28.5% | 0.403 | 57/200 | 2 | $13.78 |
| 5 | GPT-5.3 Codex | OpenAI | prior baseline | 22.5% | 0.468 | 45/200 | 3 | $8.74 |
| 6 | Kimi K2.5 | Moonshot AI | fixed harness | 19.5% | 0.301 | 39/200 | 1 | $12.78 |
| 7 | Grok Build 0.1 | xAI | prior baseline | 19.0% | 0.332 | 38/200 | 1 | $10.87 |
| 8 | GPT-5.4 | OpenAI | prior baseline | 18.5% | 0.407 | 37/200 | 3 | $4.81 |
| 9 | Qwen 3.7 Plus | Qwen | prior baseline | 16.5% | 0.292 | 33/200 | 2 | $6.59 |
| 10 | Claude Opus 4.6 | Anthropic | prior baseline | 16.0% | 0.404 | 32/200 | 2 | $10.17 |
| 11 | DeepSeek V4 Pro | DeepSeek | fixed harness | 15.5% | 0.250 | 31/200 | 3 | $12.44 |
| 12 | GPT-5.2 | OpenAI | prior baseline | 15.0% | 0.322 | 30/200 | 3 | $11.30 |
| 13 | GLM 5.1 | Z.AI | fixed harness | 12.5% | 0.165 | 25/200 | 2 | $11.24 |
| 14 | Grok 4.3 | xAI | prior baseline | 12.0% | 0.257 | 24/200 | 3 | $4.00 |
| 15 | GPT-5.4 Mini | OpenAI | prior baseline | 12.0% | 0.228 | 24/200 | 3 | $4.12 |
| 16 | Nemotron 3 Ultra 550B | NVIDIA | prior baseline | 12.0% | 0.206 | 24/200 | 2 | $5.08 |
| 17 | Kimi K2.6 | Moonshot AI | fixed harness | 11.0% | 0.120 | 22/200 | 1 | $10.20 |
| 18 | Claude Sonnet 4.6 | Anthropic | prior baseline | 10.5% | 0.322 | 21/200 | 2 | $6.87 |
| 19 | DeepSeek V4 Flash | DeepSeek | prior baseline | 10.0% | 0.226 | 20/200 | 1 | $3.71 |
| 20 | Qwen 3.5 35B A3B | Qwen | new fixed harness | 10.0% | 0.168 | 20/200 | 2 | $9.42 |
| 21 | Qwen 3.5 27B | Qwen | new fixed harness | 9.5% | 0.178 | 19/200 | 1 | $12.13 |
| 22 | MiniMax M3 | MiniMax | prior baseline | 9.5% | 0.165 | 19/200 | 2 | $2.91 |
| 23 | GLM 5.2 | Z.AI | new fixed harness | 9.0% | 0.174 | 18/200 | 1 | $9.98 |
| 24 | MiniMax M2.7 | MiniMax | fixed harness | 8.0% | 0.132 | 16/200 | 1 | $9.25 |
| 25 | Gemini 3 Flash | Google | prior baseline | 7.5% | 0.318 | 15/200 | 1 | $3.13 |
| 26 | GLM 5 | Z.AI | prior baseline | 7.0% | 0.249 | 14/200 | 3 | $4.26 |
| 27 | Mistral Medium 3.5 | Mistral AI | prior baseline | 7.0% | 0.161 | 14/200 | 2 | $4.64 |
| 28 | Kimi K2.7 Code | Moonshot AI | new fixed harness | 6.0% | 0.067 | 12/200 | 3 | $8.33 |
| 29 | Grok 4.1 Fast | xAI | prior baseline | 5.5% | 0.273 | 11/200 | 3 | $3.46 |
| 30 | GPT-5 Mini | OpenAI | prior baseline | 5.0% | 0.275 | 10/200 | 2 | $3.63 |
| 31 | DeepSeek V3.2 | DeepSeek | prior baseline | 4.5% | 0.253 | 9/200 | 2 | $3.25 |
| 32 | Gemini 3.5 Flash | Google | prior baseline | 4.5% | 0.047 | 9/200 | 3 | $10.33 |
| 33 | Claude Haiku 4.5 | Anthropic | prior baseline | 3.5% | 0.263 | 7/200 | 3 | $3.95 |
| 34 | Gemini 3.1 Pro | Google | prior baseline | 2.5% | 0.093 | 5/200 | 2 | $9.60 |
| 35 | MiniMax M2.5 | MiniMax | prior baseline | 1.5% | 0.181 | 3/200 | 2 | $3.25 |
| 36 | Step 3.7 Flash | StepFun | prior baseline | 1.5% | 0.018 | 3/200 | 3 | $1.12 |
| 37 | Step 3.5 Flash | StepFun | prior baseline | 0.0% | 0.000 | 0/200 | 1 | $0.00 |
