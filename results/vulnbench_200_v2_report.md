# VulnBench V2 Report

Curated VulnBench-200 retest using best-of-3 runs, source context, description-only file hints, and Claude Opus 4.8 as judge.

## Summary

- Final models included: 21
- Pending models: None
- Leader: Claude Fable 5 at 37.5% (75/200)
- Median pass rate: 11.5%

## Leaderboard

| Rank | Model | Org | Pass Rate | Mean Score | Passed | Best Run | Cost |
|:----:|-------|-----|:---------:|:----------:|:------:|:--------:|-----:|
| 1 | Claude Fable 5 | Anthropic | 37.5% | 0.443 | 75/200 | 1 | $32.27 |
| 2 | Claude Opus 4.8 | Anthropic | 29.5% | 0.418 | 59/200 | 1 | $8.43 |
| 3 | Qwen 3.7 Max | Qwen | 28.5% | 0.403 | 57/200 | 2 | $10.03 |
| 4 | GPT-5.3 Codex | OpenAI | 22.5% | 0.468 | 45/200 | 3 | $5.78 |
| 5 | Grok Build 0.1 | xAI | 19.0% | 0.332 | 38/200 | 1 | $7.32 |
| 6 | GPT-5.5 | OpenAI | 17.5% | 0.214 | 35/200 | 3 | $22.36 |
| 7 | Qwen 3.7 Plus | Qwen | 16.5% | 0.292 | 33/200 | 2 | $3.22 |
| 8 | Grok 4.3 | xAI | 12.0% | 0.257 | 24/200 | 3 | $0.57 |
| 9 | GPT-5.4 Mini | OpenAI | 12.0% | 0.228 | 24/200 | 3 | $0.40 |
| 10 | Nemotron 3 Ultra 550B | NVIDIA | 12.0% | 0.206 | 24/200 | 2 | $1.32 |
| 11 | DeepSeek V4 Pro | DeepSeek | 11.5% | 0.230 | 23/200 | 2 | $1.51 |
| 12 | GLM 5.1 | Z.AI | 11.0% | 0.134 | 22/200 | 2 | $4.01 |
| 13 | Claude Sonnet 4.6 | Anthropic | 10.5% | 0.322 | 21/200 | 2 | $3.97 |
| 14 | DeepSeek V4 Flash | DeepSeek | 10.0% | 0.226 | 20/200 | 1 | $0.07 |
| 15 | MiniMax M3 | MiniMax | 9.5% | 0.165 | 19/200 | 2 | $0.76 |
| 16 | Mistral Medium 3.5 | Mistral AI | 7.0% | 0.161 | 14/200 | 2 | $1.13 |
| 17 | Kimi K2.6 | Moonshot AI | 7.0% | 0.082 | 14/200 | 3 | $4.19 |
| 18 | Gemini 3.5 Flash | Google | 4.5% | 0.047 | 9/200 | 3 | $7.45 |
| 19 | Claude Haiku 4.5 | Anthropic | 3.5% | 0.263 | 7/200 | 3 | $1.04 |
| 20 | Gemini 3.1 Pro | Google | 2.5% | 0.093 | 5/200 | 2 | $8.03 |
| 21 | Step 3.7 Flash | StepFun | 1.5% | 0.018 | 3/200 | 3 | $0.96 |

## Notes

- Full 1,650-instance reruns were stopped and are not mixed into this report.
- Rows are selected by best run out of three using pass rate, then mean score as tiebreaker.
- Costs include generation and judge costs as recorded in each result artifact.
