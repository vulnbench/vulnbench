# VulnBench-200 Merged Harness-Fix Report

Merged leaderboard preserving the prior curated-200 best-of-3 baseline and replacing only rows with clear material improvement from the fixed adapter retry/empty-response harness.

## Summary

- Rows included: 36
- Updated from fixed harness: 3
- Added new fixed-harness rows: 3
- Carried forward from prior baseline: 30
- Leader: Claude Fable 5 at 37.5% (75/200)
- Median pass rate: 10.0%

## Merge Rule

- A prior row is replaced only when the fixed-harness row improves mean score by at least 0.02 and pass count by at least 1.
- New models with no prior 200-instance baseline are added as fixed-harness rows.
- Regressions and ambiguous changes are kept from the prior baseline, even if one metric improved.
- Fixed-harness rows used adapter exception retries, empty-response retries, and two judges: Claude Opus 4.8 plus GPT-5.5.

## Updated Rows

| Model | Prior Passed | Fixed Passed | Pass Delta | Prior Score | Fixed Score | Score Delta |
|---|---:|---:|---:|---:|---:|---:|
| GPT-5.5 | 35/200 | 40/200 | +5 | 0.2140 | 0.3384 | +0.1244 |
| Kimi K2.5 | 13/200 | 20/200 | +7 | 0.2277 | 0.3006 | +0.0729 |
| MiniMax M2.7 | 3/200 | 10/200 | +7 | 0.0988 | 0.1318 | +0.0330 |

## Added Rows

| Model | Passed | Pass Rate | Mean Score |
|---|---:|---:|---:|
| Kimi K2.7 Code | 8/200 | 4.0% | 0.0670 |
| Qwen 3.5 27B | 9/200 | 4.5% | 0.1815 |
| Qwen 3.5 35B A3B | 5/200 | 2.5% | 0.1680 |

## Leaderboard

| Rank | Model | Org | Source | Pass Rate | Mean Score | Passed | Avg Time | Cost |
|:---:|---|---|---|---:|---:|---:|---:|---:|
| 1 | Claude Fable 5 | Anthropic | prior baseline | 37.5% | 0.4427 | 75/200 | 40.5s | $34.80 |
| 2 | Claude Opus 4.8 | Anthropic | prior baseline | 29.5% | 0.4185 | 59/200 | 20.3s | $12.34 |
| 3 | Qwen 3.7 Max | Qwen | prior baseline | 28.5% | 0.4027 | 57/200 | 278.9s | $13.78 |
| 4 | GPT-5.3 Codex | OpenAI | prior baseline | 22.5% | 0.4675 | 45/200 | 43.4s | $8.74 |
| 5 | GPT-5.5 | OpenAI | fixed harness | 20.0% | 0.3384 | 40/200 | 177.6s | $53.83 |
| 6 | Grok Build 0.1 | xAI | prior baseline | 19.0% | 0.3315 | 38/200 | 117.1s | $10.87 |
| 7 | GPT-5.4 | OpenAI | prior baseline | 18.5% | 0.4075 | 37/200 | 7.3s | $4.81 |
| 8 | Qwen 3.7 Plus | Qwen | prior baseline | 16.5% | 0.2918 | 33/200 | 260.2s | $6.59 |
| 9 | Claude Opus 4.6 | Anthropic | prior baseline | 16.0% | 0.4038 | 32/200 | 19.6s | $10.17 |
| 10 | GPT-5.2 | OpenAI | prior baseline | 15.0% | 0.3223 | 30/200 | 75.2s | $11.30 |
| 11 | Grok 4.3 | xAI | prior baseline | 12.0% | 0.2568 | 24/200 | 7.1s | $4.00 |
| 12 | GPT-5.4 Mini | OpenAI | prior baseline | 12.0% | 0.2278 | 24/200 | 2.9s | $4.12 |
| 13 | Nemotron 3 Ultra 550B | NVIDIA | prior baseline | 12.0% | 0.2065 | 24/200 | 19.9s | $5.08 |
| 14 | DeepSeek V4 Pro | DeepSeek | prior baseline | 11.5% | 0.2295 | 23/200 | 57.7s | $4.60 |
| 15 | GLM 5.1 | Z.AI | prior baseline | 11.0% | 0.1338 | 22/200 | 175.6s | $5.04 |
| 16 | Claude Sonnet 4.6 | Anthropic | prior baseline | 10.5% | 0.3220 | 21/200 | 16.0s | $6.87 |
| 17 | Kimi K2.5 | Moonshot AI | fixed harness | 10.0% | 0.3006 | 20/200 | 123.8s | $12.78 |
| 18 | DeepSeek V4 Flash | DeepSeek | prior baseline | 10.0% | 0.2260 | 20/200 | 26.1s | $3.71 |
| 19 | MiniMax M3 | MiniMax | prior baseline | 9.5% | 0.1653 | 19/200 | 58.3s | $2.91 |
| 20 | Gemini 3 Flash | Google | prior baseline | 7.5% | 0.3180 | 15/200 | 5.1s | $3.13 |
| 21 | GLM 5 | Z.AI | prior baseline | 7.0% | 0.2490 | 14/200 | 91.9s | $4.26 |
| 22 | Mistral Medium 3.5 | Mistral AI | prior baseline | 7.0% | 0.1608 | 14/200 | 12.0s | $4.64 |
| 23 | Kimi K2.6 | Moonshot AI | prior baseline | 7.0% | 0.0817 | 14/200 | 176.0s | $4.89 |
| 24 | Grok 4.1 Fast | xAI | prior baseline | 5.5% | 0.2725 | 11/200 | 61.1s | $3.46 |
| 25 | GPT-5 Mini | OpenAI | prior baseline | 5.0% | 0.2747 | 10/200 | 25.4s | $3.63 |
| 26 | MiniMax M2.7 | MiniMax | fixed harness | 5.0% | 0.1318 | 10/200 | 48.4s | $9.25 |
| 27 | DeepSeek V3.2 | DeepSeek | prior baseline | 4.5% | 0.2527 | 9/200 | 78.7s | $3.25 |
| 28 | Qwen 3.5 27B | Qwen | new fixed harness | 4.5% | 0.1815 | 9/200 | 123.0s | $12.34 |
| 29 | Gemini 3.5 Flash | Google | prior baseline | 4.5% | 0.0470 | 9/200 | 23.6s | $10.33 |
| 30 | Kimi K2.7 Code | Moonshot AI | new fixed harness | 4.0% | 0.0670 | 8/200 | 172.5s | $8.33 |
| 31 | Claude Haiku 4.5 | Anthropic | prior baseline | 3.5% | 0.2633 | 7/200 | 7.0s | $3.95 |
| 32 | Qwen 3.5 35B A3B | Qwen | new fixed harness | 2.5% | 0.1680 | 5/200 | 11.0s | $9.42 |
| 33 | Gemini 3.1 Pro | Google | prior baseline | 2.5% | 0.0927 | 5/200 | 44.4s | $9.60 |
| 34 | MiniMax M2.5 | MiniMax | prior baseline | 1.5% | 0.1813 | 3/200 | 45.0s | $3.25 |
| 35 | Step 3.7 Flash | StepFun | prior baseline | 1.5% | 0.0178 | 3/200 | 44.9s | $1.12 |
| 36 | Step 3.5 Flash | StepFun | prior baseline | 0.0% | 0.0000 | 0/200 | 44.0s | $0.00 |

## Kept Despite Fixed-Rerun Changes

| Model | Prior Passed | Fixed Passed | Pass Delta | Prior Score | Fixed Score | Score Delta | Reason |
|---|---:|---:|---:|---:|---:|---:|---|
| Kimi K2.6 | 14/200 | 13/200 | -1 | 0.0817 | 0.1199 | +0.0382 | score improved but pass count did not materially improve |
| GLM 5.1 | 22/200 | 15/200 | -7 | 0.1338 | 0.1651 | +0.0313 | score improved but pass count did not materially improve |
| DeepSeek V4 Pro | 23/200 | 12/200 | -11 | 0.2295 | 0.2498 | +0.0203 | score improved but pass count did not materially improve |
| Step 3.7 Flash | 3/200 | 3/200 | +0 | 0.0178 | 0.0267 | +0.0089 | score improved but pass count did not materially improve |
| Step 3.5 Flash | 0/200 | 0/200 | +0 | 0.0000 | 0.0065 | +0.0065 | score improved but pass count did not materially improve |
| GPT-5.3 Codex | 45/200 | 48/200 | +3 | 0.4675 | 0.4440 | -0.0235 | pass count improved but score did not materially improve |
| Claude Sonnet 4.6 | 21/200 | 23/200 | +2 | 0.3220 | 0.2917 | -0.0303 | pass count improved but score did not materially improve |
| Qwen 3.7 Plus | 33/200 | 20/200 | -13 | 0.2918 | 0.2325 | -0.0593 | fixed rerun regressed or changed ambiguously |
| DeepSeek V3.2 | 9/200 | 15/200 | +6 | 0.2527 | 0.1889 | -0.0638 | pass count improved but score did not materially improve |
| Gemini 3.1 Pro | 5/200 | 0/200 | -5 | 0.0927 | 0.0000 | -0.0927 | fixed rerun regressed or changed ambiguously |
| MiniMax M3 | 19/200 | 0/200 | -19 | 0.1653 | 0.0000 | -0.1653 | fixed rerun regressed or changed ambiguously |
| MiniMax M2.5 | 3/200 | 0/200 | -3 | 0.1813 | 0.0000 | -0.1813 | fixed rerun regressed or changed ambiguously |
| GLM 5 | 14/200 | 0/200 | -14 | 0.2490 | 0.0000 | -0.2490 | fixed rerun regressed or changed ambiguously |
| Grok 4.1 Fast | 11/200 | 0/200 | -11 | 0.2725 | 0.0000 | -0.2725 | fixed rerun regressed or changed ambiguously |
| Gemini 3 Flash | 15/200 | 0/200 | -15 | 0.3180 | 0.0000 | -0.3180 | fixed rerun regressed or changed ambiguously |
| GPT-5.2 | 30/200 | 0/200 | -30 | 0.3223 | 0.0000 | -0.3223 | fixed rerun regressed or changed ambiguously |
| Qwen 3.7 Max | 57/200 | 5/200 | -52 | 0.4027 | 0.0354 | -0.3673 | fixed rerun regressed or changed ambiguously |
| Claude Opus 4.6 | 32/200 | 0/200 | -32 | 0.4038 | 0.0000 | -0.4038 | fixed rerun regressed or changed ambiguously |
| Claude Fable 5 | 75/200 | 0/200 | -75 | 0.4427 | 0.0000 | -0.4427 | fixed rerun regressed or changed ambiguously |

## Artifacts

- Merged JSON manifest: `results/merged_harness_fix_20260620/merged_leaderboard.json`
- Merge decisions: `results/merged_harness_fix_20260620/merge_decisions.json`
- Selected per-model reports: `results/merged_harness_fix_20260620/best3_*.json`
- Fixed rerun source: `results/rerun_fixes_2judge_20260613_232410`
