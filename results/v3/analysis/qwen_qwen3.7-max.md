# qwen/qwen3.7-max — VulnBench performance analysis

*Runs: 1 · Judges: openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hint mode: description · source context: True · max_tokens: 16384*

## Why this model performed the way it did

qwen/qwen3.7-max passed 51/200 instances (25.5%, 95% CI 20.0%–32.0%) with a mean judge score of 0.389.

Of the 149 failed instances in the reference run: 65 (44%) because the patch modifies files unrelated to the ground-truth fix; 24 (16%) because the model understood the issue but the fix was judged inadequate; 22 (15%) because the judge scored the patch just below the pass threshold.

In total, 8 failures (4%) were harness or provider artifacts (API errors, empty responses, exhausted budgets) rather than judged model mistakes. Under the v2 quality gate, rows above 2% artifacts are not publishable.

Relative strengths: cve year 2020: 33% vs suite median 17% (n=6); primary cwe CWE-20: 39% vs suite median 26% (n=23); cve year 2025: 42% vs suite median 31% (n=55).

Relative weaknesses: cve year 2021: 20% vs suite median 40% (n=5); primary cwe CWE-1321: 20% vs suite median 40% (n=5).

Cost: $7.22 total generation spend, $0.14 per passing patch, median generation time 113s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| wrong_file | 65 | the patch modifies files unrelated to the ground-truth fix |
| insufficient_fix | 24 | the model understood the issue but the fix was judged inadequate |
| near_miss | 22 | the judge scored the patch just below the pass threshold |
| likely_truncated | 17 | the diff appears cut off by the completion token limit |
| off_target | 12 | the patch was judged irrelevant to the vulnerability |
| adapter_error | 8 | the provider/API call failed after retries (not a model capability signal) |
| not_a_diff | 1 | the model responded with prose or code instead of a unified diff |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 141 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 16 | 23.9% | 15.3%–35.3% |
| tier_2 | 67 | 13 | 19.4% | 11.7%–30.4% |
| tier_3 | 66 | 22 | 33.3% | 23.2%–45.3% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 1 | 20.0% | 3.6%–62.5% |
| CWE-1333 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-20 | 23 | 9 | 39.1% | 22.2%–59.2% |
| CWE-200 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-22 | 25 | 6 | 24.0% | 11.5%–43.4% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-287 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-290 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-295 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-325 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-330 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-347 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-352 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-367 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-384 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-400 | 25 | 7 | 28.0% | 14.3%–47.6% |
| CWE-402 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-434 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-444 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-470 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-476 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-506 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-532 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-601 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-668 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-670 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-674 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-680 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-693 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-696 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-73 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-74 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-755 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-77 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-770 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-78 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-79 | 38 | 10 | 26.3% | 15.0%–42.0% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-918 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-94 | 18 | 6 | 33.3% | 16.3%–56.2% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 0 | 0.0% | 0.0%–65.8% |
| maven | 5 | 1 | 20.0% | 3.6%–62.5% |
| npm | 134 | 34 | 25.4% | 18.8%–33.4% |
| pip | 54 | 15 | 27.8% | 17.6%–40.9% |
| rubygems | 3 | 1 | 33.3% | 6.2%–79.2% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 6 | 28.6% | 13.8%–50.0% |
| high | 42 | 10 | 23.8% | 13.5%–38.5% |
| medium | 137 | 35 | 25.6% | 19.0%–33.5% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 1 | 100.0% | 20.6%–100.0% |
| 2016 | 2 | 1 | 50.0% | 9.4%–90.5% |
| 2017 | 3 | 0 | 0.0% | 0.0%–56.1% |
| 2018 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2019 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2020 | 6 | 2 | 33.3% | 9.7%–70.0% |
| 2021 | 5 | 1 | 20.0% | 3.6%–62.5% |
| 2022 | 24 | 5 | 20.8% | 9.2%–40.5% |
| 2023 | 26 | 4 | 15.4% | 6.2%–33.5% |
| 2024 | 48 | 9 | 18.8% | 10.2%–31.9% |
| 2025 | 55 | 23 | 41.8% | 29.7%–55.0% |
| 2026 | 16 | 3 | 18.8% | 6.6%–43.0% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*