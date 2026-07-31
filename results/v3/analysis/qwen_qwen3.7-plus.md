# qwen/qwen3.7-plus — VulnBench performance analysis

*Runs: 1 · Judges: openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hint mode: description · source context: True · max_tokens: 16384*

## Why this model performed the way it did

qwen/qwen3.7-plus passed 41/200 instances (20.5%, 95% CI 15.5%–26.6%) with a mean judge score of 0.290.

Of the 159 failed instances in the reference run: 40 (25%) because the patch modifies files unrelated to the ground-truth fix; 37 (23%) because the provider/API call failed after retries (not a model capability signal); 30 (19%) because the diff appears cut off by the completion token limit.

In total, 37 failures (18%) were harness or provider artifacts (API errors, empty responses, exhausted budgets) rather than judged model mistakes. Under the v2 quality gate, rows above 2% artifacts are not publishable.

The model produced a parseable diff on only 72% of instances (answer rate); capability comparisons against models with higher answer rates are confounded until this is resolved.

Relative strengths: cve year 2021: 60% vs suite median 40% (n=5); primary cwe CWE-20: 39% vs suite median 22% (n=23); cve year 2020: 33% vs suite median 17% (n=6); cve year 2018: 29% vs suite median 14% (n=7); primary cwe CWE-94: 33% vs suite median 22% (n=18).

Relative weaknesses: ecosystem maven: 0% vs suite median 20% (n=5).

Cost: $2.40 total generation spend, $0.06 per passing patch, median generation time 202s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| wrong_file | 40 | the patch modifies files unrelated to the ground-truth fix |
| adapter_error | 37 | the provider/API call failed after retries (not a model capability signal) |
| likely_truncated | 30 | the diff appears cut off by the completion token limit |
| not_a_diff | 18 | the model responded with prose or code instead of a unified diff |
| insufficient_fix | 15 | the model understood the issue but the fix was judged inadequate |
| near_miss | 12 | the judge scored the patch just below the pass threshold |
| off_target | 7 | the patch was judged irrelevant to the vulnerability |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 122 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 11 | 16.4% | 9.4%–27.1% |
| tier_2 | 67 | 13 | 19.4% | 11.7%–30.4% |
| tier_3 | 66 | 17 | 25.8% | 16.8%–37.4% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 2 | 40.0% | 11.8%–76.9% |
| CWE-1333 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-20 | 23 | 9 | 39.1% | 22.2%–59.2% |
| CWE-200 | 4 | 2 | 50.0% | 15.0%–85.0% |
| CWE-22 | 25 | 6 | 24.0% | 11.5%–43.4% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-287 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-290 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-295 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-325 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-330 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-347 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-352 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-367 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-384 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-400 | 25 | 2 | 8.0% | 2.2%–25.0% |
| CWE-402 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-434 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-444 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-470 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-476 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-506 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-532 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-601 | 2 | 0 | 0.0% | 0.0%–65.8% |
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
| CWE-79 | 38 | 5 | 13.2% | 5.8%–27.3% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-918 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-94 | 18 | 6 | 33.3% | 16.3%–56.2% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 1 | 50.0% | 9.4%–90.5% |
| maven | 5 | 0 | 0.0% | 0.0%–43.5% |
| npm | 134 | 29 | 21.6% | 15.5%–29.3% |
| pip | 54 | 10 | 18.5% | 10.4%–30.8% |
| rubygems | 3 | 1 | 33.3% | 6.2%–79.2% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 5 | 23.8% | 10.6%–45.1% |
| high | 42 | 13 | 30.9% | 19.1%–46.0% |
| medium | 137 | 23 | 16.8% | 11.5%–23.9% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 1 | 100.0% | 20.6%–100.0% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 0 | 0.0% | 0.0%–56.1% |
| 2018 | 7 | 2 | 28.6% | 8.2%–64.1% |
| 2019 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2020 | 6 | 2 | 33.3% | 9.7%–70.0% |
| 2021 | 5 | 3 | 60.0% | 23.1%–88.2% |
| 2022 | 24 | 1 | 4.2% | 0.7%–20.2% |
| 2023 | 26 | 3 | 11.5% | 4.0%–29.0% |
| 2024 | 48 | 7 | 14.6% | 7.2%–27.2% |
| 2025 | 55 | 18 | 32.7% | 21.8%–45.9% |
| 2026 | 16 | 3 | 18.8% | 6.6%–43.0% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*