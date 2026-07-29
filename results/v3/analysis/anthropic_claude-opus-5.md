# anthropic/claude-opus-5 — VulnBench performance analysis

*Runs: 1 · Judges: openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hint mode: description · source context: True · max_tokens: 16384*

## Why this model performed the way it did

anthropic/claude-opus-5 passed 121/200 instances (60.5%, 95% CI 53.6%–67.0%) with a mean judge score of 0.638.

Of the 79 failed instances in the reference run: 29 (37%) because the patch modifies files unrelated to the ground-truth fix; 16 (20%) because the judge scored the patch just below the pass threshold; 13 (16%) because the model understood the issue but the fix was judged inadequate.

In total, 6 failures (3%) were harness or provider artifacts (API errors, empty responses, exhausted budgets) rather than judged model mistakes. Under the v2 quality gate, rows above 2% artifacts are not publishable.

Relative strengths: cve year 2018: 86% vs suite median 14% (n=7); ecosystem maven: 80% vs suite median 20% (n=5); ecosystem pip: 70% vs suite median 20% (n=54); cve year 2024: 67% vs suite median 19% (n=48); primary cwe CWE-20: 70% vs suite median 22% (n=23).

Cost: $42.87 total generation spend, $0.35 per passing patch, median generation time 62s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| wrong_file | 29 | the patch modifies files unrelated to the ground-truth fix |
| near_miss | 16 | the judge scored the patch just below the pass threshold |
| insufficient_fix | 13 | the model understood the issue but the fix was judged inadequate |
| likely_truncated | 8 | the diff appears cut off by the completion token limit |
| adapter_error | 6 | the provider/API call failed after retries (not a model capability signal) |
| off_target | 5 | the patch was judged irrelevant to the vulnerability |
| not_a_diff | 2 | the model responded with prose or code instead of a unified diff |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 73 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 38 | 56.7% | 44.8%–67.9% |
| tier_2 | 67 | 40 | 59.7% | 47.7%–70.6% |
| tier_3 | 66 | 43 | 65.1% | 53.1%–75.5% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 2 | 66.7% | 20.8%–93.8% |
| CWE-1321 | 5 | 4 | 80.0% | 37.5%–96.4% |
| CWE-1333 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-20 | 23 | 16 | 69.6% | 49.1%–84.4% |
| CWE-200 | 4 | 2 | 50.0% | 15.0%–85.0% |
| CWE-22 | 25 | 15 | 60.0% | 40.7%–76.6% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-287 | 3 | 2 | 66.7% | 20.8%–93.8% |
| CWE-290 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-295 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-325 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-330 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-347 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-352 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-367 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-384 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-400 | 25 | 14 | 56.0% | 37.1%–73.3% |
| CWE-402 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-434 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-444 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-470 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-476 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-506 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-532 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-601 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-668 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-670 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-674 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-680 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-693 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-696 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-73 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-74 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-755 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-77 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-770 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-78 | 3 | 2 | 66.7% | 20.8%–93.8% |
| CWE-79 | 38 | 21 | 55.3% | 39.7%–69.8% |
| CWE-830 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-862 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-863 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-89 | 4 | 2 | 50.0% | 15.0%–85.0% |
| CWE-918 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-94 | 18 | 13 | 72.2% | 49.1%–87.5% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 1 | 50.0% | 9.4%–90.5% |
| maven | 5 | 4 | 80.0% | 37.5%–96.4% |
| npm | 134 | 76 | 56.7% | 48.3%–64.8% |
| pip | 54 | 38 | 70.4% | 57.2%–80.9% |
| rubygems | 3 | 1 | 33.3% | 6.2%–79.2% |
| rust | 1 | 1 | 100.0% | 20.6%–100.0% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 10 | 47.6% | 28.3%–67.6% |
| high | 42 | 27 | 64.3% | 49.2%–77.0% |
| medium | 137 | 84 | 61.3% | 53.0%–69.0% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 1 | 100.0% | 20.6%–100.0% |
| 2016 | 2 | 1 | 50.0% | 9.4%–90.5% |
| 2017 | 3 | 2 | 66.7% | 20.8%–93.8% |
| 2018 | 7 | 6 | 85.7% | 48.7%–97.4% |
| 2019 | 7 | 2 | 28.6% | 8.2%–64.1% |
| 2020 | 6 | 2 | 33.3% | 9.7%–70.0% |
| 2021 | 5 | 3 | 60.0% | 23.1%–88.2% |
| 2022 | 24 | 14 | 58.3% | 38.8%–75.5% |
| 2023 | 26 | 14 | 53.8% | 35.5%–71.2% |
| 2024 | 48 | 32 | 66.7% | 52.5%–78.3% |
| 2025 | 55 | 34 | 61.8% | 48.6%–73.5% |
| 2026 | 16 | 10 | 62.5% | 38.6%–81.5% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*