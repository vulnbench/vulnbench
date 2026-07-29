# openai/gpt-5.6-sol — VulnBench performance analysis

*Runs: 1 · Judges: openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hint mode: description · source context: True · max_tokens: 16384*

## Why this model performed the way it did

openai/gpt-5.6-sol passed 87/200 instances (43.5%, 95% CI 36.8%–50.4%) with a mean judge score of 0.505.

Of the 113 failed instances in the reference run: 51 (45%) because the patch modifies files unrelated to the ground-truth fix; 31 (27%) because the model understood the issue but the fix was judged inadequate; 15 (13%) because the judge scored the patch just below the pass threshold.

Relative strengths: cve year 2020: 67% vs suite median 17% (n=6); cve year 2021: 80% vs suite median 40% (n=5); ecosystem maven: 60% vs suite median 20% (n=5); severity critical: 52% vs suite median 19% (n=21); primary cwe CWE-94: 61% vs suite median 28% (n=18).

Cost: $21.96 total generation spend, $0.25 per passing patch, median generation time 61s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| wrong_file | 51 | the patch modifies files unrelated to the ground-truth fix |
| insufficient_fix | 31 | the model understood the issue but the fix was judged inadequate |
| near_miss | 15 | the judge scored the patch just below the pass threshold |
| off_target | 15 | the patch was judged irrelevant to the vulnerability |
| not_a_diff | 1 | the model responded with prose or code instead of a unified diff |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 113 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 27 | 40.3% | 29.4%–52.3% |
| tier_2 | 67 | 31 | 46.3% | 34.9%–58.1% |
| tier_3 | 66 | 29 | 43.9% | 32.6%–55.9% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 3 | 60.0% | 23.1%–88.2% |
| CWE-1333 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-20 | 23 | 9 | 39.1% | 22.2%–59.2% |
| CWE-200 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-22 | 25 | 11 | 44.0% | 26.7%–62.9% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-287 | 3 | 3 | 100.0% | 43.9%–100.0% |
| CWE-290 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-295 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-325 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-330 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-347 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-352 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-367 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-384 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-400 | 25 | 9 | 36.0% | 20.2%–55.5% |
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
| CWE-696 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-73 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-74 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-755 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-77 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-770 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-78 | 3 | 2 | 66.7% | 20.8%–93.8% |
| CWE-79 | 38 | 16 | 42.1% | 27.9%–57.8% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-918 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-94 | 18 | 11 | 61.1% | 38.6%–79.7% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 2 | 100.0% | 34.2%–100.0% |
| maven | 5 | 3 | 60.0% | 23.1%–88.2% |
| npm | 134 | 58 | 43.3% | 35.2%–51.7% |
| pip | 54 | 22 | 40.7% | 28.7%–54.0% |
| rubygems | 3 | 1 | 33.3% | 6.2%–79.2% |
| rust | 1 | 1 | 100.0% | 20.6%–100.0% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 11 | 52.4% | 32.4%–71.7% |
| high | 42 | 18 | 42.9% | 29.1%–57.8% |
| medium | 137 | 58 | 42.3% | 34.4%–50.7% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 1 | 100.0% | 20.6%–100.0% |
| 2016 | 2 | 1 | 50.0% | 9.4%–90.5% |
| 2017 | 3 | 2 | 66.7% | 20.8%–93.8% |
| 2018 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2019 | 7 | 2 | 28.6% | 8.2%–64.1% |
| 2020 | 6 | 4 | 66.7% | 30.0%–90.3% |
| 2021 | 5 | 4 | 80.0% | 37.5%–96.4% |
| 2022 | 24 | 8 | 33.3% | 18.0%–53.3% |
| 2023 | 26 | 8 | 30.8% | 16.5%–50.0% |
| 2024 | 48 | 20 | 41.7% | 28.8%–55.7% |
| 2025 | 55 | 30 | 54.5% | 41.5%–67.0% |
| 2026 | 16 | 6 | 37.5% | 18.5%–61.4% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*