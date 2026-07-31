# google/gemini-3.1-pro-preview — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hint mode: description · source context: True · max_tokens: 16384*

## Why this model performed the way it did

google/gemini-3.1-pro-preview passed 67/200 instances (33.5%, 95% CI 27.3%–40.3%) with a mean judge score of 0.430.

Across 3 independent runs the pass rate was 29.0%, 31.0%, 33.5% (mean 31.2% ± 2.2%); 45.0% of instances passed in at least one run and 17.0% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 133 failed instances in the reference run: 44 (33%) because the diff appears cut off by the completion token limit; 25 (19%) because the model understood the issue but the fix was judged inadequate; 22 (17%) because the patch modifies files unrelated to the ground-truth fix.

Relative strengths: primary cwe CWE-1321: 80% vs suite median 40% (n=5); cve year 2021: 80% vs suite median 40% (n=5); primary cwe CWE-20: 43% vs suite median 17% (n=23); primary cwe CWE-79: 37% vs suite median 16% (n=38); cve year 2022: 33% vs suite median 12% (n=24).

Cost: $36.13 total generation spend, $0.54 per passing patch, median generation time 74s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| likely_truncated | 44 | the diff appears cut off by the completion token limit |
| insufficient_fix | 25 | the model understood the issue but the fix was judged inadequate |
| wrong_file | 22 | the patch modifies files unrelated to the ground-truth fix |
| near_miss | 21 | the judge scored the patch just below the pass threshold |
| off_target | 13 | the patch was judged irrelevant to the vulnerability |
| not_a_diff | 8 | the model responded with prose or code instead of a unified diff |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 133 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 21 | 31.3% | 21.5%–43.2% |
| tier_2 | 67 | 23 | 34.3% | 24.1%–46.3% |
| tier_3 | 66 | 23 | 34.8% | 24.5%–46.9% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 2 | 66.7% | 20.8%–93.8% |
| CWE-1321 | 5 | 4 | 80.0% | 37.5%–96.4% |
| CWE-1333 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-20 | 23 | 10 | 43.5% | 25.6%–63.2% |
| CWE-200 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-22 | 25 | 7 | 28.0% | 14.3%–47.6% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-287 | 3 | 2 | 66.7% | 20.8%–93.8% |
| CWE-290 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-295 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-325 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-330 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-347 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-352 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-367 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-384 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-400 | 25 | 7 | 28.0% | 14.3%–47.6% |
| CWE-402 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-434 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-444 | 1 | 1 | 100.0% | 20.6%–100.0% |
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
| CWE-74 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-755 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-77 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-770 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-78 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-79 | 38 | 14 | 36.8% | 23.4%–52.7% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-918 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-94 | 18 | 6 | 33.3% | 16.3%–56.2% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 1 | 50.0% | 9.4%–90.5% |
| maven | 5 | 1 | 20.0% | 3.6%–62.5% |
| npm | 134 | 51 | 38.1% | 30.3%–46.5% |
| pip | 54 | 12 | 22.2% | 13.2%–34.9% |
| rubygems | 3 | 2 | 66.7% | 20.8%–93.8% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 7 | 33.3% | 17.2%–54.6% |
| high | 42 | 15 | 35.7% | 23.0%–50.8% |
| medium | 137 | 45 | 32.9% | 25.5%–41.1% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 1 | 100.0% | 20.6%–100.0% |
| 2016 | 2 | 1 | 50.0% | 9.4%–90.5% |
| 2017 | 3 | 1 | 33.3% | 6.2%–79.2% |
| 2018 | 7 | 2 | 28.6% | 8.2%–64.1% |
| 2019 | 7 | 2 | 28.6% | 8.2%–64.1% |
| 2020 | 6 | 1 | 16.7% | 3.0%–56.4% |
| 2021 | 5 | 4 | 80.0% | 37.5%–96.4% |
| 2022 | 24 | 8 | 33.3% | 18.0%–53.3% |
| 2023 | 26 | 6 | 23.1% | 11.0%–42.0% |
| 2024 | 48 | 15 | 31.2% | 20.0%–45.3% |
| 2025 | 55 | 23 | 41.8% | 29.7%–55.0% |
| 2026 | 16 | 3 | 18.8% | 6.6%–43.0% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*