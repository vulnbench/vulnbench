# google/gemini-3.5-flash — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hint mode: description · source context: True · max_tokens: 16384*

## Why this model performed the way it did

google/gemini-3.5-flash passed 59/200 instances (29.5%, 95% CI 23.6%–36.2%) with a mean judge score of 0.376.

Across 3 independent runs the pass rate was 29.5%, 26.5%, 29.5% (mean 28.5% ± 1.7%); 41.0% of instances passed in at least one run and 16.5% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 141 failed instances in the reference run: 39 (28%) because the patch modifies files unrelated to the ground-truth fix; 36 (26%) because the model responded with prose or code instead of a unified diff; 22 (16%) because the diff appears cut off by the completion token limit.

The model produced a parseable diff on only 82% of instances (answer rate); capability comparisons against models with higher answer rates are confounded until this is resolved.

Relative strengths: primary cwe CWE-94: 44% vs suite median 22% (n=18); primary cwe CWE-79: 34% vs suite median 16% (n=38); cve year 2022: 29% vs suite median 12% (n=24); cve year 2020: 33% vs suite median 17% (n=6); cve year 2024: 31% vs suite median 17% (n=48).

Cost: $19.00 total generation spend, $0.32 per passing patch, median generation time 53s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| wrong_file | 39 | the patch modifies files unrelated to the ground-truth fix |
| not_a_diff | 36 | the model responded with prose or code instead of a unified diff |
| likely_truncated | 22 | the diff appears cut off by the completion token limit |
| near_miss | 18 | the judge scored the patch just below the pass threshold |
| insufficient_fix | 18 | the model understood the issue but the fix was judged inadequate |
| off_target | 8 | the patch was judged irrelevant to the vulnerability |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 141 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 22 | 32.8% | 22.8%–44.7% |
| tier_2 | 67 | 17 | 25.4% | 16.5%–36.9% |
| tier_3 | 66 | 20 | 30.3% | 20.5%–42.2% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 2 | 40.0% | 11.8%–76.9% |
| CWE-1333 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-20 | 23 | 7 | 30.4% | 15.6%–50.9% |
| CWE-200 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-22 | 25 | 8 | 32.0% | 17.2%–51.6% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-287 | 3 | 3 | 100.0% | 43.9%–100.0% |
| CWE-290 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-295 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-325 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-330 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-347 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-352 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-367 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-384 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-400 | 25 | 5 | 20.0% | 8.9%–39.1% |
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
| CWE-78 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-79 | 38 | 13 | 34.2% | 21.2%–50.1% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-918 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-94 | 18 | 8 | 44.4% | 24.6%–66.3% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 0 | 0.0% | 0.0%–65.8% |
| maven | 5 | 1 | 20.0% | 3.6%–62.5% |
| npm | 134 | 44 | 32.8% | 25.5%–41.2% |
| pip | 54 | 13 | 24.1% | 14.6%–37.0% |
| rubygems | 3 | 1 | 33.3% | 6.2%–79.2% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 4 | 19.1% | 7.7%–40.0% |
| high | 42 | 15 | 35.7% | 23.0%–50.8% |
| medium | 137 | 40 | 29.2% | 22.2%–37.3% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 1 | 100.0% | 20.6%–100.0% |
| 2016 | 2 | 1 | 50.0% | 9.4%–90.5% |
| 2017 | 3 | 0 | 0.0% | 0.0%–56.1% |
| 2018 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2019 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2020 | 6 | 2 | 33.3% | 9.7%–70.0% |
| 2021 | 5 | 2 | 40.0% | 11.8%–76.9% |
| 2022 | 24 | 7 | 29.2% | 14.9%–49.2% |
| 2023 | 26 | 6 | 23.1% | 11.0%–42.0% |
| 2024 | 48 | 15 | 31.2% | 20.0%–45.3% |
| 2025 | 55 | 18 | 32.7% | 21.8%–45.9% |
| 2026 | 16 | 5 | 31.2% | 14.2%–55.6% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*