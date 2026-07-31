# openai/gpt-5.5 — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hint mode: description · source context: True · max_tokens: 16384*

## Why this model performed the way it did

openai/gpt-5.5 passed 71/200 instances (35.5%, 95% CI 29.2%–42.4%) with a mean judge score of 0.570.

Across 3 independent runs the pass rate was 28.0%, 33.0%, 35.5% (mean 32.2% ± 3.8%); 53.0% of instances passed in at least one run and 14.0% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 129 failed instances in the reference run: 69 (53%) because the patch modifies files unrelated to the ground-truth fix; 33 (26%) because the judge scored the patch just below the pass threshold; 14 (11%) because the model understood the issue but the fix was judged inadequate.

Relative strengths: cve year 2019: 43% vs suite median 14% (n=7); cve year 2024: 40% vs suite median 17% (n=48); primary cwe CWE-79: 37% vs suite median 16% (n=38); ecosystem maven: 40% vs suite median 20% (n=5); primary cwe CWE-1321: 60% vs suite median 40% (n=5).

Cost: $28.93 total generation spend, $0.41 per passing patch, median generation time 64s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| wrong_file | 69 | the patch modifies files unrelated to the ground-truth fix |
| near_miss | 33 | the judge scored the patch just below the pass threshold |
| insufficient_fix | 14 | the model understood the issue but the fix was judged inadequate |
| off_target | 13 | the patch was judged irrelevant to the vulnerability |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 129 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 25 | 37.3% | 26.7%–49.3% |
| tier_2 | 67 | 26 | 38.8% | 28.1%–50.8% |
| tier_3 | 66 | 20 | 30.3% | 20.5%–42.2% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 3 | 60.0% | 23.1%–88.2% |
| CWE-1333 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-20 | 23 | 8 | 34.8% | 18.8%–55.1% |
| CWE-200 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-22 | 25 | 9 | 36.0% | 20.2%–55.5% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-235 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-287 | 3 | 2 | 66.7% | 20.8%–93.8% |
| CWE-290 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-295 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-325 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-330 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-347 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-352 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-367 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-384 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-400 | 25 | 5 | 20.0% | 8.9%–39.1% |
| CWE-402 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-434 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-444 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-470 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-476 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-506 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-532 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-601 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-668 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-670 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-674 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-680 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-693 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-696 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-73 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-74 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-755 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-77 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-770 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-78 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-79 | 38 | 14 | 36.8% | 23.4%–52.7% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 2 | 50.0% | 15.0%–85.0% |
| CWE-918 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-94 | 18 | 7 | 38.9% | 20.3%–61.4% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 1 | 50.0% | 9.4%–90.5% |
| maven | 5 | 2 | 40.0% | 11.8%–76.9% |
| npm | 134 | 49 | 36.6% | 28.9%–45.0% |
| pip | 54 | 17 | 31.5% | 20.7%–44.7% |
| rubygems | 3 | 1 | 33.3% | 6.2%–79.2% |
| rust | 1 | 1 | 100.0% | 20.6%–100.0% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 8 | 38.1% | 20.8%–59.1% |
| high | 42 | 15 | 35.7% | 23.0%–50.8% |
| medium | 137 | 48 | 35.0% | 27.6%–43.3% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 0 | 0.0% | 0.0%–79.3% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 1 | 33.3% | 6.2%–79.2% |
| 2018 | 7 | 2 | 28.6% | 8.2%–64.1% |
| 2019 | 7 | 3 | 42.9% | 15.8%–75.0% |
| 2020 | 6 | 1 | 16.7% | 3.0%–56.4% |
| 2021 | 5 | 2 | 40.0% | 11.8%–76.9% |
| 2022 | 24 | 7 | 29.2% | 14.9%–49.2% |
| 2023 | 26 | 6 | 23.1% | 11.0%–42.0% |
| 2024 | 48 | 19 | 39.6% | 27.0%–53.7% |
| 2025 | 55 | 24 | 43.6% | 31.4%–56.7% |
| 2026 | 16 | 6 | 37.5% | 18.5%–61.4% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*