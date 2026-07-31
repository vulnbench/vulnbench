# openai/gpt-5.6-luna — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hint mode: description · source context: True · max_tokens: 16384*

## Why this model performed the way it did

openai/gpt-5.6-luna passed 51/200 instances (25.5%, 95% CI 20.0%–32.0%) with a mean judge score of 0.404.

Across 3 independent runs the pass rate was 26.0%, 25.5%, 25.5% (mean 25.7% ± 0.3%); 36.5% of instances passed in at least one run and 14.5% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 149 failed instances in the reference run: 87 (58%) because the patch modifies files unrelated to the ground-truth fix; 35 (23%) because the model understood the issue but the fix was judged inadequate; 18 (12%) because the judge scored the patch just below the pass threshold.

Relative strengths: ecosystem maven: 40% vs suite median 20% (n=5); cve year 2021: 60% vs suite median 40% (n=5); primary cwe CWE-94: 39% vs suite median 22% (n=18); cve year 2020: 33% vs suite median 17% (n=6); cve year 2019: 29% vs suite median 14% (n=7).

Cost: $3.50 total generation spend, $0.07 per passing patch, median generation time 24s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| wrong_file | 87 | the patch modifies files unrelated to the ground-truth fix |
| insufficient_fix | 35 | the model understood the issue but the fix was judged inadequate |
| near_miss | 18 | the judge scored the patch just below the pass threshold |
| off_target | 8 | the patch was judged irrelevant to the vulnerability |
| not_a_diff | 1 | the model responded with prose or code instead of a unified diff |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 149 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 15 | 22.4% | 14.1%–33.7% |
| tier_2 | 67 | 18 | 26.9% | 17.7%–38.5% |
| tier_3 | 66 | 18 | 27.3% | 18.0%–39.0% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 2 | 40.0% | 11.8%–76.9% |
| CWE-1333 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-20 | 23 | 7 | 30.4% | 15.6%–50.9% |
| CWE-200 | 4 | 2 | 50.0% | 15.0%–85.0% |
| CWE-22 | 25 | 7 | 28.0% | 14.3%–47.6% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-287 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-290 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-295 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-325 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-330 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-347 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-352 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-367 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-384 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-400 | 25 | 4 | 16.0% | 6.4%–34.6% |
| CWE-402 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-434 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-444 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-470 | 1 | 0 | 0.0% | 0.0%–79.3% |
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
| CWE-770 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-78 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-79 | 38 | 8 | 21.1% | 11.1%–36.4% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-918 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-94 | 18 | 7 | 38.9% | 20.3%–61.4% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 1 | 50.0% | 9.4%–90.5% |
| maven | 5 | 2 | 40.0% | 11.8%–76.9% |
| npm | 134 | 32 | 23.9% | 17.4%–31.8% |
| pip | 54 | 15 | 27.8% | 17.6%–40.9% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 1 | 100.0% | 20.6%–100.0% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 6 | 28.6% | 13.8%–50.0% |
| high | 42 | 9 | 21.4% | 11.7%–35.9% |
| medium | 137 | 36 | 26.3% | 19.6%–34.2% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 0 | 0.0% | 0.0%–79.3% |
| 2016 | 2 | 1 | 50.0% | 9.4%–90.5% |
| 2017 | 3 | 1 | 33.3% | 6.2%–79.2% |
| 2018 | 7 | 2 | 28.6% | 8.2%–64.1% |
| 2019 | 7 | 2 | 28.6% | 8.2%–64.1% |
| 2020 | 6 | 2 | 33.3% | 9.7%–70.0% |
| 2021 | 5 | 3 | 60.0% | 23.1%–88.2% |
| 2022 | 24 | 3 | 12.5% | 4.3%–31.0% |
| 2023 | 26 | 3 | 11.5% | 4.0%–29.0% |
| 2024 | 48 | 13 | 27.1% | 16.6%–41.0% |
| 2025 | 55 | 17 | 30.9% | 20.3%–44.0% |
| 2026 | 16 | 4 | 25.0% | 10.2%–49.5% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*