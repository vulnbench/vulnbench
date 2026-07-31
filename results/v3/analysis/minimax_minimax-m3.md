# minimax/minimax-m3 — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hint mode: description · source context: True · max_tokens: 16384*

## Why this model performed the way it did

minimax/minimax-m3 passed 24/200 instances (12.0%, 95% CI 8.2%–17.2%) with a mean judge score of 0.229.

Across 3 independent runs the pass rate was 12.5%, 12.5%, 12.0% (mean 12.3% ± 0.3%); 21.0% of instances passed in at least one run and 4.5% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 176 failed instances in the reference run: 92 (52%) because the patch modifies files unrelated to the ground-truth fix; 32 (18%) because the patch was judged irrelevant to the vulnerability; 23 (13%) because the diff appears cut off by the completion token limit.

Relative weaknesses: cve year 2021: 20% vs suite median 40% (n=5); cve year 2018: 0% vs suite median 14% (n=7); cve year 2019: 0% vs suite median 14% (n=7); cve year 2023: 4% vs suite median 15% (n=26); ecosystem pip: 9% vs suite median 20% (n=54).

Cost: $1.23 total generation spend, $0.05 per passing patch, median generation time 23s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| wrong_file | 92 | the patch modifies files unrelated to the ground-truth fix |
| off_target | 32 | the patch was judged irrelevant to the vulnerability |
| likely_truncated | 23 | the diff appears cut off by the completion token limit |
| insufficient_fix | 18 | the model understood the issue but the fix was judged inadequate |
| near_miss | 7 | the judge scored the patch just below the pass threshold |
| not_a_diff | 4 | the model responded with prose or code instead of a unified diff |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 176 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 9 | 13.4% | 7.2%–23.6% |
| tier_2 | 67 | 8 | 11.9% | 6.2%–21.8% |
| tier_3 | 66 | 7 | 10.6% | 5.2%–20.3% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 2 | 40.0% | 11.8%–76.9% |
| CWE-1333 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-20 | 23 | 2 | 8.7% | 2.4%–26.8% |
| CWE-200 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-22 | 25 | 4 | 16.0% | 6.4%–34.6% |
| CWE-23 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-287 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-290 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-295 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-325 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-330 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-347 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-352 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-367 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-384 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-400 | 25 | 1 | 4.0% | 0.7%–19.5% |
| CWE-402 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-434 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-444 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-470 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-476 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-506 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-532 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-601 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-668 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-670 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-674 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-680 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-693 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-696 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-73 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-74 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-755 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-77 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-770 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-78 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-79 | 38 | 5 | 13.2% | 5.8%–27.3% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-918 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-94 | 18 | 4 | 22.2% | 9.0%–45.2% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 0 | 0.0% | 0.0%–65.8% |
| maven | 5 | 1 | 20.0% | 3.6%–62.5% |
| npm | 134 | 18 | 13.4% | 8.7%–20.2% |
| pip | 54 | 5 | 9.3% | 4.0%–19.9% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 4 | 19.1% | 7.7%–40.0% |
| high | 42 | 7 | 16.7% | 8.3%–30.6% |
| medium | 137 | 13 | 9.5% | 5.6%–15.6% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 1 | 100.0% | 20.6%–100.0% |
| 2016 | 2 | 1 | 50.0% | 9.4%–90.5% |
| 2017 | 3 | 1 | 33.3% | 6.2%–79.2% |
| 2018 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2019 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2020 | 6 | 1 | 16.7% | 3.0%–56.4% |
| 2021 | 5 | 1 | 20.0% | 3.6%–62.5% |
| 2022 | 24 | 1 | 4.2% | 0.7%–20.2% |
| 2023 | 26 | 1 | 3.9% | 0.7%–18.9% |
| 2024 | 48 | 6 | 12.5% | 5.9%–24.7% |
| 2025 | 55 | 9 | 16.4% | 8.9%–28.3% |
| 2026 | 16 | 2 | 12.5% | 3.5%–36.0% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*