# nvidia/nemotron-3-ultra-550b-a55b — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hint mode: description · source context: True · max_tokens: 16384*

## Why this model performed the way it did

nvidia/nemotron-3-ultra-550b-a55b passed 26/200 instances (13.0%, 95% CI 9.0%–18.4%) with a mean judge score of 0.243.

Across 3 independent runs the pass rate was 10.0%, 9.5%, 13.0% (mean 10.8% ± 1.9%); 19.5% of instances passed in at least one run and 3.5% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 174 failed instances in the reference run: 110 (63%) because the patch modifies files unrelated to the ground-truth fix; 25 (14%) because the model understood the issue but the fix was judged inadequate; 25 (14%) because the patch was judged irrelevant to the vulnerability.

Relative weaknesses: primary cwe CWE-1321: 0% vs suite median 40% (n=5); cve year 2021: 20% vs suite median 40% (n=5); ecosystem maven: 0% vs suite median 20% (n=5); cve year 2018: 0% vs suite median 14% (n=7); difficulty tier tier_2: 9% vs suite median 22% (n=67).

Cost: $1.80 total generation spend, $0.07 per passing patch, median generation time 20s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| wrong_file | 110 | the patch modifies files unrelated to the ground-truth fix |
| insufficient_fix | 25 | the model understood the issue but the fix was judged inadequate |
| off_target | 25 | the patch was judged irrelevant to the vulnerability |
| near_miss | 10 | the judge scored the patch just below the pass threshold |
| not_a_diff | 3 | the model responded with prose or code instead of a unified diff |
| likely_truncated | 1 | the diff appears cut off by the completion token limit |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 174 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 12 | 17.9% | 10.5%–28.7% |
| tier_2 | 67 | 6 | 9.0% | 4.2%–18.2% |
| tier_3 | 66 | 8 | 12.1% | 6.3%–22.1% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 0 | 0.0% | 0.0%–43.5% |
| CWE-1333 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-20 | 23 | 3 | 13.0% | 4.5%–32.1% |
| CWE-200 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-22 | 25 | 6 | 24.0% | 11.5%–43.4% |
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
| CWE-400 | 25 | 0 | 0.0% | 0.0%–13.3% |
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
| CWE-674 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-680 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-693 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-696 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-73 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-74 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-755 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-77 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-770 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-78 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-79 | 38 | 6 | 15.8% | 7.4%–30.4% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-918 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-94 | 18 | 5 | 27.8% | 12.5%–50.9% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 0 | 0.0% | 0.0%–65.8% |
| maven | 5 | 0 | 0.0% | 0.0%–43.5% |
| npm | 134 | 19 | 14.2% | 9.3%–21.1% |
| pip | 54 | 7 | 13.0% | 6.4%–24.4% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 3 | 14.3% | 5.0%–34.6% |
| high | 42 | 5 | 11.9% | 5.2%–25.0% |
| medium | 137 | 18 | 13.1% | 8.5%–19.8% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 1 | 100.0% | 20.6%–100.0% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 0 | 0.0% | 0.0%–56.1% |
| 2018 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2019 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2020 | 6 | 1 | 16.7% | 3.0%–56.4% |
| 2021 | 5 | 1 | 20.0% | 3.6%–62.5% |
| 2022 | 24 | 0 | 0.0% | 0.0%–13.8% |
| 2023 | 26 | 2 | 7.7% | 2.1%–24.1% |
| 2024 | 48 | 4 | 8.3% | 3.3%–19.6% |
| 2025 | 55 | 13 | 23.6% | 14.4%–36.4% |
| 2026 | 16 | 3 | 18.8% | 6.6%–43.0% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*