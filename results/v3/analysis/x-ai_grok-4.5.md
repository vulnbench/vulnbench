# x-ai/grok-4.5 — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hint mode: description · source context: True · max_tokens: 16384*

## Why this model performed the way it did

x-ai/grok-4.5 passed 48/200 instances (24.0%, 95% CI 18.6%–30.4%) with a mean judge score of 0.296.

Across 3 independent runs the pass rate was 23.5%, 18.0%, 24.0% (mean 21.8% ± 3.3%); 40.0% of instances passed in at least one run and 6.0% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 152 failed instances in the reference run: 88 (58%) because the model responded with prose or code instead of a unified diff; 23 (15%) because the patch modifies files unrelated to the ground-truth fix; 18 (12%) because the model understood the issue but the fix was judged inadequate.

The model produced a parseable diff on only 56% of instances (answer rate); capability comparisons against models with higher answer rates are confounded until this is resolved.

Relative strengths: severity critical: 52% vs suite median 19% (n=21); primary cwe CWE-94: 50% vs suite median 22% (n=18); ecosystem maven: 40% vs suite median 20% (n=5); cve year 2023: 35% vs suite median 15% (n=26); primary cwe CWE-20: 35% vs suite median 17% (n=23).

Relative weaknesses: cve year 2021: 20% vs suite median 40% (n=5).

Cost: $4.03 total generation spend, $0.08 per passing patch, median generation time 25s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| not_a_diff | 88 | the model responded with prose or code instead of a unified diff |
| wrong_file | 23 | the patch modifies files unrelated to the ground-truth fix |
| insufficient_fix | 18 | the model understood the issue but the fix was judged inadequate |
| near_miss | 12 | the judge scored the patch just below the pass threshold |
| off_target | 8 | the patch was judged irrelevant to the vulnerability |
| likely_truncated | 3 | the diff appears cut off by the completion token limit |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 152 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 13 | 19.4% | 11.7%–30.4% |
| tier_2 | 67 | 15 | 22.4% | 14.1%–33.7% |
| tier_3 | 66 | 20 | 30.3% | 20.5%–42.2% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 2 | 40.0% | 11.8%–76.9% |
| CWE-1333 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-20 | 23 | 8 | 34.8% | 18.8%–55.1% |
| CWE-200 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-22 | 25 | 4 | 16.0% | 6.4%–34.6% |
| CWE-23 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-287 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-290 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-295 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-325 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-330 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-347 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-352 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-367 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-384 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-400 | 25 | 3 | 12.0% | 4.2%–30.0% |
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
| CWE-674 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-680 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-693 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-696 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-73 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-74 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-755 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-77 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-770 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-78 | 3 | 2 | 66.7% | 20.8%–93.8% |
| CWE-79 | 38 | 9 | 23.7% | 13.0%–39.2% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-918 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-94 | 18 | 9 | 50.0% | 29.0%–71.0% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 1 | 50.0% | 9.4%–90.5% |
| maven | 5 | 2 | 40.0% | 11.8%–76.9% |
| npm | 134 | 33 | 24.6% | 18.1%–32.6% |
| pip | 54 | 12 | 22.2% | 13.2%–34.9% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 11 | 52.4% | 32.4%–71.7% |
| high | 42 | 7 | 16.7% | 8.3%–30.6% |
| medium | 137 | 30 | 21.9% | 15.8%–29.5% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 1 | 100.0% | 20.6%–100.0% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 1 | 33.3% | 6.2%–79.2% |
| 2018 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2019 | 7 | 2 | 28.6% | 8.2%–64.1% |
| 2020 | 6 | 1 | 16.7% | 3.0%–56.4% |
| 2021 | 5 | 1 | 20.0% | 3.6%–62.5% |
| 2022 | 24 | 4 | 16.7% | 6.7%–35.9% |
| 2023 | 26 | 9 | 34.6% | 19.4%–53.8% |
| 2024 | 48 | 8 | 16.7% | 8.7%–29.6% |
| 2025 | 55 | 16 | 29.1% | 18.8%–42.1% |
| 2026 | 16 | 4 | 25.0% | 10.2%–49.5% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*