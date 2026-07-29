# openai/gpt-5.6-terra — VulnBench performance analysis

*Runs: 1 · Judges: openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hint mode: description · source context: True · max_tokens: 16384*

## Why this model performed the way it did

openai/gpt-5.6-terra passed 66/200 instances (33.0%, 95% CI 26.9%–39.8%) with a mean judge score of 0.457.

Of the 134 failed instances in the reference run: 71 (53%) because the patch modifies files unrelated to the ground-truth fix; 34 (25%) because the model understood the issue but the fix was judged inadequate; 17 (13%) because the judge scored the patch just below the pass threshold.

Relative strengths: cve year 2021: 80% vs suite median 40% (n=5); primary cwe CWE-94: 61% vs suite median 28% (n=18); cve year 2018: 43% vs suite median 14% (n=7); severity critical: 38% vs suite median 19% (n=21); cve year 2026: 38% vs suite median 19% (n=16).

Relative weaknesses: primary cwe CWE-1321: 20% vs suite median 40% (n=5).

Cost: $10.03 total generation spend, $0.15 per passing patch, median generation time 35s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| wrong_file | 71 | the patch modifies files unrelated to the ground-truth fix |
| insufficient_fix | 34 | the model understood the issue but the fix was judged inadequate |
| near_miss | 17 | the judge scored the patch just below the pass threshold |
| off_target | 11 | the patch was judged irrelevant to the vulnerability |
| not_a_diff | 1 | the model responded with prose or code instead of a unified diff |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 134 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 19 | 28.4% | 19.0%–40.1% |
| tier_2 | 67 | 20 | 29.8% | 20.2%–41.7% |
| tier_3 | 66 | 27 | 40.9% | 29.9%–52.9% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 1 | 20.0% | 3.6%–62.5% |
| CWE-1333 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-20 | 23 | 9 | 39.1% | 22.2%–59.2% |
| CWE-200 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-22 | 25 | 9 | 36.0% | 20.2%–55.5% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-287 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-290 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-295 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-325 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-330 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-347 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-352 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-367 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-384 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-400 | 25 | 7 | 28.0% | 14.3%–47.6% |
| CWE-402 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-434 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-444 | 1 | 1 | 100.0% | 20.6%–100.0% |
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
| CWE-770 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-78 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-79 | 38 | 10 | 26.3% | 15.0%–42.0% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-918 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-94 | 18 | 11 | 61.1% | 38.6%–79.7% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 1 | 50.0% | 9.4%–90.5% |
| maven | 5 | 1 | 20.0% | 3.6%–62.5% |
| npm | 134 | 43 | 32.1% | 24.8%–40.4% |
| pip | 54 | 20 | 37.0% | 25.4%–50.4% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 1 | 100.0% | 20.6%–100.0% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 8 | 38.1% | 20.8%–59.1% |
| high | 42 | 11 | 26.2% | 15.3%–41.1% |
| medium | 137 | 47 | 34.3% | 26.9%–42.6% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 0 | 0.0% | 0.0%–79.3% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 2 | 66.7% | 20.8%–93.8% |
| 2018 | 7 | 3 | 42.9% | 15.8%–75.0% |
| 2019 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2020 | 6 | 2 | 33.3% | 9.7%–70.0% |
| 2021 | 5 | 4 | 80.0% | 37.5%–96.4% |
| 2022 | 24 | 5 | 20.8% | 9.2%–40.5% |
| 2023 | 26 | 5 | 19.2% | 8.5%–37.9% |
| 2024 | 48 | 13 | 27.1% | 16.6%–41.0% |
| 2025 | 55 | 25 | 45.5% | 33.0%–58.5% |
| 2026 | 16 | 6 | 37.5% | 18.5%–61.4% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*