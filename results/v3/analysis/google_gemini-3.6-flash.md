# google/gemini-3.6-flash — VulnBench performance analysis

*Runs: 1 · Judges: openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hint mode: description · source context: True · max_tokens: 16384*

## Why this model performed the way it did

google/gemini-3.6-flash passed 48/200 instances (24.0%, 95% CI 18.6%–30.4%) with a mean judge score of 0.320.

Of the 152 failed instances in the reference run: 52 (34%) because the model responded with prose or code instead of a unified diff; 39 (26%) because the patch modifies files unrelated to the ground-truth fix; 23 (15%) because the diff appears cut off by the completion token limit.

In total, 4 failures (2%) were harness or provider artifacts (API errors, empty responses, exhausted budgets) rather than judged model mistakes. Under the v2 quality gate, rows above 2% artifacts are not publishable.

The model produced a parseable diff on only 72% of instances (answer rate); capability comparisons against models with higher answer rates are confounded until this is resolved.

Relative strengths: primary cwe CWE-1321: 60% vs suite median 40% (n=5); cve year 2022: 29% vs suite median 12% (n=24); cve year 2019: 29% vs suite median 14% (n=7).

Relative weaknesses: ecosystem maven: 0% vs suite median 20% (n=5); cve year 2018: 0% vs suite median 14% (n=7).

Cost: $18.05 total generation spend, $0.38 per passing patch, median generation time 64s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| not_a_diff | 52 | the model responded with prose or code instead of a unified diff |
| wrong_file | 39 | the patch modifies files unrelated to the ground-truth fix |
| likely_truncated | 23 | the diff appears cut off by the completion token limit |
| insufficient_fix | 21 | the model understood the issue but the fix was judged inadequate |
| near_miss | 8 | the judge scored the patch just below the pass threshold |
| off_target | 5 | the patch was judged irrelevant to the vulnerability |
| adapter_error | 4 | the provider/API call failed after retries (not a model capability signal) |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 148 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 15 | 22.4% | 14.1%–33.7% |
| tier_2 | 67 | 17 | 25.4% | 16.5%–36.9% |
| tier_3 | 66 | 16 | 24.2% | 15.5%–35.8% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 3 | 60.0% | 23.1%–88.2% |
| CWE-1333 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-20 | 23 | 4 | 17.4% | 7.0%–37.1% |
| CWE-200 | 4 | 2 | 50.0% | 15.0%–85.0% |
| CWE-22 | 25 | 6 | 24.0% | 11.5%–43.4% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-287 | 3 | 2 | 66.7% | 20.8%–93.8% |
| CWE-290 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-295 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-325 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-330 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-347 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-352 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-367 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-384 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-400 | 25 | 6 | 24.0% | 11.5%–43.4% |
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
| CWE-770 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-78 | 3 | 2 | 66.7% | 20.8%–93.8% |
| CWE-79 | 38 | 9 | 23.7% | 13.0%–39.2% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-918 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-94 | 18 | 6 | 33.3% | 16.3%–56.2% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 0 | 0.0% | 0.0%–65.8% |
| maven | 5 | 0 | 0.0% | 0.0%–43.5% |
| npm | 134 | 37 | 27.6% | 20.8%–35.7% |
| pip | 54 | 11 | 20.4% | 11.8%–32.9% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 6 | 28.6% | 13.8%–50.0% |
| high | 42 | 11 | 26.2% | 15.3%–41.1% |
| medium | 137 | 31 | 22.6% | 16.4%–30.3% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 1 | 100.0% | 20.6%–100.0% |
| 2016 | 2 | 1 | 50.0% | 9.4%–90.5% |
| 2017 | 3 | 1 | 33.3% | 6.2%–79.2% |
| 2018 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2019 | 7 | 2 | 28.6% | 8.2%–64.1% |
| 2020 | 6 | 1 | 16.7% | 3.0%–56.4% |
| 2021 | 5 | 2 | 40.0% | 11.8%–76.9% |
| 2022 | 24 | 7 | 29.2% | 14.9%–49.2% |
| 2023 | 26 | 4 | 15.4% | 6.2%–33.5% |
| 2024 | 48 | 11 | 22.9% | 13.3%–36.5% |
| 2025 | 55 | 15 | 27.3% | 17.3%–40.2% |
| 2026 | 16 | 3 | 18.8% | 6.6%–43.0% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*