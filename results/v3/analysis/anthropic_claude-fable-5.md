# anthropic/claude-fable-5 — VulnBench performance analysis

*Runs: 1 · Judges: openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hint mode: description · source context: True · max_tokens: 16384*

## Why this model performed the way it did

anthropic/claude-fable-5 passed 51/200 instances (25.5%, 95% CI 20.0%–32.0%) with a mean judge score of 0.267.

Of the 149 failed instances in the reference run: 113 (76%) because the provider returned no patch text without exhausting the token budget; 12 (8%) because the patch modifies files unrelated to the ground-truth fix; 8 (5%) because the provider/API call failed after retries (not a model capability signal).

In total, 121 failures (60%) were harness or provider artifacts (API errors, empty responses, exhausted budgets) rather than judged model mistakes. Under the v2 quality gate, rows above 2% artifacts are not publishable.

The model produced a parseable diff on only 39% of instances (answer rate); capability comparisons against models with higher answer rates are confounded until this is resolved.

Relative strengths: cve year 2021: 80% vs suite median 40% (n=5); primary cwe CWE-400: 48% vs suite median 16% (n=25); cve year 2022: 33% vs suite median 12% (n=24); ecosystem maven: 40% vs suite median 20% (n=5); primary cwe CWE-79: 34% vs suite median 18% (n=38).

Relative weaknesses: primary cwe CWE-1321: 20% vs suite median 40% (n=5); cve year 2020: 0% vs suite median 17% (n=6); severity critical: 5% vs suite median 19% (n=21); primary cwe CWE-22: 12% vs suite median 24% (n=25); primary cwe CWE-94: 17% vs suite median 28% (n=18).

Cost: $23.30 total generation spend, $0.46 per passing patch, median generation time 222s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| empty_patch | 113 | the provider returned no patch text without exhausting the token budget |
| wrong_file | 12 | the patch modifies files unrelated to the ground-truth fix |
| adapter_error | 8 | the provider/API call failed after retries (not a model capability signal) |
| near_miss | 7 | the judge scored the patch just below the pass threshold |
| insufficient_fix | 6 | the model understood the issue but the fix was judged inadequate |
| likely_truncated | 1 | the diff appears cut off by the completion token limit |
| not_a_diff | 1 | the model responded with prose or code instead of a unified diff |
| off_target | 1 | the patch was judged irrelevant to the vulnerability |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 28 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 17 | 25.4% | 16.5%–36.9% |
| tier_2 | 67 | 15 | 22.4% | 14.1%–33.7% |
| tier_3 | 66 | 19 | 28.8% | 19.3%–40.6% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 1 | 20.0% | 3.6%–62.5% |
| CWE-1333 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-20 | 23 | 4 | 17.4% | 7.0%–37.1% |
| CWE-200 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-22 | 25 | 3 | 12.0% | 4.2%–30.0% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-287 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-290 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-295 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-325 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-330 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-347 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-352 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-367 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-384 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-400 | 25 | 12 | 48.0% | 30.0%–66.5% |
| CWE-402 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-434 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-444 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-470 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-476 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-506 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-532 | 1 | 1 | 100.0% | 20.6%–100.0% |
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
| CWE-78 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-79 | 38 | 13 | 34.2% | 21.2%–50.1% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-918 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-94 | 18 | 3 | 16.7% | 5.8%–39.2% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 1 | 50.0% | 9.4%–90.5% |
| maven | 5 | 2 | 40.0% | 11.8%–76.9% |
| npm | 134 | 30 | 22.4% | 16.2%–30.2% |
| pip | 54 | 17 | 31.5% | 20.7%–44.7% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 1 | 100.0% | 20.6%–100.0% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 1 | 4.8% | 0.9%–22.7% |
| high | 42 | 9 | 21.4% | 11.7%–35.9% |
| medium | 137 | 41 | 29.9% | 22.9%–38.1% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 0 | 0.0% | 0.0%–79.3% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 0 | 0.0% | 0.0%–56.1% |
| 2018 | 7 | 2 | 28.6% | 8.2%–64.1% |
| 2019 | 7 | 2 | 28.6% | 8.2%–64.1% |
| 2020 | 6 | 0 | 0.0% | 0.0%–39.0% |
| 2021 | 5 | 4 | 80.0% | 37.5%–96.4% |
| 2022 | 24 | 8 | 33.3% | 18.0%–53.3% |
| 2023 | 26 | 4 | 15.4% | 6.2%–33.5% |
| 2024 | 48 | 8 | 16.7% | 8.7%–29.6% |
| 2025 | 55 | 19 | 34.5% | 23.4%–47.8% |
| 2026 | 16 | 4 | 25.0% | 10.2%–49.5% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*