# moonshotai/kimi-k2.7-code — VulnBench performance analysis

*Runs: 1 · Judges: openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hint mode: description · source context: True · max_tokens: 16384*

## Why this model performed the way it did

moonshotai/kimi-k2.7-code passed 52/200 instances (26.0%, 95% CI 20.4%–32.5%) with a mean judge score of 0.384.

Of the 148 failed instances in the reference run: 80 (54%) because the diff appears cut off by the completion token limit; 23 (16%) because the patch modifies files unrelated to the ground-truth fix; 16 (11%) because the judge scored the patch just below the pass threshold.

In total, 11 failures (6%) were harness or provider artifacts (API errors, empty responses, exhausted budgets) rather than judged model mistakes. Under the v2 quality gate, rows above 2% artifacts are not publishable.

Relative strengths: primary cwe CWE-1321: 60% vs suite median 40% (n=5); cve year 2021: 60% vs suite median 40% (n=5); cve year 2020: 33% vs suite median 17% (n=6); cve year 2019: 29% vs suite median 14% (n=7); cve year 2018: 29% vs suite median 14% (n=7).

Cost: $10.97 total generation spend, $0.21 per passing patch, median generation time 180s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| likely_truncated | 80 | the diff appears cut off by the completion token limit |
| wrong_file | 23 | the patch modifies files unrelated to the ground-truth fix |
| near_miss | 16 | the judge scored the patch just below the pass threshold |
| insufficient_fix | 11 | the model understood the issue but the fix was judged inadequate |
| adapter_error | 10 | the provider/API call failed after retries (not a model capability signal) |
| not_a_diff | 4 | the model responded with prose or code instead of a unified diff |
| off_target | 3 | the patch was judged irrelevant to the vulnerability |
| empty_patch | 1 | the provider returned no patch text without exhausting the token budget |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 137 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 16 | 23.9% | 15.3%–35.3% |
| tier_2 | 67 | 19 | 28.4% | 19.0%–40.1% |
| tier_3 | 66 | 17 | 25.8% | 16.8%–37.4% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 3 | 60.0% | 23.1%–88.2% |
| CWE-1333 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-20 | 23 | 6 | 26.1% | 12.6%–46.5% |
| CWE-200 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-22 | 25 | 8 | 32.0% | 17.2%–51.6% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-287 | 3 | 2 | 66.7% | 20.8%–93.8% |
| CWE-290 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-295 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-325 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-330 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-347 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-352 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-367 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-384 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-400 | 25 | 7 | 28.0% | 14.3%–47.6% |
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
| CWE-674 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-680 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-693 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-696 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-73 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-74 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-755 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-77 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-770 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-78 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-79 | 38 | 8 | 21.1% | 11.1%–36.4% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-918 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-94 | 18 | 4 | 22.2% | 9.0%–45.2% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 2 | 100.0% | 34.2%–100.0% |
| maven | 5 | 1 | 20.0% | 3.6%–62.5% |
| npm | 134 | 33 | 24.6% | 18.1%–32.6% |
| pip | 54 | 14 | 25.9% | 16.1%–38.9% |
| rubygems | 3 | 2 | 66.7% | 20.8%–93.8% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 5 | 23.8% | 10.6%–45.1% |
| high | 42 | 11 | 26.2% | 15.3%–41.1% |
| medium | 137 | 36 | 26.3% | 19.6%–34.2% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 1 | 100.0% | 20.6%–100.0% |
| 2016 | 2 | 1 | 50.0% | 9.4%–90.5% |
| 2017 | 3 | 0 | 0.0% | 0.0%–56.1% |
| 2018 | 7 | 2 | 28.6% | 8.2%–64.1% |
| 2019 | 7 | 2 | 28.6% | 8.2%–64.1% |
| 2020 | 6 | 2 | 33.3% | 9.7%–70.0% |
| 2021 | 5 | 3 | 60.0% | 23.1%–88.2% |
| 2022 | 24 | 5 | 20.8% | 9.2%–40.5% |
| 2023 | 26 | 5 | 19.2% | 8.5%–37.9% |
| 2024 | 48 | 12 | 25.0% | 14.9%–38.8% |
| 2025 | 55 | 17 | 30.9% | 20.3%–44.0% |
| 2026 | 16 | 2 | 12.5% | 3.5%–36.0% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*