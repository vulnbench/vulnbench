# x-ai/grok-build-0.1 — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hint mode: description · source context: True · max_tokens: 16384*

## Why this model performed the way it did

x-ai/grok-build-0.1 passed 44/200 instances (22.0%, 95% CI 16.8%–28.2%) with a mean judge score of 0.349.

Across 3 independent runs the pass rate was 24.0%, 25.0%, 22.0% (mean 23.7% ± 1.5%); 37.0% of instances passed in at least one run and 11.5% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 156 failed instances in the reference run: 75 (48%) because the diff appears cut off by the completion token limit; 40 (26%) because the patch modifies files unrelated to the ground-truth fix; 22 (14%) because the model understood the issue but the fix was judged inadequate.

In total, 2 failures (1%) were harness or provider artifacts (API errors, empty responses, exhausted budgets) rather than judged model mistakes. Under the v2 quality gate, rows above 2% artifacts are not publishable.

Relative strengths: primary cwe CWE-1321: 80% vs suite median 40% (n=5); cve year 2020: 50% vs suite median 17% (n=6); primary cwe CWE-20: 30% vs suite median 17% (n=23).

Relative weaknesses: cve year 2021: 20% vs suite median 40% (n=5).

Cost: $7.19 total generation spend, $0.16 per passing patch, median generation time 91s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| likely_truncated | 75 | the diff appears cut off by the completion token limit |
| wrong_file | 40 | the patch modifies files unrelated to the ground-truth fix |
| insufficient_fix | 22 | the model understood the issue but the fix was judged inadequate |
| near_miss | 9 | the judge scored the patch just below the pass threshold |
| off_target | 7 | the patch was judged irrelevant to the vulnerability |
| adapter_error | 2 | the provider/API call failed after retries (not a model capability signal) |
| not_a_diff | 1 | the model responded with prose or code instead of a unified diff |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 154 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 14 | 20.9% | 12.9%–32.1% |
| tier_2 | 67 | 16 | 23.9% | 15.3%–35.3% |
| tier_3 | 66 | 14 | 21.2% | 13.1%–32.5% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 4 | 80.0% | 37.5%–96.4% |
| CWE-1333 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-20 | 23 | 7 | 30.4% | 15.6%–50.9% |
| CWE-200 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-22 | 25 | 8 | 32.0% | 17.2%–51.6% |
| CWE-23 | 1 | 0 | 0.0% | 0.0%–79.3% |
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
| CWE-367 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-384 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-400 | 25 | 3 | 12.0% | 4.2%–30.0% |
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
| CWE-770 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-78 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-79 | 38 | 6 | 15.8% | 7.4%–30.4% |
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
| npm | 134 | 31 | 23.1% | 16.8%–31.0% |
| pip | 54 | 11 | 20.4% | 11.8%–32.9% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 1 | 100.0% | 20.6%–100.0% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 5 | 23.8% | 10.6%–45.1% |
| high | 42 | 12 | 28.6% | 17.2%–43.6% |
| medium | 137 | 27 | 19.7% | 13.9%–27.2% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 0 | 0.0% | 0.0%–79.3% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 0 | 0.0% | 0.0%–56.1% |
| 2018 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2019 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2020 | 6 | 3 | 50.0% | 18.8%–81.2% |
| 2021 | 5 | 1 | 20.0% | 3.6%–62.5% |
| 2022 | 24 | 4 | 16.7% | 6.7%–35.9% |
| 2023 | 26 | 4 | 15.4% | 6.2%–33.5% |
| 2024 | 48 | 10 | 20.8% | 11.7%–34.3% |
| 2025 | 55 | 18 | 32.7% | 21.8%–45.9% |
| 2026 | 16 | 2 | 12.5% | 3.5%–36.0% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*