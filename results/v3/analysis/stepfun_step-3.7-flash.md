# stepfun/step-3.7-flash — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hint mode: description · source context: True · max_tokens: 16384*

## Why this model performed the way it did

stepfun/step-3.7-flash passed 22/200 instances (11.0%, 95% CI 7.4%–16.1%) with a mean judge score of 0.238.

Across 3 independent runs the pass rate was 7.5%, 8.0%, 11.0% (mean 8.8% ± 1.9%); 15.5% of instances passed in at least one run and 3.5% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 178 failed instances in the reference run: 117 (66%) because the diff appears cut off by the completion token limit; 24 (13%) because the patch modifies files unrelated to the ground-truth fix; 15 (8%) because the model understood the issue but the fix was judged inadequate.

In total, 9 failures (4%) were harness or provider artifacts (API errors, empty responses, exhausted budgets) rather than judged model mistakes. Under the v2 quality gate, rows above 2% artifacts are not publishable.

Relative weaknesses: cve year 2021: 20% vs suite median 40% (n=5); ecosystem maven: 0% vs suite median 20% (n=5); primary cwe CWE-1321: 20% vs suite median 40% (n=5); cve year 2018: 0% vs suite median 14% (n=7); difficulty tier tier_2: 9% vs suite median 22% (n=67).

Cost: $3.80 total generation spend, $0.17 per passing patch, median generation time 84s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| likely_truncated | 117 | the diff appears cut off by the completion token limit |
| wrong_file | 24 | the patch modifies files unrelated to the ground-truth fix |
| insufficient_fix | 15 | the model understood the issue but the fix was judged inadequate |
| adapter_error | 9 | the provider/API call failed after retries (not a model capability signal) |
| off_target | 6 | the patch was judged irrelevant to the vulnerability |
| not_a_diff | 4 | the model responded with prose or code instead of a unified diff |
| near_miss | 3 | the judge scored the patch just below the pass threshold |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 169 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 7 | 10.4% | 5.1%–20.0% |
| tier_2 | 67 | 6 | 9.0% | 4.2%–18.2% |
| tier_3 | 66 | 9 | 13.6% | 7.3%–23.9% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 1 | 20.0% | 3.6%–62.5% |
| CWE-1333 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-20 | 23 | 2 | 8.7% | 2.4%–26.8% |
| CWE-200 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-22 | 25 | 3 | 12.0% | 4.2%–30.0% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-287 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-290 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-295 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-325 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-330 | 1 | 0 | 0.0% | 0.0%–79.3% |
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
| CWE-506 | 1 | 0 | 0.0% | 0.0%–79.3% |
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
| CWE-78 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-79 | 38 | 4 | 10.5% | 4.2%–24.1% |
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
| maven | 5 | 0 | 0.0% | 0.0%–43.5% |
| npm | 134 | 14 | 10.4% | 6.3%–16.8% |
| pip | 54 | 8 | 14.8% | 7.7%–26.6% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 3 | 14.3% | 5.0%–34.6% |
| high | 42 | 5 | 11.9% | 5.2%–25.0% |
| medium | 137 | 14 | 10.2% | 6.2%–16.4% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 0 | 0.0% | 0.0%–79.3% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 0 | 0.0% | 0.0%–56.1% |
| 2018 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2019 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2020 | 6 | 1 | 16.7% | 3.0%–56.4% |
| 2021 | 5 | 1 | 20.0% | 3.6%–62.5% |
| 2022 | 24 | 1 | 4.2% | 0.7%–20.2% |
| 2023 | 26 | 1 | 3.9% | 0.7%–18.9% |
| 2024 | 48 | 5 | 10.4% | 4.5%–22.2% |
| 2025 | 55 | 10 | 18.2% | 10.2%–30.3% |
| 2026 | 16 | 2 | 12.5% | 3.5%–36.0% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*