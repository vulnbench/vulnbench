# z-ai/glm-5.2 — VulnBench performance analysis

*Runs: 2 · Judges: openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hint mode: description · source context: True · max_tokens: 16384*

## Why this model performed the way it did

z-ai/glm-5.2 passed 24/200 instances (12.0%, 95% CI 8.2%–17.2%) with a mean judge score of 0.267.

Across 2 independent runs the pass rate was 16.5%, 12.0% (mean 14.2% ± 3.2%); 22.5% of instances passed in at least one run and 6.0% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 176 failed instances in the reference run: 83 (47%) because the diff appears cut off by the completion token limit; 36 (20%) because the patch modifies files unrelated to the ground-truth fix; 19 (11%) because the provider/API call failed after retries (not a model capability signal).

In total, 24 failures (12%) were harness or provider artifacts (API errors, empty responses, exhausted budgets) rather than judged model mistakes. Under the v2 quality gate, rows above 2% artifacts are not publishable.

The model produced a parseable diff on only 88% of instances (answer rate); capability comparisons against models with higher answer rates are confounded until this is resolved.

Relative strengths: cve year 2020: 33% vs suite median 17% (n=6).

Relative weaknesses: cve year 2021: 20% vs suite median 40% (n=5); ecosystem maven: 0% vs suite median 20% (n=5); primary cwe CWE-1321: 20% vs suite median 40% (n=5); cve year 2018: 0% vs suite median 14% (n=7); cve year 2025: 16% vs suite median 29% (n=55).

Cost: $12.34 total generation spend, $0.51 per passing patch, median generation time 178s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| likely_truncated | 83 | the diff appears cut off by the completion token limit |
| wrong_file | 36 | the patch modifies files unrelated to the ground-truth fix |
| adapter_error | 19 | the provider/API call failed after retries (not a model capability signal) |
| insufficient_fix | 15 | the model understood the issue but the fix was judged inadequate |
| near_miss | 10 | the judge scored the patch just below the pass threshold |
| off_target | 8 | the patch was judged irrelevant to the vulnerability |
| budget_exhausted | 5 | the model spent the entire completion budget (likely on hidden reasoning) and returned no visible text — a harness/config artifact, not a capability signal |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 152 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 7 | 10.4% | 5.1%–20.0% |
| tier_2 | 67 | 9 | 13.4% | 7.2%–23.6% |
| tier_3 | 66 | 8 | 12.1% | 6.3%–22.1% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 1 | 20.0% | 3.6%–62.5% |
| CWE-1333 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-20 | 23 | 5 | 21.7% | 9.7%–41.9% |
| CWE-200 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-22 | 25 | 3 | 12.0% | 4.2%–30.0% |
| CWE-23 | 1 | 0 | 0.0% | 0.0%–79.3% |
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
| CWE-400 | 25 | 1 | 4.0% | 0.7%–19.5% |
| CWE-402 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-434 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-444 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-470 | 1 | 1 | 100.0% | 20.6%–100.0% |
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
| CWE-78 | 3 | 2 | 66.7% | 20.8%–93.8% |
| CWE-79 | 38 | 4 | 10.5% | 4.2%–24.1% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-918 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-94 | 18 | 2 | 11.1% | 3.1%–32.8% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 0 | 0.0% | 0.0%–65.8% |
| maven | 5 | 0 | 0.0% | 0.0%–43.5% |
| npm | 134 | 18 | 13.4% | 8.7%–20.2% |
| pip | 54 | 5 | 9.3% | 4.0%–19.9% |
| rubygems | 3 | 1 | 33.3% | 6.2%–79.2% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 5 | 23.8% | 10.6%–45.1% |
| high | 42 | 6 | 14.3% | 6.7%–27.8% |
| medium | 137 | 13 | 9.5% | 5.6%–15.6% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 0 | 0.0% | 0.0%–79.3% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 1 | 33.3% | 6.2%–79.2% |
| 2018 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2019 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2020 | 6 | 2 | 33.3% | 9.7%–70.0% |
| 2021 | 5 | 1 | 20.0% | 3.6%–62.5% |
| 2022 | 24 | 2 | 8.3% | 2.3%–25.9% |
| 2023 | 26 | 2 | 7.7% | 2.1%–24.1% |
| 2024 | 48 | 4 | 8.3% | 3.3%–19.6% |
| 2025 | 55 | 9 | 16.4% | 8.9%–28.3% |
| 2026 | 16 | 2 | 12.5% | 3.5%–36.0% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*