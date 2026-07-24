# google/gemini-3.5-flash — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4.8 · hint mode: description · source context: True · max_tokens: 4096*

## Why this model performed the way it did

google/gemini-3.5-flash passed 9/200 instances (4.5%, 95% CI 2.4%–8.3%) with a mean judge score of 0.047.

Across 3 independent runs the pass rate was 3.5%, 3.0%, 4.5% (mean 3.7% ± 0.8%); 7.0% of instances passed in at least one run and 1.5% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 191 failed instances in the reference run: 165 (86%) because the model responded with prose or code instead of a unified diff; 22 (12%) because the diff appears cut off by the completion token limit; 2 (1%) because the judge scored the patch just below the pass threshold.

In total, 1 failures (0%) were harness or provider artifacts (API errors, empty responses, exhausted budgets) rather than judged model mistakes. Under the v2 quality gate, rows above 2% artifacts are not publishable.

The model produced a parseable diff on only 17% of instances (answer rate); capability comparisons against models with higher answer rates are confounded until this is resolved.

Relative strengths: primary cwe CWE-1321: 60% vs suite median 20% (n=5).

Relative weaknesses: primary cwe CWE-22: 0% vs suite median 16% (n=25); cve year 2019: 0% vs suite median 14% (n=7); cve year 2026: 0% vs suite median 12% (n=16); primary cwe CWE-94: 0% vs suite median 11% (n=18); difficulty tier tier_1: 0% vs suite median 10% (n=67).

Cost: $7.45 total generation spend, $0.83 per passing patch, median generation time 22s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| not_a_diff | 165 | the model responded with prose or code instead of a unified diff |
| likely_truncated | 22 | the diff appears cut off by the completion token limit |
| near_miss | 2 | the judge scored the patch just below the pass threshold |
| insufficient_fix | 1 | the model understood the issue but the fix was judged inadequate |
| budget_exhausted | 1 | the model spent the entire completion budget (likely on hidden reasoning) and returned no visible text — a harness/config artifact, not a capability signal |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 89 |
| incomplete-scope | 47 |
| invalid-patch | 31 |
| root-cause-missed | 17 |
| wrong-location | 6 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 0 | 0.0% | 0.0%–5.4% |
| tier_2 | 67 | 7 | 10.4% | 5.1%–20.0% |
| tier_3 | 66 | 2 | 3.0% | 0.8%–10.4% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 3 | 60.0% | 23.1%–88.2% |
| CWE-1333 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-20 | 23 | 1 | 4.3% | 0.8%–21.0% |
| CWE-200 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-22 | 25 | 0 | 0.0% | 0.0%–13.3% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 0 | 0.0% | 0.0%–65.8% |
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
| CWE-770 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-78 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-79 | 38 | 0 | 0.0% | 0.0%–9.2% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-918 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-94 | 18 | 0 | 0.0% | 0.0%–17.6% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 0 | 0.0% | 0.0%–65.8% |
| maven | 5 | 1 | 20.0% | 3.6%–62.5% |
| npm | 134 | 6 | 4.5% | 2.1%–9.4% |
| pip | 54 | 2 | 3.7% | 1.0%–12.5% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 1 | 4.8% | 0.9%–22.7% |
| high | 42 | 3 | 7.1% | 2.5%–19.0% |
| medium | 137 | 5 | 3.6% | 1.6%–8.3% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 0 | 0.0% | 0.0%–79.3% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 0 | 0.0% | 0.0%–56.1% |
| 2018 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2019 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2020 | 6 | 0 | 0.0% | 0.0%–39.0% |
| 2021 | 5 | 1 | 20.0% | 3.6%–62.5% |
| 2022 | 24 | 0 | 0.0% | 0.0%–13.8% |
| 2023 | 26 | 0 | 0.0% | 0.0%–12.9% |
| 2024 | 48 | 5 | 10.4% | 4.5%–22.2% |
| 2025 | 55 | 3 | 5.5% | 1.9%–14.8% |
| 2026 | 16 | 0 | 0.0% | 0.0%–19.4% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*