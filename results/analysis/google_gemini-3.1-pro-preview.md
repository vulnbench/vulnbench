# google/gemini-3.1-pro-preview — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4-6 · hint mode: description · source context: True · max_tokens: 4096*

## Why this model performed the way it did

google/gemini-3.1-pro-preview passed 3/200 instances (1.5%, 95% CI 0.5%–4.3%) with a mean judge score of 0.086.

Across 3 independent runs the pass rate was 1.5%, 2.5%, 1.5% (mean 1.8% ± 0.6%); 3.5% of instances passed in at least one run and 0.5% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 197 failed instances in the reference run: 75 (38%) because the diff appears cut off by the completion token limit; 49 (25%) because the provider returned no patch text without exhausting the token budget; 48 (24%) because the model responded with prose or code instead of a unified diff.

⚠ On 15 instances (8% of the benchmark) the model exhausted the completion token budget without emitting any visible text — almost always hidden reasoning consuming the shared budget. These score 0 but say more about the token limit than about the model's patching ability; the pass rate is a lower bound until the run is repeated with an adequate budget.

In total, 64 failures (32%) were harness or provider artifacts (API errors, empty responses, exhausted budgets) rather than judged model mistakes. Under the v2 quality gate, rows above 2% artifacts are not publishable.

The model produced a parseable diff on only 44% of instances (answer rate); capability comparisons against models with higher answer rates are confounded until this is resolved.

Judge reasoning on failures clusters on 'incomplete-scope' (55 instances): its patches most often fixed part of the issue but missed other affected paths the gold fix covered.

Relative weaknesses: primary cwe CWE-1321: 0% vs suite median 20% (n=5).

Cost: $7.79 total generation spend, $2.60 per passing patch, median generation time 45s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| likely_truncated | 75 | the diff appears cut off by the completion token limit |
| empty_patch | 49 | the provider returned no patch text without exhausting the token budget |
| not_a_diff | 48 | the model responded with prose or code instead of a unified diff |
| budget_exhausted | 15 | the model spent the entire completion budget (likely on hidden reasoning) and returned no visible text — a harness/config artifact, not a capability signal |
| near_miss | 5 | the judge scored the patch just below the pass threshold |
| wrong_file | 4 | the patch modifies files unrelated to the ground-truth fix |
| insufficient_fix | 1 | the model understood the issue but the fix was judged inadequate |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| incomplete-scope | 55 |
| invalid-patch | 33 |
| other | 22 |
| wrong-location | 13 |
| root-cause-missed | 10 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 1 | 1.5% | 0.3%–8.0% |
| tier_2 | 67 | 0 | 0.0% | 0.0%–5.4% |
| tier_3 | 66 | 2 | 3.0% | 0.8%–10.4% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 0 | 0.0% | 0.0%–43.5% |
| CWE-1333 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-20 | 23 | 1 | 4.3% | 0.8%–21.0% |
| CWE-200 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-22 | 25 | 1 | 4.0% | 0.7%–19.5% |
| CWE-23 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 0 | 0.0% | 0.0%–65.8% |
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
| CWE-506 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-532 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-601 | 2 | 0 | 0.0% | 0.0%–65.8% |
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
| CWE-94 | 18 | 1 | 5.6% | 1.0%–25.8% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 0 | 0.0% | 0.0%–65.8% |
| maven | 5 | 0 | 0.0% | 0.0%–43.5% |
| npm | 134 | 3 | 2.2% | 0.8%–6.4% |
| pip | 54 | 0 | 0.0% | 0.0%–6.6% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 0 | 0.0% | 0.0%–15.5% |
| high | 42 | 1 | 2.4% | 0.4%–12.3% |
| medium | 137 | 2 | 1.5% | 0.4%–5.2% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 0 | 0.0% | 0.0%–79.3% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 0 | 0.0% | 0.0%–56.1% |
| 2018 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2019 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2020 | 6 | 0 | 0.0% | 0.0%–39.0% |
| 2021 | 5 | 0 | 0.0% | 0.0%–43.5% |
| 2022 | 24 | 0 | 0.0% | 0.0%–13.8% |
| 2023 | 26 | 1 | 3.9% | 0.7%–18.9% |
| 2024 | 48 | 1 | 2.1% | 0.4%–10.9% |
| 2025 | 55 | 0 | 0.0% | 0.0%–6.5% |
| 2026 | 16 | 1 | 6.2% | 1.1%–28.3% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*