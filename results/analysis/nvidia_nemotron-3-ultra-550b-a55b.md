# nvidia/nemotron-3-ultra-550b-a55b — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4.8 · hint mode: description · source context: True · max_tokens: 4096*

## Why this model performed the way it did

nvidia/nemotron-3-ultra-550b-a55b passed 19/200 instances (9.5%, 95% CI 6.2%–14.4%) with a mean judge score of 0.179.

Across 3 independent runs the pass rate was 7.5%, 12.0%, 9.5% (mean 9.7% ± 2.2%); 18.0% of instances passed in at least one run and 2.5% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 181 failed instances in the reference run: 104 (57%) because the patch modifies files unrelated to the ground-truth fix; 23 (13%) because the model responded with prose or code instead of a unified diff; 18 (10%) because the diff appears cut off by the completion token limit.

In total, 2 failures (1%) were harness or provider artifacts (API errors, empty responses, exhausted budgets) rather than judged model mistakes. Under the v2 quality gate, rows above 2% artifacts are not publishable.

The model produced a parseable diff on only 88% of instances (answer rate); capability comparisons against models with higher answer rates are confounded until this is resolved.

Judge reasoning on failures clusters on 'root-cause-missed' (60 instances): its patches most often treated symptoms rather than the underlying root cause.

Relative strengths: cve year 2021: 60% vs suite median 20% (n=5); cve year 2020: 17% vs suite median 0% (n=6).

Cost: $1.37 total generation spend, $0.07 per passing patch, median generation time 13s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| wrong_file | 104 | the patch modifies files unrelated to the ground-truth fix |
| not_a_diff | 23 | the model responded with prose or code instead of a unified diff |
| likely_truncated | 18 | the diff appears cut off by the completion token limit |
| off_target | 14 | the patch was judged irrelevant to the vulnerability |
| near_miss | 10 | the judge scored the patch just below the pass threshold |
| insufficient_fix | 10 | the model understood the issue but the fix was judged inadequate |
| empty_patch | 2 | the provider returned no patch text without exhausting the token budget |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| root-cause-missed | 60 |
| other | 53 |
| wrong-location | 38 |
| incomplete-scope | 24 |
| regression-risk | 3 |
| invalid-patch | 1 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 7 | 10.4% | 5.1%–20.0% |
| tier_2 | 67 | 6 | 9.0% | 4.2%–18.2% |
| tier_3 | 66 | 6 | 9.1% | 4.2%–18.4% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 1 | 20.0% | 3.6%–62.5% |
| CWE-1333 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-20 | 23 | 2 | 8.7% | 2.4%–26.8% |
| CWE-200 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-22 | 25 | 2 | 8.0% | 2.2%–25.0% |
| CWE-23 | 1 | 0 | 0.0% | 0.0%–79.3% |
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
| CWE-400 | 25 | 2 | 8.0% | 2.2%–25.0% |
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
| CWE-770 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-78 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-79 | 38 | 5 | 13.2% | 5.8%–27.3% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-918 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-94 | 18 | 2 | 11.1% | 3.1%–32.8% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 1 | 50.0% | 9.4%–90.5% |
| maven | 5 | 1 | 20.0% | 3.6%–62.5% |
| npm | 134 | 12 | 9.0% | 5.2%–15.0% |
| pip | 54 | 5 | 9.3% | 4.0%–19.9% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 2 | 9.5% | 2.6%–28.9% |
| high | 42 | 6 | 14.3% | 6.7%–27.8% |
| medium | 137 | 11 | 8.0% | 4.5%–13.8% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 0 | 0.0% | 0.0%–79.3% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 1 | 33.3% | 6.2%–79.2% |
| 2018 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2019 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2020 | 6 | 1 | 16.7% | 3.0%–56.4% |
| 2021 | 5 | 3 | 60.0% | 23.1%–88.2% |
| 2022 | 24 | 1 | 4.2% | 0.7%–20.2% |
| 2023 | 26 | 2 | 7.7% | 2.1%–24.1% |
| 2024 | 48 | 3 | 6.2% | 2.1%–16.8% |
| 2025 | 55 | 6 | 10.9% | 5.1%–21.8% |
| 2026 | 16 | 1 | 6.2% | 1.1%–28.3% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*