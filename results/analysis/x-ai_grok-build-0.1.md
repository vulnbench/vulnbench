# x-ai/grok-build-0.1 — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4.8 · hint mode: description · source context: True · max_tokens: 4096*

## Why this model performed the way it did

x-ai/grok-build-0.1 passed 26/200 instances (13.0%, 95% CI 9.0%–18.4%) with a mean judge score of 0.312.

Across 3 independent runs the pass rate was 19.0%, 14.0%, 13.0% (mean 15.3% ± 3.2%); 28.0% of instances passed in at least one run and 4.5% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 174 failed instances in the reference run: 161 (93%) because the diff appears cut off by the completion token limit; 4 (2%) because the model spent the entire completion budget (likely on hidden reasoning) and returned no visible text — a harness/config artifact, not a capability signal; 3 (2%) because the model understood the issue but the fix was judged inadequate.

In total, 4 failures (2%) were harness or provider artifacts (API errors, empty responses, exhausted budgets) rather than judged model mistakes. Under the v2 quality gate, rows above 2% artifacts are not publishable.

Judge reasoning on failures clusters on 'root-cause-missed' (59 instances): its patches most often treated symptoms rather than the underlying root cause.

Relative strengths: primary cwe CWE-79: 18% vs suite median 8% (n=38).

Relative weaknesses: ecosystem maven: 0% vs suite median 20% (n=5); primary cwe CWE-1321: 0% vs suite median 20% (n=5).

Cost: $8.19 total generation spend, $0.31 per passing patch, median generation time 83s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| likely_truncated | 161 | the diff appears cut off by the completion token limit |
| budget_exhausted | 4 | the model spent the entire completion budget (likely on hidden reasoning) and returned no visible text — a harness/config artifact, not a capability signal |
| insufficient_fix | 3 | the model understood the issue but the fix was judged inadequate |
| not_a_diff | 2 | the model responded with prose or code instead of a unified diff |
| wrong_file | 2 | the patch modifies files unrelated to the ground-truth fix |
| off_target | 1 | the patch was judged irrelevant to the vulnerability |
| near_miss | 1 | the judge scored the patch just below the pass threshold |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| root-cause-missed | 59 |
| wrong-location | 42 |
| incomplete-scope | 39 |
| other | 27 |
| regression-risk | 2 |
| invalid-patch | 1 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 12 | 17.9% | 10.5%–28.7% |
| tier_2 | 67 | 9 | 13.4% | 7.2%–23.6% |
| tier_3 | 66 | 5 | 7.6% | 3.3%–16.5% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 0 | 0.0% | 0.0%–43.5% |
| CWE-1333 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-20 | 23 | 3 | 13.0% | 4.5%–32.1% |
| CWE-200 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-22 | 25 | 5 | 20.0% | 8.9%–39.1% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-287 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-290 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-295 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-325 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-330 | 1 | 1 | 100.0% | 20.6%–100.0% |
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
| CWE-770 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-78 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-79 | 38 | 7 | 18.4% | 9.2%–33.4% |
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
| npm | 134 | 20 | 14.9% | 9.9%–21.9% |
| pip | 54 | 6 | 11.1% | 5.2%–22.2% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 3 | 14.3% | 5.0%–34.6% |
| high | 42 | 5 | 11.9% | 5.2%–25.0% |
| medium | 137 | 18 | 13.1% | 8.5%–19.8% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 1 | 100.0% | 20.6%–100.0% |
| 2016 | 2 | 1 | 50.0% | 9.4%–90.5% |
| 2017 | 3 | 1 | 33.3% | 6.2%–79.2% |
| 2018 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2019 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2020 | 6 | 0 | 0.0% | 0.0%–39.0% |
| 2021 | 5 | 1 | 20.0% | 3.6%–62.5% |
| 2022 | 24 | 3 | 12.5% | 4.3%–31.0% |
| 2023 | 26 | 2 | 7.7% | 2.1%–24.1% |
| 2024 | 48 | 5 | 10.4% | 4.5%–22.2% |
| 2025 | 55 | 10 | 18.2% | 10.2%–30.3% |
| 2026 | 16 | 1 | 6.2% | 1.1%–28.3% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*