# anthropic/claude-fable-5 — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4.8 · hint mode: description · source context: True · max_tokens: 4096*

## Why this model performed the way it did

anthropic/claude-fable-5 passed 71/200 instances (35.5%, 95% CI 29.2%–42.4%) with a mean judge score of 0.451.

Across 3 independent runs the pass rate was 37.5%, 37.0%, 35.5% (mean 36.7% ± 1.0%); 56.0% of instances passed in at least one run and 18.0% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 129 failed instances in the reference run: 48 (37%) because the model spent the entire completion budget (likely on hidden reasoning) and returned no visible text — a harness/config artifact, not a capability signal; 20 (16%) because the judge scored the patch just below the pass threshold; 19 (15%) because the patch modifies files unrelated to the ground-truth fix.

⚠ On 48 instances (24% of the benchmark) the model exhausted the completion token budget without emitting any visible text — almost always hidden reasoning consuming the shared budget. These score 0 but say more about the token limit than about the model's patching ability; the pass rate is a lower bound until the run is repeated with an adequate budget.

In total, 59 failures (30%) were harness or provider artifacts (API errors, empty responses, exhausted budgets) rather than judged model mistakes. Under the v2 quality gate, rows above 2% artifacts are not publishable.

The model produced a parseable diff on only 64% of instances (answer rate); capability comparisons against models with higher answer rates are confounded until this is resolved.

Judge reasoning on failures clusters on 'root-cause-missed' (31 instances): its patches most often treated symptoms rather than the underlying root cause.

Relative strengths: cve year 2020: 67% vs suite median 0% (n=6); cve year 2021: 60% vs suite median 20% (n=5); primary cwe CWE-400: 44% vs suite median 8% (n=25); cve year 2022: 42% vs suite median 8% (n=24); primary cwe CWE-22: 48% vs suite median 16% (n=25).

Cost: $31.54 total generation spend, $0.44 per passing patch, median generation time 40s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| budget_exhausted | 48 | the model spent the entire completion budget (likely on hidden reasoning) and returned no visible text — a harness/config artifact, not a capability signal |
| near_miss | 20 | the judge scored the patch just below the pass threshold |
| wrong_file | 19 | the patch modifies files unrelated to the ground-truth fix |
| not_a_diff | 13 | the model responded with prose or code instead of a unified diff |
| likely_truncated | 12 | the diff appears cut off by the completion token limit |
| empty_patch | 11 | the provider returned no patch text without exhausting the token budget |
| insufficient_fix | 5 | the model understood the issue but the fix was judged inadequate |
| off_target | 1 | the patch was judged irrelevant to the vulnerability |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| root-cause-missed | 31 |
| incomplete-scope | 17 |
| other | 13 |
| wrong-location | 8 |
| invalid-patch | 1 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 26 | 38.8% | 28.1%–50.8% |
| tier_2 | 67 | 20 | 29.8% | 20.2%–41.7% |
| tier_3 | 66 | 25 | 37.9% | 27.2%–49.9% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-1321 | 5 | 1 | 20.0% | 3.6%–62.5% |
| CWE-1333 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-20 | 23 | 8 | 34.8% | 18.8%–55.1% |
| CWE-200 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-22 | 25 | 12 | 48.0% | 30.0%–66.5% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 1 | 50.0% | 9.4%–90.5% |
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
| CWE-384 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-400 | 25 | 11 | 44.0% | 26.7%–62.9% |
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
| CWE-674 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-680 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-693 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-696 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-73 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-74 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-755 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-77 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-770 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-78 | 3 | 3 | 100.0% | 43.9%–100.0% |
| CWE-79 | 38 | 13 | 34.2% | 21.2%–50.1% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-918 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-94 | 18 | 6 | 33.3% | 16.3%–56.2% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 0 | 0.0% | 0.0%–65.8% |
| maven | 5 | 2 | 40.0% | 11.8%–76.9% |
| npm | 134 | 51 | 38.1% | 30.3%–46.5% |
| pip | 54 | 18 | 33.3% | 22.2%–46.6% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 7 | 33.3% | 17.2%–54.6% |
| high | 42 | 16 | 38.1% | 25.0%–53.2% |
| medium | 137 | 48 | 35.0% | 27.6%–43.3% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 0 | 0.0% | 0.0%–79.3% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 1 | 33.3% | 6.2%–79.2% |
| 2018 | 7 | 2 | 28.6% | 8.2%–64.1% |
| 2019 | 7 | 2 | 28.6% | 8.2%–64.1% |
| 2020 | 6 | 4 | 66.7% | 30.0%–90.3% |
| 2021 | 5 | 3 | 60.0% | 23.1%–88.2% |
| 2022 | 24 | 10 | 41.7% | 24.5%–61.2% |
| 2023 | 26 | 9 | 34.6% | 19.4%–53.8% |
| 2024 | 48 | 14 | 29.2% | 18.2%–43.2% |
| 2025 | 55 | 21 | 38.2% | 26.5%–51.4% |
| 2026 | 16 | 5 | 31.2% | 14.2%–55.6% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*