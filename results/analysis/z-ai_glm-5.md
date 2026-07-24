# z-ai/glm-5 — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4-6 · hint mode: description · source context: True · max_tokens: 4096*

## Why this model performed the way it did

z-ai/glm-5 passed 14/200 instances (7.0%, 95% CI 4.2%–11.4%) with a mean judge score of 0.249.

Across 3 independent runs the pass rate was 5.5%, 4.0%, 7.0% (mean 5.5% ± 1.5%); 10.0% of instances passed in at least one run and 2.0% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 186 failed instances in the reference run: 66 (35%) because the patch modifies files unrelated to the ground-truth fix; 38 (20%) because the model spent the entire completion budget (likely on hidden reasoning) and returned no visible text — a harness/config artifact, not a capability signal; 22 (12%) because the judge scored the patch just below the pass threshold.

⚠ On 38 instances (19% of the benchmark) the model exhausted the completion token budget without emitting any visible text — almost always hidden reasoning consuming the shared budget. These score 0 but say more about the token limit than about the model's patching ability; the pass rate is a lower bound until the run is repeated with an adequate budget.

In total, 46 failures (23%) were harness or provider artifacts (API errors, empty responses, exhausted budgets) rather than judged model mistakes. Under the v2 quality gate, rows above 2% artifacts are not publishable.

The model produced a parseable diff on only 72% of instances (answer rate); capability comparisons against models with higher answer rates are confounded until this is resolved.

Judge reasoning on failures clusters on 'wrong-location' (60 instances): it most often patched a plausible but wrong file or code path — a localization failure, expected to improve with better file hints or source context.

Relative strengths: severity high: 19% vs suite median 5% (n=42); cve year 2018: 14% vs suite median 0% (n=7); primary cwe CWE-94: 17% vs suite median 6% (n=18).

Cost: $2.05 total generation spend, $0.15 per passing patch, median generation time 50s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| wrong_file | 66 | the patch modifies files unrelated to the ground-truth fix |
| budget_exhausted | 38 | the model spent the entire completion budget (likely on hidden reasoning) and returned no visible text — a harness/config artifact, not a capability signal |
| near_miss | 22 | the judge scored the patch just below the pass threshold |
| insufficient_fix | 21 | the model understood the issue but the fix was judged inadequate |
| likely_truncated | 19 | the diff appears cut off by the completion token limit |
| not_a_diff | 10 | the model responded with prose or code instead of a unified diff |
| empty_patch | 8 | the provider returned no patch text without exhausting the token budget |
| off_target | 2 | the patch was judged irrelevant to the vulnerability |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| wrong-location | 60 |
| incomplete-scope | 40 |
| other | 20 |
| root-cause-missed | 15 |
| invalid-patch | 3 |
| regression-risk | 2 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 5 | 7.5% | 3.2%–16.3% |
| tier_2 | 67 | 5 | 7.5% | 3.2%–16.3% |
| tier_3 | 66 | 4 | 6.1% | 2.4%–14.6% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 1 | 20.0% | 3.6%–62.5% |
| CWE-1333 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-20 | 23 | 0 | 0.0% | 0.0%–14.3% |
| CWE-200 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-22 | 25 | 3 | 12.0% | 4.2%–30.0% |
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
| CWE-400 | 25 | 1 | 4.0% | 0.7%–19.5% |
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
| CWE-79 | 38 | 2 | 5.3% | 1.5%–17.3% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-918 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-94 | 18 | 3 | 16.7% | 5.8%–39.2% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 0 | 0.0% | 0.0%–65.8% |
| maven | 5 | 0 | 0.0% | 0.0%–43.5% |
| npm | 134 | 12 | 9.0% | 5.2%–15.0% |
| pip | 54 | 2 | 3.7% | 1.0%–12.5% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 0 | 0.0% | 0.0%–15.5% |
| high | 42 | 8 | 19.1% | 10.0%–33.3% |
| medium | 137 | 6 | 4.4% | 2.0%–9.2% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 1 | 100.0% | 20.6%–100.0% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 0 | 0.0% | 0.0%–56.1% |
| 2018 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2019 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2020 | 6 | 0 | 0.0% | 0.0%–39.0% |
| 2021 | 5 | 0 | 0.0% | 0.0%–43.5% |
| 2022 | 24 | 1 | 4.2% | 0.7%–20.2% |
| 2023 | 26 | 0 | 0.0% | 0.0%–12.9% |
| 2024 | 48 | 3 | 6.2% | 2.1%–16.8% |
| 2025 | 55 | 7 | 12.7% | 6.3%–24.0% |
| 2026 | 16 | 1 | 6.2% | 1.1%–28.3% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*