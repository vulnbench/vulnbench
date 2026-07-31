# z-ai/glm-5.1 — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4.8 · hint mode: description · source context: True · max_tokens: 4096*

## Why this model performed the way it did

z-ai/glm-5.1 passed 22/200 instances (11.0%, 95% CI 7.4%–16.1%) with a mean judge score of 0.134.

Across 3 independent runs the pass rate was 9.5%, 9.0%, 11.0% (mean 9.8% ± 1.0%); 17.0% of instances passed in at least one run and 3.5% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 178 failed instances in the reference run: 144 (81%) because the model spent the entire completion budget (likely on hidden reasoning) and returned no visible text — a harness/config artifact, not a capability signal; 15 (8%) because the patch modifies files unrelated to the ground-truth fix; 8 (4%) because the diff appears cut off by the completion token limit.

⚠ On 144 instances (72% of the benchmark) the model exhausted the completion token budget without emitting any visible text — almost always hidden reasoning consuming the shared budget. These score 0 but say more about the token limit than about the model's patching ability; the pass rate is a lower bound until the run is repeated with an adequate budget.

In total, 144 failures (72%) were harness or provider artifacts (API errors, empty responses, exhausted budgets) rather than judged model mistakes. Under the v2 quality gate, rows above 2% artifacts are not publishable.

The model produced a parseable diff on only 27% of instances (answer rate); capability comparisons against models with higher answer rates are confounded until this is resolved.

Judge reasoning on failures clusters on 'incomplete-scope' (12 instances): its patches most often fixed part of the issue but missed other affected paths the gold fix covered.

Relative strengths: primary cwe CWE-1321: 40% vs suite median 20% (n=5); cve year 2021: 40% vs suite median 20% (n=5).

Relative weaknesses: ecosystem maven: 0% vs suite median 20% (n=5).

Cost: $4.01 total generation spend, $0.18 per passing patch, median generation time 69s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| budget_exhausted | 144 | the model spent the entire completion budget (likely on hidden reasoning) and returned no visible text — a harness/config artifact, not a capability signal |
| wrong_file | 15 | the patch modifies files unrelated to the ground-truth fix |
| likely_truncated | 8 | the diff appears cut off by the completion token limit |
| near_miss | 4 | the judge scored the patch just below the pass threshold |
| insufficient_fix | 4 | the model understood the issue but the fix was judged inadequate |
| not_a_diff | 2 | the model responded with prose or code instead of a unified diff |
| off_target | 1 | the patch was judged irrelevant to the vulnerability |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| incomplete-scope | 12 |
| wrong-location | 9 |
| root-cause-missed | 8 |
| other | 5 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 7 | 10.4% | 5.1%–20.0% |
| tier_2 | 67 | 7 | 10.4% | 5.1%–20.0% |
| tier_3 | 66 | 8 | 12.1% | 6.3%–22.1% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 2 | 40.0% | 11.8%–76.9% |
| CWE-1333 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-20 | 23 | 4 | 17.4% | 7.0%–37.1% |
| CWE-200 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-22 | 25 | 4 | 16.0% | 6.4%–34.6% |
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
| CWE-400 | 25 | 2 | 8.0% | 2.2%–25.0% |
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
| CWE-78 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-79 | 38 | 3 | 7.9% | 2.7%–20.8% |
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
| npm | 134 | 16 | 11.9% | 7.5%–18.5% |
| pip | 54 | 6 | 11.1% | 5.2%–22.2% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 2 | 9.5% | 2.6%–28.9% |
| high | 42 | 6 | 14.3% | 6.7%–27.8% |
| medium | 137 | 14 | 10.2% | 6.2%–16.4% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 1 | 100.0% | 20.6%–100.0% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 0 | 0.0% | 0.0%–56.1% |
| 2018 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2019 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2020 | 6 | 0 | 0.0% | 0.0%–39.0% |
| 2021 | 5 | 2 | 40.0% | 11.8%–76.9% |
| 2022 | 24 | 2 | 8.3% | 2.3%–25.9% |
| 2023 | 26 | 3 | 11.5% | 4.0%–29.0% |
| 2024 | 48 | 4 | 8.3% | 3.3%–19.6% |
| 2025 | 55 | 7 | 12.7% | 6.3%–24.0% |
| 2026 | 16 | 2 | 12.5% | 3.5%–36.0% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*