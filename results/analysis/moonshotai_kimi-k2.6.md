# moonshotai/kimi-k2.6 — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4.8 · hint mode: description · source context: True · max_tokens: 4096*

## Why this model performed the way it did

moonshotai/kimi-k2.6 passed 14/200 instances (7.0%, 95% CI 4.2%–11.4%) with a mean judge score of 0.082.

Across 3 independent runs the pass rate was 5.0%, 6.0%, 7.0% (mean 6.0% ± 1.0%); 15.0% of instances passed in at least one run and 1.0% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 186 failed instances in the reference run: 159 (85%) because the model spent the entire completion budget (likely on hidden reasoning) and returned no visible text — a harness/config artifact, not a capability signal; 18 (10%) because the diff appears cut off by the completion token limit; 4 (2%) because the model responded with prose or code instead of a unified diff.

⚠ On 159 instances (80% of the benchmark) the model exhausted the completion token budget without emitting any visible text — almost always hidden reasoning consuming the shared budget. These score 0 but say more about the token limit than about the model's patching ability; the pass rate is a lower bound until the run is repeated with an adequate budget.

In total, 161 failures (80%) were harness or provider artifacts (API errors, empty responses, exhausted budgets) rather than judged model mistakes. Under the v2 quality gate, rows above 2% artifacts are not publishable.

The model produced a parseable diff on only 18% of instances (answer rate); capability comparisons against models with higher answer rates are confounded until this is resolved.

Judge reasoning on failures clusters on 'wrong-location' (8 instances): it most often patched a plausible but wrong file or code path — a localization failure, expected to improve with better file hints or source context.

Relative strengths: ecosystem maven: 40% vs suite median 20% (n=5); cve year 2021: 40% vs suite median 20% (n=5); cve year 2020: 17% vs suite median 0% (n=6).

Relative weaknesses: primary cwe CWE-1321: 0% vs suite median 20% (n=5); cve year 2019: 0% vs suite median 14% (n=7); cve year 2026: 0% vs suite median 12% (n=16); severity high: 2% vs suite median 14% (n=42); primary cwe CWE-94: 0% vs suite median 11% (n=18).

Cost: $4.19 total generation spend, $0.30 per passing patch, median generation time 114s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| budget_exhausted | 159 | the model spent the entire completion budget (likely on hidden reasoning) and returned no visible text — a harness/config artifact, not a capability signal |
| likely_truncated | 18 | the diff appears cut off by the completion token limit |
| not_a_diff | 4 | the model responded with prose or code instead of a unified diff |
| wrong_file | 3 | the patch modifies files unrelated to the ground-truth fix |
| empty_patch | 2 | the provider returned no patch text without exhausting the token budget |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| wrong-location | 8 |
| other | 6 |
| incomplete-scope | 5 |
| root-cause-missed | 5 |
| regression-risk | 1 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 5 | 7.5% | 3.2%–16.3% |
| tier_2 | 67 | 6 | 9.0% | 4.2%–18.2% |
| tier_3 | 66 | 3 | 4.5% | 1.6%–12.5% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 0 | 0.0% | 0.0%–43.5% |
| CWE-1333 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-20 | 23 | 1 | 4.3% | 0.8%–21.0% |
| CWE-200 | 4 | 2 | 50.0% | 15.0%–85.0% |
| CWE-22 | 25 | 3 | 12.0% | 4.2%–30.0% |
| CWE-23 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-287 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-290 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-295 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-325 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-330 | 1 | 1 | 100.0% | 20.6%–100.0% |
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
| CWE-770 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-78 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-79 | 38 | 2 | 5.3% | 1.5%–17.3% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-918 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-94 | 18 | 0 | 0.0% | 0.0%–17.6% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 1 | 50.0% | 9.4%–90.5% |
| maven | 5 | 2 | 40.0% | 11.8%–76.9% |
| npm | 134 | 6 | 4.5% | 2.1%–9.4% |
| pip | 54 | 5 | 9.3% | 4.0%–19.9% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 2 | 9.5% | 2.6%–28.9% |
| high | 42 | 1 | 2.4% | 0.4%–12.3% |
| medium | 137 | 11 | 8.0% | 4.5%–13.8% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 0 | 0.0% | 0.0%–79.3% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 1 | 33.3% | 6.2%–79.2% |
| 2018 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2019 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2020 | 6 | 1 | 16.7% | 3.0%–56.4% |
| 2021 | 5 | 2 | 40.0% | 11.8%–76.9% |
| 2022 | 24 | 0 | 0.0% | 0.0%–13.8% |
| 2023 | 26 | 1 | 3.9% | 0.7%–18.9% |
| 2024 | 48 | 1 | 2.1% | 0.4%–10.9% |
| 2025 | 55 | 8 | 14.5% | 7.6%–26.2% |
| 2026 | 16 | 0 | 0.0% | 0.0%–19.4% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*