# openai/gpt-5.3-codex — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4-6 · hint mode: description · source context: True · max_tokens: 4096*

## Why this model performed the way it did

openai/gpt-5.3-codex passed 45/200 instances (22.5%, 95% CI 17.3%–28.8%) with a mean judge score of 0.468.

Across 3 independent runs the pass rate was 8.5%, 21.0%, 22.5% (mean 17.3% ± 7.7%); 29.0% of instances passed in at least one run and 6.0% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 155 failed instances in the reference run: 89 (57%) because the patch modifies files unrelated to the ground-truth fix; 41 (26%) because the judge scored the patch just below the pass threshold; 15 (10%) because the model understood the issue but the fix was judged inadequate.

In total, 2 failures (1%) were harness or provider artifacts (API errors, empty responses, exhausted budgets) rather than judged model mistakes. Under the v2 quality gate, rows above 2% artifacts are not publishable.

Judge reasoning on failures clusters on 'wrong-location' (62 instances): it most often patched a plausible but wrong file or code path — a localization failure, expected to improve with better file hints or source context.

Relative strengths: primary cwe CWE-1321: 80% vs suite median 20% (n=5); severity critical: 33% vs suite median 0% (n=21); cve year 2019: 29% vs suite median 0% (n=7); primary cwe CWE-94: 33% vs suite median 6% (n=18); primary cwe CWE-79: 26% vs suite median 3% (n=38).

Cost: $5.78 total generation spend, $0.13 per passing patch, median generation time 33s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| wrong_file | 89 | the patch modifies files unrelated to the ground-truth fix |
| near_miss | 41 | the judge scored the patch just below the pass threshold |
| insufficient_fix | 15 | the model understood the issue but the fix was judged inadequate |
| likely_truncated | 4 | the diff appears cut off by the completion token limit |
| off_target | 4 | the patch was judged irrelevant to the vulnerability |
| budget_exhausted | 2 | the model spent the entire completion budget (likely on hidden reasoning) and returned no visible text — a harness/config artifact, not a capability signal |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| wrong-location | 62 |
| incomplete-scope | 49 |
| root-cause-missed | 22 |
| other | 18 |
| regression-risk | 1 |
| invalid-patch | 1 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 18 | 26.9% | 17.7%–38.5% |
| tier_2 | 67 | 15 | 22.4% | 14.1%–33.7% |
| tier_3 | 66 | 12 | 18.2% | 10.7%–29.1% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 4 | 80.0% | 37.5%–96.4% |
| CWE-1333 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-20 | 23 | 3 | 13.0% | 4.5%–32.1% |
| CWE-200 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-22 | 25 | 7 | 28.0% | 14.3%–47.6% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-287 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-290 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-295 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-325 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-330 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-347 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-352 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-367 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-384 | 1 | 1 | 100.0% | 20.6%–100.0% |
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
| CWE-674 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-680 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-693 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-696 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-73 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-74 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-755 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-77 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-770 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-78 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-79 | 38 | 10 | 26.3% | 15.0%–42.0% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-918 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-94 | 18 | 6 | 33.3% | 16.3%–56.2% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 1 | 50.0% | 9.4%–90.5% |
| maven | 5 | 1 | 20.0% | 3.6%–62.5% |
| npm | 134 | 31 | 23.1% | 16.8%–31.0% |
| pip | 54 | 11 | 20.4% | 11.8%–32.9% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 1 | 100.0% | 20.6%–100.0% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 7 | 33.3% | 17.2%–54.6% |
| high | 42 | 8 | 19.1% | 10.0%–33.3% |
| medium | 137 | 30 | 21.9% | 15.8%–29.5% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 1 | 100.0% | 20.6%–100.0% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 1 | 33.3% | 6.2%–79.2% |
| 2018 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2019 | 7 | 2 | 28.6% | 8.2%–64.1% |
| 2020 | 6 | 1 | 16.7% | 3.0%–56.4% |
| 2021 | 5 | 1 | 20.0% | 3.6%–62.5% |
| 2022 | 24 | 4 | 16.7% | 6.7%–35.9% |
| 2023 | 26 | 6 | 23.1% | 11.0%–42.0% |
| 2024 | 48 | 9 | 18.8% | 10.2%–31.9% |
| 2025 | 55 | 15 | 27.3% | 17.3%–40.2% |
| 2026 | 16 | 4 | 25.0% | 10.2%–49.5% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*