# qwen/qwen3.7-max — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4.8 · hint mode: description · source context: True · max_tokens: 4096*

## Why this model performed the way it did

qwen/qwen3.7-max passed 57/200 instances (28.5%, 95% CI 22.7%–35.1%) with a mean judge score of 0.403.

Across 3 independent runs the pass rate was 11.5%, 27.0%, 28.5% (mean 22.3% ± 9.4%); 41.0% of instances passed in at least one run and 6.0% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 143 failed instances in the reference run: 104 (73%) because the diff appears cut off by the completion token limit; 19 (13%) because the patch modifies files unrelated to the ground-truth fix; 8 (6%) because the model understood the issue but the fix was judged inadequate.

In total, 3 failures (2%) were harness or provider artifacts (API errors, empty responses, exhausted budgets) rather than judged model mistakes. Under the v2 quality gate, rows above 2% artifacts are not publishable.

Judge reasoning on failures clusters on 'root-cause-missed' (49 instances): its patches most often treated symptoms rather than the underlying root cause.

Relative strengths: primary cwe CWE-1321: 60% vs suite median 20% (n=5); primary cwe CWE-94: 39% vs suite median 11% (n=18); cve year 2025: 40% vs suite median 13% (n=55); primary cwe CWE-79: 32% vs suite median 8% (n=38); difficulty tier tier_3: 32% vs suite median 11% (n=66).

Cost: $10.03 total generation spend, $0.18 per passing patch, median generation time 130s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| likely_truncated | 104 | the diff appears cut off by the completion token limit |
| wrong_file | 19 | the patch modifies files unrelated to the ground-truth fix |
| insufficient_fix | 8 | the model understood the issue but the fix was judged inadequate |
| not_a_diff | 5 | the model responded with prose or code instead of a unified diff |
| near_miss | 3 | the judge scored the patch just below the pass threshold |
| empty_patch | 2 | the provider returned no patch text without exhausting the token budget |
| off_target | 1 | the patch was judged irrelevant to the vulnerability |
| budget_exhausted | 1 | the model spent the entire completion budget (likely on hidden reasoning) and returned no visible text — a harness/config artifact, not a capability signal |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| root-cause-missed | 49 |
| wrong-location | 37 |
| incomplete-scope | 28 |
| other | 23 |
| invalid-patch | 2 |
| regression-risk | 1 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 19 | 28.4% | 19.0%–40.1% |
| tier_2 | 67 | 17 | 25.4% | 16.5%–36.9% |
| tier_3 | 66 | 21 | 31.8% | 21.9%–43.8% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 3 | 60.0% | 23.1%–88.2% |
| CWE-1333 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-20 | 23 | 7 | 30.4% | 15.6%–50.9% |
| CWE-200 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-22 | 25 | 6 | 24.0% | 11.5%–43.4% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-287 | 3 | 2 | 66.7% | 20.8%–93.8% |
| CWE-290 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-295 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-325 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-330 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-347 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-352 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-367 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-384 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-400 | 25 | 7 | 28.0% | 14.3%–47.6% |
| CWE-402 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-434 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-444 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-470 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-476 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-506 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-532 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-601 | 2 | 2 | 100.0% | 34.2%–100.0% |
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
| CWE-79 | 38 | 12 | 31.6% | 19.1%–47.5% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-918 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-94 | 18 | 7 | 38.9% | 20.3%–61.4% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 0 | 0.0% | 0.0%–65.8% |
| maven | 5 | 2 | 40.0% | 11.8%–76.9% |
| npm | 134 | 39 | 29.1% | 22.1%–37.3% |
| pip | 54 | 14 | 25.9% | 16.1%–38.9% |
| rubygems | 3 | 1 | 33.3% | 6.2%–79.2% |
| rust | 1 | 1 | 100.0% | 20.6%–100.0% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 6 | 28.6% | 13.8%–50.0% |
| high | 42 | 13 | 30.9% | 19.1%–46.0% |
| medium | 137 | 38 | 27.7% | 20.9%–35.8% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 1 | 100.0% | 20.6%–100.0% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 1 | 33.3% | 6.2%–79.2% |
| 2018 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2019 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2020 | 6 | 1 | 16.7% | 3.0%–56.4% |
| 2021 | 5 | 2 | 40.0% | 11.8%–76.9% |
| 2022 | 24 | 5 | 20.8% | 9.2%–40.5% |
| 2023 | 26 | 7 | 26.9% | 13.7%–46.1% |
| 2024 | 48 | 12 | 25.0% | 14.9%–38.8% |
| 2025 | 55 | 22 | 40.0% | 28.1%–53.2% |
| 2026 | 16 | 4 | 25.0% | 10.2%–49.5% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*