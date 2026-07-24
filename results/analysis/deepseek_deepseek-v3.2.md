# deepseek/deepseek-v3.2 — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4-6 · hint mode: description · source context: True · max_tokens: 4096*

## Why this model performed the way it did

deepseek/deepseek-v3.2 passed 6/200 instances (3.0%, 95% CI 1.4%–6.4%) with a mean judge score of 0.243.

Across 3 independent runs the pass rate was 1.5%, 4.5%, 3.0% (mean 3.0% ± 1.5%); 5.0% of instances passed in at least one run and 1.0% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 194 failed instances in the reference run: 125 (64%) because the patch modifies files unrelated to the ground-truth fix; 27 (14%) because the model understood the issue but the fix was judged inadequate; 19 (10%) because the judge scored the patch just below the pass threshold.

Judge reasoning on failures clusters on 'wrong-location' (94 instances): it most often patched a plausible but wrong file or code path — a localization failure, expected to improve with better file hints or source context.

Relative weaknesses: primary cwe CWE-1321: 0% vs suite median 20% (n=5).

Cost: $0.13 total generation spend, $0.02 per passing patch, median generation time 41s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| wrong_file | 125 | the patch modifies files unrelated to the ground-truth fix |
| insufficient_fix | 27 | the model understood the issue but the fix was judged inadequate |
| near_miss | 19 | the judge scored the patch just below the pass threshold |
| off_target | 13 | the patch was judged irrelevant to the vulnerability |
| not_a_diff | 5 | the model responded with prose or code instead of a unified diff |
| likely_truncated | 5 | the diff appears cut off by the completion token limit |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| wrong-location | 94 |
| other | 35 |
| incomplete-scope | 35 |
| root-cause-missed | 23 |
| regression-risk | 5 |
| invalid-patch | 2 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 2 | 3.0% | 0.8%–10.2% |
| tier_2 | 67 | 2 | 3.0% | 0.8%–10.2% |
| tier_3 | 66 | 2 | 3.0% | 0.8%–10.4% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 0 | 0.0% | 0.0%–43.5% |
| CWE-1333 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-20 | 23 | 1 | 4.3% | 0.8%–21.0% |
| CWE-200 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-22 | 25 | 2 | 8.0% | 2.2%–25.0% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
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
| CWE-78 | 3 | 1 | 33.3% | 6.2%–79.2% |
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
| pip | 54 | 3 | 5.6% | 1.9%–15.1% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 1 | 4.8% | 0.9%–22.7% |
| high | 42 | 1 | 2.4% | 0.4%–12.3% |
| medium | 137 | 4 | 2.9% | 1.1%–7.3% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 0 | 0.0% | 0.0%–79.3% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 1 | 33.3% | 6.2%–79.2% |
| 2018 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2019 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2020 | 6 | 0 | 0.0% | 0.0%–39.0% |
| 2021 | 5 | 0 | 0.0% | 0.0%–43.5% |
| 2022 | 24 | 0 | 0.0% | 0.0%–13.8% |
| 2023 | 26 | 1 | 3.9% | 0.7%–18.9% |
| 2024 | 48 | 1 | 2.1% | 0.4%–10.9% |
| 2025 | 55 | 3 | 5.5% | 1.9%–14.8% |
| 2026 | 16 | 0 | 0.0% | 0.0%–19.4% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*