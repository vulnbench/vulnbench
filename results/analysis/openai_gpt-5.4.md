# openai/gpt-5.4 — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4-6 · hint mode: description · source context: True · max_tokens: 4096*

## Why this model performed the way it did

openai/gpt-5.4 passed 37/200 instances (18.5%, 95% CI 13.7%–24.5%) with a mean judge score of 0.407.

Across 3 independent runs the pass rate was 14.5%, 14.5%, 18.5% (mean 15.8% ± 2.3%); 27.0% of instances passed in at least one run and 5.5% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 163 failed instances in the reference run: 87 (53%) because the patch modifies files unrelated to the ground-truth fix; 32 (20%) because the judge scored the patch just below the pass threshold; 24 (15%) because the model understood the issue but the fix was judged inadequate.

Judge reasoning on failures clusters on 'wrong-location' (62 instances): it most often patched a plausible but wrong file or code path — a localization failure, expected to improve with better file hints or source context.

Relative strengths: severity critical: 33% vs suite median 0% (n=21); primary cwe CWE-1321: 40% vs suite median 20% (n=5); cve year 2021: 20% vs suite median 0% (n=5); primary cwe CWE-20: 22% vs suite median 4% (n=23); primary cwe CWE-94: 22% vs suite median 6% (n=18).

Cost: $1.68 total generation spend, $0.05 per passing patch, median generation time 6s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| wrong_file | 87 | the patch modifies files unrelated to the ground-truth fix |
| near_miss | 32 | the judge scored the patch just below the pass threshold |
| insufficient_fix | 24 | the model understood the issue but the fix was judged inadequate |
| not_a_diff | 12 | the model responded with prose or code instead of a unified diff |
| off_target | 8 | the patch was judged irrelevant to the vulnerability |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| wrong-location | 62 |
| incomplete-scope | 47 |
| other | 29 |
| root-cause-missed | 24 |
| regression-risk | 1 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 12 | 17.9% | 10.5%–28.7% |
| tier_2 | 67 | 15 | 22.4% | 14.1%–33.7% |
| tier_3 | 66 | 10 | 15.2% | 8.4%–25.7% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 2 | 40.0% | 11.8%–76.9% |
| CWE-1333 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-20 | 23 | 5 | 21.7% | 9.7%–41.9% |
| CWE-200 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-22 | 25 | 5 | 20.0% | 8.9%–39.1% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-285 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-287 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-290 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-295 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-325 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-330 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-347 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-352 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-367 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-384 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-400 | 25 | 1 | 4.0% | 0.7%–19.5% |
| CWE-402 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-434 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-444 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-470 | 1 | 1 | 100.0% | 20.6%–100.0% |
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
| CWE-77 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-770 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-78 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-79 | 38 | 6 | 15.8% | 7.4%–30.4% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-918 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-94 | 18 | 4 | 22.2% | 9.0%–45.2% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 1 | 50.0% | 9.4%–90.5% |
| maven | 5 | 0 | 0.0% | 0.0%–43.5% |
| npm | 134 | 22 | 16.4% | 11.1%–23.6% |
| pip | 54 | 12 | 22.2% | 13.2%–34.9% |
| rubygems | 3 | 1 | 33.3% | 6.2%–79.2% |
| rust | 1 | 1 | 100.0% | 20.6%–100.0% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 7 | 33.3% | 17.2%–54.6% |
| high | 42 | 7 | 16.7% | 8.3%–30.6% |
| medium | 137 | 23 | 16.8% | 11.5%–23.9% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 1 | 100.0% | 20.6%–100.0% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 0 | 0.0% | 0.0%–56.1% |
| 2018 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2019 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2020 | 6 | 0 | 0.0% | 0.0%–39.0% |
| 2021 | 5 | 1 | 20.0% | 3.6%–62.5% |
| 2022 | 24 | 3 | 12.5% | 4.3%–31.0% |
| 2023 | 26 | 5 | 19.2% | 8.5%–37.9% |
| 2024 | 48 | 8 | 16.7% | 8.7%–29.6% |
| 2025 | 55 | 14 | 25.4% | 15.8%–38.3% |
| 2026 | 16 | 3 | 18.8% | 6.6%–43.0% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*