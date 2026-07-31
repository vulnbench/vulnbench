# openai/gpt-5.4-mini — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4.8 · hint mode: description · source context: True · max_tokens: 4096*

## Why this model performed the way it did

openai/gpt-5.4-mini passed 24/200 instances (12.0%, 95% CI 8.2%–17.2%) with a mean judge score of 0.228.

Across 3 independent runs the pass rate was 11.5%, 10.5%, 12.0% (mean 11.3% ± 0.8%); 20.5% of instances passed in at least one run and 3.5% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 176 failed instances in the reference run: 94 (53%) because the patch modifies files unrelated to the ground-truth fix; 32 (18%) because the model responded with prose or code instead of a unified diff; 26 (15%) because the patch was judged irrelevant to the vulnerability.

The model produced a parseable diff on only 83% of instances (answer rate); capability comparisons against models with higher answer rates are confounded until this is resolved.

Relative strengths: primary cwe CWE-1321: 40% vs suite median 20% (n=5); cve year 2020: 17% vs suite median 0% (n=6); cve year 2018: 14% vs suite median 0% (n=7).

Relative weaknesses: ecosystem maven: 0% vs suite median 20% (n=5).

Cost: $0.40 total generation spend, $0.02 per passing patch, median generation time 2s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| wrong_file | 94 | the patch modifies files unrelated to the ground-truth fix |
| not_a_diff | 32 | the model responded with prose or code instead of a unified diff |
| off_target | 26 | the patch was judged irrelevant to the vulnerability |
| insufficient_fix | 14 | the model understood the issue but the fix was judged inadequate |
| near_miss | 10 | the judge scored the patch just below the pass threshold |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 53 |
| root-cause-missed | 46 |
| wrong-location | 45 |
| incomplete-scope | 27 |
| invalid-patch | 3 |
| regression-risk | 2 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 6 | 9.0% | 4.2%–18.2% |
| tier_2 | 67 | 11 | 16.4% | 9.4%–27.1% |
| tier_3 | 66 | 7 | 10.6% | 5.2%–20.3% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 2 | 40.0% | 11.8%–76.9% |
| CWE-1333 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-20 | 23 | 5 | 21.7% | 9.7%–41.9% |
| CWE-200 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-22 | 25 | 2 | 8.0% | 2.2%–25.0% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-287 | 3 | 1 | 33.3% | 6.2%–79.2% |
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
| CWE-79 | 38 | 4 | 10.5% | 4.2%–24.1% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-918 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-94 | 18 | 2 | 11.1% | 3.1%–32.8% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 0 | 0.0% | 0.0%–65.8% |
| maven | 5 | 0 | 0.0% | 0.0%–43.5% |
| npm | 134 | 18 | 13.4% | 8.7%–20.2% |
| pip | 54 | 6 | 11.1% | 5.2%–22.2% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 2 | 9.5% | 2.6%–28.9% |
| high | 42 | 7 | 16.7% | 8.3%–30.6% |
| medium | 137 | 15 | 10.9% | 6.8%–17.3% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 1 | 100.0% | 20.6%–100.0% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 1 | 33.3% | 6.2%–79.2% |
| 2018 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2019 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2020 | 6 | 1 | 16.7% | 3.0%–56.4% |
| 2021 | 5 | 1 | 20.0% | 3.6%–62.5% |
| 2022 | 24 | 2 | 8.3% | 2.3%–25.9% |
| 2023 | 26 | 2 | 7.7% | 2.1%–24.1% |
| 2024 | 48 | 6 | 12.5% | 5.9%–24.7% |
| 2025 | 55 | 6 | 10.9% | 5.1%–21.8% |
| 2026 | 16 | 2 | 12.5% | 3.5%–36.0% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*