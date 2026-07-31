# mistralai/mistral-medium-3-5 — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4.8 · hint mode: description · source context: True · max_tokens: 4096*

## Why this model performed the way it did

mistralai/mistral-medium-3-5 passed 14/200 instances (7.0%, 95% CI 4.2%–11.4%) with a mean judge score of 0.158.

Across 3 independent runs the pass rate was 5.0%, 7.0%, 7.0% (mean 6.3% ± 1.1%); 12.0% of instances passed in at least one run and 1.0% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 186 failed instances in the reference run: 136 (73%) because the patch modifies files unrelated to the ground-truth fix; 24 (13%) because the patch was judged irrelevant to the vulnerability; 19 (10%) because the model understood the issue but the fix was judged inadequate.

Judge reasoning on failures clusters on 'root-cause-missed' (60 instances): its patches most often treated symptoms rather than the underlying root cause.

Relative weaknesses: cve year 2019: 0% vs suite median 14% (n=7).

Cost: $1.16 total generation spend, $0.08 per passing patch, median generation time 8s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| wrong_file | 136 | the patch modifies files unrelated to the ground-truth fix |
| off_target | 24 | the patch was judged irrelevant to the vulnerability |
| insufficient_fix | 19 | the model understood the issue but the fix was judged inadequate |
| near_miss | 4 | the judge scored the patch just below the pass threshold |
| not_a_diff | 3 | the model responded with prose or code instead of a unified diff |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| root-cause-missed | 60 |
| wrong-location | 54 |
| other | 43 |
| incomplete-scope | 24 |
| regression-risk | 3 |
| invalid-patch | 2 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 4 | 6.0% | 2.4%–14.4% |
| tier_2 | 67 | 6 | 9.0% | 4.2%–18.2% |
| tier_3 | 66 | 4 | 6.1% | 2.4%–14.6% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 1 | 20.0% | 3.6%–62.5% |
| CWE-1333 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-20 | 23 | 1 | 4.3% | 0.8%–21.0% |
| CWE-200 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-22 | 25 | 3 | 12.0% | 4.2%–30.0% |
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
| CWE-770 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-78 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-79 | 38 | 1 | 2.6% | 0.5%–13.5% |
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
| maven | 5 | 1 | 20.0% | 3.6%–62.5% |
| npm | 134 | 9 | 6.7% | 3.6%–12.3% |
| pip | 54 | 4 | 7.4% | 2.9%–17.5% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 1 | 4.8% | 0.9%–22.7% |
| high | 42 | 4 | 9.5% | 3.8%–22.1% |
| medium | 137 | 9 | 6.6% | 3.5%–12.0% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 0 | 0.0% | 0.0%–79.3% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 0 | 0.0% | 0.0%–56.1% |
| 2018 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2019 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2020 | 6 | 0 | 0.0% | 0.0%–39.0% |
| 2021 | 5 | 1 | 20.0% | 3.6%–62.5% |
| 2022 | 24 | 1 | 4.2% | 0.7%–20.2% |
| 2023 | 26 | 2 | 7.7% | 2.1%–24.1% |
| 2024 | 48 | 3 | 6.2% | 2.1%–16.8% |
| 2025 | 55 | 6 | 10.9% | 5.1%–21.8% |
| 2026 | 16 | 1 | 6.2% | 1.1%–28.3% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*