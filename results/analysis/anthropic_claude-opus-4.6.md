# anthropic/claude-opus-4.6 — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4-6 · hint mode: description · source context: True · max_tokens: 4096*

## Why this model performed the way it did

anthropic/claude-opus-4.6 passed 32/200 instances (16.0%, 95% CI 11.6%–21.7%) with a mean judge score of 0.404.

Across 3 independent runs the pass rate was 12.0%, 13.0%, 16.0% (mean 13.7% ± 2.1%); 20.5% of instances passed in at least one run and 7.0% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 168 failed instances in the reference run: 67 (40%) because the patch modifies files unrelated to the ground-truth fix; 49 (29%) because the judge scored the patch just below the pass threshold; 33 (20%) because the model understood the issue but the fix was judged inadequate.

Judge reasoning on failures clusters on 'incomplete-scope' (73 instances): its patches most often fixed part of the issue but missed other affected paths the gold fix covered.

Relative strengths: primary cwe CWE-1321: 60% vs suite median 20% (n=5); cve year 2022: 25% vs suite median 0% (n=24); severity critical: 24% vs suite median 0% (n=21); severity high: 24% vs suite median 5% (n=42); cve year 2025: 27% vs suite median 9% (n=55).

Cost: $6.86 total generation spend, $0.21 per passing patch, median generation time 19s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| wrong_file | 67 | the patch modifies files unrelated to the ground-truth fix |
| near_miss | 49 | the judge scored the patch just below the pass threshold |
| insufficient_fix | 33 | the model understood the issue but the fix was judged inadequate |
| off_target | 14 | the patch was judged irrelevant to the vulnerability |
| not_a_diff | 4 | the model responded with prose or code instead of a unified diff |
| likely_truncated | 1 | the diff appears cut off by the completion token limit |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| incomplete-scope | 73 |
| other | 38 |
| wrong-location | 38 |
| root-cause-missed | 12 |
| regression-risk | 4 |
| invalid-patch | 3 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 13 | 19.4% | 11.7%–30.4% |
| tier_2 | 67 | 9 | 13.4% | 7.2%–23.6% |
| tier_3 | 66 | 10 | 15.2% | 8.4%–25.7% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 3 | 60.0% | 23.1%–88.2% |
| CWE-1333 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-20 | 23 | 5 | 21.7% | 9.7%–41.9% |
| CWE-200 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-22 | 25 | 7 | 28.0% | 14.3%–47.6% |
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
| CWE-400 | 25 | 3 | 12.0% | 4.2%–30.0% |
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
| CWE-78 | 3 | 2 | 66.7% | 20.8%–93.8% |
| CWE-79 | 38 | 5 | 13.2% | 5.8%–27.3% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-918 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-94 | 18 | 2 | 11.1% | 3.1%–32.8% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 1 | 50.0% | 9.4%–90.5% |
| maven | 5 | 0 | 0.0% | 0.0%–43.5% |
| npm | 134 | 25 | 18.7% | 13.0%–26.1% |
| pip | 54 | 6 | 11.1% | 5.2%–22.2% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 5 | 23.8% | 10.6%–45.1% |
| high | 42 | 10 | 23.8% | 13.5%–38.5% |
| medium | 137 | 17 | 12.4% | 7.9%–19.0% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 1 | 100.0% | 20.6%–100.0% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 1 | 33.3% | 6.2%–79.2% |
| 2018 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2019 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2020 | 6 | 0 | 0.0% | 0.0%–39.0% |
| 2021 | 5 | 0 | 0.0% | 0.0%–43.5% |
| 2022 | 24 | 6 | 25.0% | 12.0%–44.9% |
| 2023 | 26 | 3 | 11.5% | 4.0%–29.0% |
| 2024 | 48 | 4 | 8.3% | 3.3%–19.6% |
| 2025 | 55 | 15 | 27.3% | 17.3%–40.2% |
| 2026 | 16 | 2 | 12.5% | 3.5%–36.0% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*