# anthropic/claude-opus-4.8 — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4.8 · hint mode: description · source context: True · max_tokens: 4096*

## Why this model performed the way it did

anthropic/claude-opus-4.8 passed 53/200 instances (26.5%, 95% CI 20.9%–33.0%) with a mean judge score of 0.421.

Across 3 independent runs the pass rate was 29.5%, 24.5%, 26.5% (mean 26.8% ± 2.5%); 44.5% of instances passed in at least one run and 10.0% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 147 failed instances in the reference run: 87 (59%) because the patch modifies files unrelated to the ground-truth fix; 24 (16%) because the model understood the issue but the fix was judged inadequate; 22 (15%) because the judge scored the patch just below the pass threshold.

Judge reasoning on failures clusters on 'root-cause-missed' (45 instances): its patches most often treated symptoms rather than the underlying root cause.

Relative strengths: ecosystem maven: 60% vs suite median 20% (n=5); cve year 2020: 33% vs suite median 0% (n=6); severity critical: 38% vs suite median 10% (n=21); cve year 2023: 35% vs suite median 8% (n=26); primary cwe CWE-20: 39% vs suite median 13% (n=23).

Cost: $8.38 total generation spend, $0.16 per passing patch, median generation time 18s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| wrong_file | 87 | the patch modifies files unrelated to the ground-truth fix |
| insufficient_fix | 24 | the model understood the issue but the fix was judged inadequate |
| near_miss | 22 | the judge scored the patch just below the pass threshold |
| off_target | 12 | the patch was judged irrelevant to the vulnerability |
| not_a_diff | 1 | the model responded with prose or code instead of a unified diff |
| likely_truncated | 1 | the diff appears cut off by the completion token limit |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| root-cause-missed | 45 |
| wrong-location | 38 |
| other | 34 |
| incomplete-scope | 29 |
| invalid-patch | 1 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 17 | 25.4% | 16.5%–36.9% |
| tier_2 | 67 | 17 | 25.4% | 16.5%–36.9% |
| tier_3 | 66 | 19 | 28.8% | 19.3%–40.6% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 2 | 40.0% | 11.8%–76.9% |
| CWE-1333 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-20 | 23 | 9 | 39.1% | 22.2%–59.2% |
| CWE-200 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-22 | 25 | 7 | 28.0% | 14.3%–47.6% |
| CWE-23 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-287 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-290 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-295 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-325 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-330 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-347 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-352 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-367 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-384 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-400 | 25 | 5 | 20.0% | 8.9%–39.1% |
| CWE-402 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-434 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-444 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-470 | 1 | 0 | 0.0% | 0.0%–79.3% |
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
| CWE-78 | 3 | 2 | 66.7% | 20.8%–93.8% |
| CWE-79 | 38 | 9 | 23.7% | 13.0%–39.2% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-918 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-94 | 18 | 5 | 27.8% | 12.5%–50.9% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 0 | 0.0% | 0.0%–65.8% |
| maven | 5 | 3 | 60.0% | 23.1%–88.2% |
| npm | 134 | 33 | 24.6% | 18.1%–32.6% |
| pip | 54 | 17 | 31.5% | 20.7%–44.7% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 8 | 38.1% | 20.8%–59.1% |
| high | 42 | 9 | 21.4% | 11.7%–35.9% |
| medium | 137 | 36 | 26.3% | 19.6%–34.2% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 0 | 0.0% | 0.0%–79.3% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 2 | 66.7% | 20.8%–93.8% |
| 2018 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2019 | 7 | 2 | 28.6% | 8.2%–64.1% |
| 2020 | 6 | 2 | 33.3% | 9.7%–70.0% |
| 2021 | 5 | 1 | 20.0% | 3.6%–62.5% |
| 2022 | 24 | 5 | 20.8% | 9.2%–40.5% |
| 2023 | 26 | 9 | 34.6% | 19.4%–53.8% |
| 2024 | 48 | 9 | 18.8% | 10.2%–31.9% |
| 2025 | 55 | 19 | 34.5% | 23.4%–47.8% |
| 2026 | 16 | 3 | 18.8% | 6.6%–43.0% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*