# openai/gpt-5.3-codex — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hint mode: description · source context: True · max_tokens: 16384*

## Why this model performed the way it did

openai/gpt-5.3-codex passed 77/200 instances (38.5%, 95% CI 32.0%–45.4%) with a mean judge score of 0.496.

Across 3 independent runs the pass rate was 34.5%, 34.0%, 38.5% (mean 35.7% ± 2.5%); 50.5% of instances passed in at least one run and 20.5% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 123 failed instances in the reference run: 72 (59%) because the patch modifies files unrelated to the ground-truth fix; 24 (20%) because the model understood the issue but the fix was judged inadequate; 19 (15%) because the judge scored the patch just below the pass threshold.

Relative strengths: cve year 2020: 83% vs suite median 17% (n=6); cve year 2018: 71% vs suite median 14% (n=7); primary cwe CWE-94: 50% vs suite median 22% (n=18); primary cwe CWE-20: 43% vs suite median 17% (n=23); primary cwe CWE-400: 36% vs suite median 12% (n=25).

Relative weaknesses: primary cwe CWE-1321: 20% vs suite median 40% (n=5).

Cost: $6.49 total generation spend, $0.08 per passing patch, median generation time 23s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| wrong_file | 72 | the patch modifies files unrelated to the ground-truth fix |
| insufficient_fix | 24 | the model understood the issue but the fix was judged inadequate |
| near_miss | 19 | the judge scored the patch just below the pass threshold |
| off_target | 8 | the patch was judged irrelevant to the vulnerability |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 123 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 26 | 38.8% | 28.1%–50.8% |
| tier_2 | 67 | 23 | 34.3% | 24.1%–46.3% |
| tier_3 | 66 | 28 | 42.4% | 31.2%–54.4% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-1321 | 5 | 1 | 20.0% | 3.6%–62.5% |
| CWE-1333 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-20 | 23 | 10 | 43.5% | 25.6%–63.2% |
| CWE-200 | 4 | 1 | 25.0% | 4.6%–69.9% |
| CWE-22 | 25 | 12 | 48.0% | 30.0%–66.5% |
| CWE-23 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-287 | 3 | 2 | 66.7% | 20.8%–93.8% |
| CWE-290 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-295 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-325 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-330 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-347 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-352 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-367 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-384 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-400 | 25 | 9 | 36.0% | 20.2%–55.5% |
| CWE-402 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-434 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-444 | 1 | 1 | 100.0% | 20.6%–100.0% |
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
| CWE-755 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-77 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-770 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-78 | 3 | 1 | 33.3% | 6.2%–79.2% |
| CWE-79 | 38 | 14 | 36.8% | 23.4%–52.7% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-918 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-94 | 18 | 9 | 50.0% | 29.0%–71.0% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 1 | 50.0% | 9.4%–90.5% |
| maven | 5 | 1 | 20.0% | 3.6%–62.5% |
| npm | 134 | 55 | 41.0% | 33.1%–49.5% |
| pip | 54 | 19 | 35.2% | 23.8%–48.5% |
| rubygems | 3 | 1 | 33.3% | 6.2%–79.2% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 8 | 38.1% | 20.8%–59.1% |
| high | 42 | 17 | 40.5% | 27.0%–55.5% |
| medium | 137 | 52 | 38.0% | 30.3%–46.3% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 1 | 100.0% | 20.6%–100.0% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 2 | 66.7% | 20.8%–93.8% |
| 2018 | 7 | 5 | 71.4% | 35.9%–91.8% |
| 2019 | 7 | 2 | 28.6% | 8.2%–64.1% |
| 2020 | 6 | 5 | 83.3% | 43.6%–97.0% |
| 2021 | 5 | 3 | 60.0% | 23.1%–88.2% |
| 2022 | 24 | 7 | 29.2% | 14.9%–49.2% |
| 2023 | 26 | 8 | 30.8% | 16.5%–50.0% |
| 2024 | 48 | 17 | 35.4% | 23.4%–49.6% |
| 2025 | 55 | 23 | 41.8% | 29.7%–55.0% |
| 2026 | 16 | 4 | 25.0% | 10.2%–49.5% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*