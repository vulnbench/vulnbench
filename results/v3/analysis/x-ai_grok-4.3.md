# x-ai/grok-4.3 — VulnBench performance analysis

*Runs: 3 · Judges: openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hint mode: description · source context: True · max_tokens: 16384*

## Why this model performed the way it did

x-ai/grok-4.3 passed 24/200 instances (12.0%, 95% CI 8.2%–17.2%) with a mean judge score of 0.266.

Across 3 independent runs the pass rate was 12.5%, 11.5%, 12.0% (mean 12.0% ± 0.5%); 19.0% of instances passed in at least one run and 4.5% passed in every run — the gap between those two numbers is the model's run-to-run variance.

Of the 176 failed instances in the reference run: 98 (56%) because the patch modifies files unrelated to the ground-truth fix; 34 (19%) because the model understood the issue but the fix was judged inadequate; 33 (19%) because the patch was judged irrelevant to the vulnerability.

Relative strengths: primary cwe CWE-1321: 60% vs suite median 40% (n=5).

Relative weaknesses: ecosystem maven: 0% vs suite median 20% (n=5); cve year 2020: 0% vs suite median 17% (n=6); cve year 2018: 0% vs suite median 14% (n=7); cve year 2022: 0% vs suite median 12% (n=24); difficulty tier tier_3: 9% vs suite median 21% (n=66).

Cost: $0.57 total generation spend, $0.02 per passing patch, median generation time 12s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| wrong_file | 98 | the patch modifies files unrelated to the ground-truth fix |
| insufficient_fix | 34 | the model understood the issue but the fix was judged inadequate |
| off_target | 33 | the patch was judged irrelevant to the vulnerability |
| near_miss | 11 | the judge scored the patch just below the pass threshold |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 176 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 7 | 10.4% | 5.1%–20.0% |
| tier_2 | 67 | 11 | 16.4% | 9.4%–27.1% |
| tier_3 | 66 | 6 | 9.1% | 4.2%–18.4% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 3 | 60.0% | 23.1%–88.2% |
| CWE-1333 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-20 | 23 | 3 | 13.0% | 4.5%–32.1% |
| CWE-200 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-22 | 25 | 4 | 16.0% | 6.4%–34.6% |
| CWE-23 | 1 | 0 | 0.0% | 0.0%–79.3% |
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
| CWE-400 | 25 | 1 | 4.0% | 0.7%–19.5% |
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
| CWE-79 | 38 | 3 | 7.9% | 2.7%–20.8% |
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
| maven | 5 | 0 | 0.0% | 0.0%–43.5% |
| npm | 134 | 18 | 13.4% | 8.7%–20.2% |
| pip | 54 | 6 | 11.1% | 5.2%–22.2% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 3 | 14.3% | 5.0%–34.6% |
| high | 42 | 6 | 14.3% | 6.7%–27.8% |
| medium | 137 | 15 | 10.9% | 6.8%–17.3% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 0 | 0.0% | 0.0%–79.3% |
| 2016 | 2 | 0 | 0.0% | 0.0%–65.8% |
| 2017 | 3 | 1 | 33.3% | 6.2%–79.2% |
| 2018 | 7 | 0 | 0.0% | 0.0%–35.4% |
| 2019 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2020 | 6 | 0 | 0.0% | 0.0%–39.0% |
| 2021 | 5 | 2 | 40.0% | 11.8%–76.9% |
| 2022 | 24 | 0 | 0.0% | 0.0%–13.8% |
| 2023 | 26 | 3 | 11.5% | 4.0%–29.0% |
| 2024 | 48 | 6 | 12.5% | 5.9%–24.7% |
| 2025 | 55 | 9 | 16.4% | 8.9%–28.3% |
| 2026 | 16 | 2 | 12.5% | 3.5%–36.0% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*