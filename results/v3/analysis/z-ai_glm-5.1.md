# z-ai/glm-5.1 — VulnBench performance analysis

*Runs: 1 · Judges: openrouter/anthropic/claude-opus-4.8, openrouter/openai/gpt-5.5 · hint mode: description · source context: True · max_tokens: 16384*

## Why this model performed the way it did

z-ai/glm-5.1 passed 36/200 instances (18.0%, 95% CI 13.3%–23.9%) with a mean judge score of 0.296.

Of the 164 failed instances in the reference run: 49 (30%) because the diff appears cut off by the completion token limit; 45 (27%) because the patch modifies files unrelated to the ground-truth fix; 24 (15%) because the provider/API call failed after retries (not a model capability signal).

In total, 25 failures (12%) were harness or provider artifacts (API errors, empty responses, exhausted budgets) rather than judged model mistakes. Under the v2 quality gate, rows above 2% artifacts are not publishable.

The model produced a parseable diff on only 85% of instances (answer rate); capability comparisons against models with higher answer rates are confounded until this is resolved.

Relative strengths: primary cwe CWE-1321: 80% vs suite median 40% (n=5); ecosystem maven: 40% vs suite median 20% (n=5); cve year 2019: 29% vs suite median 14% (n=7).

Relative weaknesses: cve year 2021: 20% vs suite median 40% (n=5); cve year 2020: 0% vs suite median 17% (n=6); cve year 2022: 0% vs suite median 12% (n=24).

Cost: $7.17 total generation spend, $0.20 per passing patch, median generation time 184s.

## Failure modes

| Mode | Count | Meaning |
|---|---:|---|
| likely_truncated | 49 | the diff appears cut off by the completion token limit |
| wrong_file | 45 | the patch modifies files unrelated to the ground-truth fix |
| adapter_error | 24 | the provider/API call failed after retries (not a model capability signal) |
| insufficient_fix | 21 | the model understood the issue but the fix was judged inadequate |
| off_target | 12 | the patch was judged irrelevant to the vulnerability |
| near_miss | 7 | the judge scored the patch just below the pass threshold |
| not_a_diff | 5 | the model responded with prose or code instead of a unified diff |
| budget_exhausted | 1 | the model spent the entire completion budget (likely on hidden reasoning) and returned no visible text — a harness/config artifact, not a capability signal |

## Judge reasoning clusters (failures)

| Cluster | Count |
|---|---:|
| other | 139 |

## By difficulty tier

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| tier_1 | 67 | 14 | 20.9% | 12.9%–32.1% |
| tier_2 | 67 | 10 | 14.9% | 8.3%–25.3% |
| tier_3 | 66 | 12 | 18.2% | 10.7%–29.1% |

## By CWE

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| CWE-125 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-1321 | 5 | 4 | 80.0% | 37.5%–96.4% |
| CWE-1333 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-20 | 23 | 4 | 17.4% | 7.0%–37.1% |
| CWE-200 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-22 | 25 | 6 | 24.0% | 11.5%–43.4% |
| CWE-23 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-235 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-248 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-284 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-285 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-287 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-290 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-295 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-325 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-330 | 1 | 1 | 100.0% | 20.6%–100.0% |
| CWE-347 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-352 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-367 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-384 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-400 | 25 | 4 | 16.0% | 6.4%–34.6% |
| CWE-402 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-434 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-444 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-470 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-476 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-506 | 1 | 1 | 100.0% | 20.6%–100.0% |
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
| CWE-770 | 2 | 1 | 50.0% | 9.4%–90.5% |
| CWE-78 | 3 | 0 | 0.0% | 0.0%–56.1% |
| CWE-79 | 38 | 8 | 21.1% | 11.1%–36.4% |
| CWE-830 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-862 | 1 | 0 | 0.0% | 0.0%–79.3% |
| CWE-863 | 2 | 0 | 0.0% | 0.0%–65.8% |
| CWE-89 | 4 | 0 | 0.0% | 0.0%–49.0% |
| CWE-918 | 2 | 2 | 100.0% | 34.2%–100.0% |
| CWE-94 | 18 | 4 | 22.2% | 9.0%–45.2% |

## By ecosystem

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| composer | 2 | 1 | 50.0% | 9.4%–90.5% |
| maven | 5 | 2 | 40.0% | 11.8%–76.9% |
| npm | 134 | 25 | 18.7% | 13.0%–26.1% |
| pip | 54 | 8 | 14.8% | 7.7%–26.6% |
| rubygems | 3 | 0 | 0.0% | 0.0%–56.1% |
| rust | 1 | 0 | 0.0% | 0.0%–79.3% |
| swift | 1 | 0 | 0.0% | 0.0%–79.3% |

## By severity

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| critical | 21 | 5 | 23.8% | 10.6%–45.1% |
| high | 42 | 7 | 16.7% | 8.3%–30.6% |
| medium | 137 | 24 | 17.5% | 12.1%–24.7% |

## By CVE year

| Value | n | Passed | Pass rate | 95% CI |
|---|---:|---:|---:|---|
| 2013 | 1 | 1 | 100.0% | 20.6%–100.0% |
| 2016 | 2 | 1 | 50.0% | 9.4%–90.5% |
| 2017 | 3 | 0 | 0.0% | 0.0%–56.1% |
| 2018 | 7 | 1 | 14.3% | 2.6%–51.3% |
| 2019 | 7 | 2 | 28.6% | 8.2%–64.1% |
| 2020 | 6 | 0 | 0.0% | 0.0%–39.0% |
| 2021 | 5 | 1 | 20.0% | 3.6%–62.5% |
| 2022 | 24 | 0 | 0.0% | 0.0%–13.8% |
| 2023 | 26 | 3 | 11.5% | 4.0%–29.0% |
| 2024 | 48 | 9 | 18.8% | 10.2%–31.9% |
| 2025 | 55 | 16 | 29.1% | 18.8%–42.1% |
| 2026 | 16 | 2 | 12.5% | 3.5%–36.0% |

---
*Generated by `benchmark.model_report` from stored evaluation results; no additional model calls were made. Wilson intervals; failure modes assigned by the first matching rule in the taxonomy.*