# VulnBench v3 — Results

*Generated 2026-07-31 · 25 models · curated 200-instance benchmark · best-of-3 · Protocol v2*

Each model generates a unified-diff patch for 200 real CVEs (no execution). A pinned
cross-vendor LLM-judge panel (Claude Opus 4.8 + GPT-5.5, Gemini 3.5 Flash adjudicating
splits; no model judges its own patches) scores each patch against the ground-truth fix.
Headline metric is **mean pass rate across 3 independent runs** with a 95% Wilson interval;
**pass@3** = solved in at least one run. All rows are artifact-free (0 API/judge failures).
Full methodology in [METHODOLOGY.md](METHODOLOGY.md).

## Leaderboard

| Rank | Model | Pass rate | 95% CI | pass@3 | Tie group |
|---:|---|---:|:---:|---:|:---:|
| 1 | **anthropic/claude-opus-5** | 64.3% | 60.4–68.1% | 80.5% | 1 |
| 2 | **openai/gpt-5.6-sol** | 42.2% | 38.3–46.2% | 56.5% | 2 |
| 3 | **openai/gpt-5.3-codex** | 35.7% | 31.9–39.6% | 50.5% | 2 |
| 4 | **openai/gpt-5.6-terra** | 33.3% | 29.7–37.2% | 47.5% | 3 |
| 5 | **openai/gpt-5.5** | 32.2% | 28.5–36.0% | 53.0% | 3 |
| 6 | **google/gemini-3.1-pro-preview** | 31.2% | 27.6–35.0% | 45.0% | 3 |
| 7 | **google/gemini-3.5-flash** | 28.5% | 25.0–32.2% | 41.0% | 3 |
| 8 | **google/gemini-3.6-flash** | 26.7% | 23.3–30.3% | 40.5% | 4 |
| 9 | **openai/gpt-5.6-luna** | 25.7% | 22.3–29.3% | 36.5% | 4 |
| 10 | **anthropic/claude-fable-5** | 24.7% | 21.4–28.3% | 33.0% | 4 |
| 11 | **x-ai/grok-build-0.1** | 23.7% | 20.4–27.2% | 37.0% | 4 |
| 12 | **x-ai/grok-4.5** | 21.8% | 18.7–25.3% | 40.0% | 4 |
| 13 | **anthropic/claude-opus-4.8** | 20.8% | 17.8–24.3% | 35.0% | 4 |
| 14 | **anthropic/claude-sonnet-5** | 19.7% | 16.7–23.0% | 33.0% | 4 |
| 15 | **anthropic/claude-sonnet-4.6** | 17.2% | 14.4–20.4% | 29.0% | 5 |
| 16 | **deepseek/deepseek-v4-pro** | 16.0% | 13.3–19.1% | 26.5% | 5 |
| 17 | **minimax/minimax-m3** | 12.3% | 9.9–15.2% | 21.0% | 5 |
| 18 | **x-ai/grok-4.3** | 12.0% | 9.6–14.8% | 19.0% | 5 |
| 19 | **google/gemini-3.5-flash-lite** | 11.8% | 9.5–14.7% | 19.0% | 5 |
| 20 | **nvidia/nemotron-3-ultra-550b-a55b** | 10.8% | 8.6–13.6% | 19.5% | 5 |
| 21 | **openai/gpt-5.4-mini** | 10.3% | 8.1–13.0% | 19.5% | 5 |
| 22 | **anthropic/claude-haiku-4.5** | 8.8% | 6.8–11.4% | 12.0% | 6 |
| 23 | **stepfun/step-3.7-flash** | 8.8% | 6.8–11.4% | 15.5% | 6 |
| 24 | **deepseek/deepseek-v4-flash** | 7.8% | 5.9–10.3% | 15.5% | 6 |
| 25 | **mistralai/mistral-medium-3-5** | 5.8% | 4.2–8.0% | 9.0% | 6 |

*Tie groups: models sharing one are statistically indistinguishable (paired bootstrap, p ≥ 0.05). Provenance: harness `e8d4338-dirty`, dataset `8534cdf4a976d07e`.*

## Headline

**anthropic/claude-opus-5 leads decisively at 64.3%** (95% CI 60.4–68.1%, pass@3 80.5%) — a 22-point margin over openai/gpt-5.6-sol (42.2%), non-overlapping CIs. It produced a passing patch for 80% of vulnerabilities within three attempts.

## Coverage & caveats

- **25 of 29 planned models** shown. Four mid-tier models (z-ai/glm-5.2, z-ai/glm-5.1, qwen/qwen3.7-plus, tencent/hy3) were still completing at publication and are added in a follow-up; they do not affect the top of the table.
- **Latency-excluded (reported separately):** moonshotai/kimi-k3, kimi-k2.7-code, kimi-k2.6, and qwen/qwen3.7-max generate 5–16 min per patch (measured), making best-of-3 infeasible on this timeline.
- Pass rates reflect judged patch quality without executable validation; see README Limitations.
