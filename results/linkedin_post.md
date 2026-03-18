# LinkedIn Post

---

**Can AI help patch real security vulnerabilities? We tested 16 frontier LLMs to find out.**

We built VulnBench — a full benchmark of 1,650 real CVEs plus a curated 200-instance evaluation subset across 7 ecosystems and 55 vulnerability types — and evaluated frontier LLMs on the curated subset. The results are now public.

**Key findings:**

On the curated 200-instance subset, the best model (GPT-5.3 Codex) patches 57% of instances. The median model? Just ~22%. Even on the "easiest" category — pattern-matching fixes like XSS and SQL injection — no model breaks 62%.

**Top 5 Leaderboard (Curated VulnBench-200 subset):**
1. GPT-5.3 Codex — 57.0%
2. Claude Opus 4.6 — 45.5%
3. GPT-5.4 — 42.5%
4. Claude Sonnet 4.6 — 42.0%
5. GPT-5.2 — 42.0%

**What surprised us:**

- Cost doesn't predict quality. DeepSeek V3.2 costs $0.001/instance and hits 23.5% — while Gemini 3.1 Pro costs 50x more at $0.05/instance and only manages 6.5%.

- Deep reasoning vulnerabilities (code injection, resource exhaustion) aren't always harder than pattern-matching ones. GPT-5.4 actually scored higher on Tier 3 (48.5%) than Tier 2 (32.8%).

- The gap between frontier and mid-tier models is massive. The top 5 models all exceed 42%. After that, there's a steep cliff — #8 (Claude Haiku 4.5) is already down to 25%.

- Total cost to evaluate all 16 models across the curated 200-instance subset: $49.34.

**How we scored:** LLM-as-judge (Claude Opus 4.6) comparing candidate patches against ground-truth fix commits — evaluating root cause, safety, and scope. The current repo now reports source-enabled runs, separates gold file-hint ablations, and includes judge-audit utilities for contradiction analysis and human review sampling.

The full benchmark, evaluation harness, and all results are open source. Link in comments.

Presented at RSA Conference 2026.

#appsec #llm #cybersecurity #vulnerabilities #ai #benchmark #opensecurity

---
