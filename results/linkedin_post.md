# LinkedIn Post

---

**Can AI fix real security vulnerabilities? We tested 16 frontier LLMs to find out.**

We built VulnBench — a benchmark of 200 real CVEs across 7 ecosystems and 55 vulnerability types — and evaluated every major LLM on security patch generation. The results are now public.

**Key findings:**

The best model (GPT-5.3 Codex) patches 57% of real-world vulnerabilities. The median model? Just ~22%. Even on the "easiest" category — pattern-matching fixes like XSS and SQL injection — no model breaks 62%.

**Top 5 Leaderboard (VulnBench-200):**
1. GPT-5.3 Codex — 57.0%
2. Claude Opus 4.6 — 45.5%
3. GPT-5.4 — 42.5%
4. Claude Sonnet 4.6 — 42.0%
5. GPT-5.2 — 42.0%

**What surprised us:**

- Cost doesn't predict quality. DeepSeek V3.2 costs $0.001/instance and hits 23.5% — while Gemini 3.1 Pro costs 50x more at $0.05/instance and only manages 6.5%.

- Deep reasoning vulnerabilities (code injection, resource exhaustion) aren't always harder than pattern-matching ones. GPT-5.4 actually scored higher on Tier 3 (48.5%) than Tier 2 (32.8%).

- The gap between frontier and mid-tier models is massive. The top 5 models all exceed 42%. After that, there's a steep cliff — #8 (Claude Haiku 4.5) is already down to 25%.

- Total cost to evaluate all 16 models across 200 instances: $49.34. LLM evaluation is remarkably cheap.

**How we scored:** LLM-as-judge (Claude Opus 4.6) comparing candidate patches against ground-truth fix commits — evaluating root cause, safety, and scope. This replaced deterministic diff-matching, which systematically undervalues correct patches with different syntax.

The full benchmark, evaluation harness, and all results are open source. Link in comments.

Presented at RSA Conference 2026.

#appsec #llm #cybersecurity #vulnerabilities #ai #benchmark #opensecurity

---
