<p align="center">
  <img src="docs/vuln_bench.png" alt="VulnBench" width="600">
</p>

# VulnBench: Can LLMs Fix Real-World Security Vulnerabilities?

**A benchmark for evaluating large language models on open-source security patch generation.**

VulnBench contains a **full benchmark of 1,650 real CVEs** and a **curated evaluation subset of 200 instances**. The public leaderboard in this repo is currently reported on the curated `VulnBench-200` subset, not the full benchmark. The evaluation harness can include vulnerable source context at runtime and supports both no-hint and gold-hint localization modes.

> Presented at **RSA Conference 2026** by [Ghost Security](https://ghost.security)

---

## Key Findings

On the curated `VulnBench-200` subset, the best model — **GPT-5.3 Codex** — successfully patches **57% of instances**, while the median model achieves only ~22%. No model exceeds 62% on even the easiest vulnerability class (Tier 1: pattern-matching fixes like XSS and SQL injection), revealing significant room for improvement in AI-assisted security remediation.

### VulnBench-200 Leaderboard

This leaderboard is for the **curated 200-instance evaluation subset**. It should not be treated as equivalent to a full-benchmark score.

| Rank | Model | Pass Rate | Mean Score | Instances | Cost |
|:----:|-------|:---------:|:----------:|:---------:|-----:|
| 1 | **OpenAI GPT-5.3 Codex** | **57.0%** | 0.514 | 111/200 | $6.24 |
| 2 | Anthropic Claude Opus 4.6 | 45.5% | 0.457 | 91/200 | $6.46 |
| 3 | OpenAI GPT-5.4 | 42.5% | 0.431 | 85/200 | $1.94 |
| 4 | Anthropic Claude Sonnet 4.6 | 42.0% | 0.419 | 84/200 | $3.65 |
| 5 | OpenAI GPT-5.2 | 42.0% | 0.374 | 84/200 | $8.50 |
| 6 | Google Gemini 3 Flash | 33.5% | 0.373 | 67/200 | $0.34 |
| 7 | Moonshot Kimi K2.5 | 29.0% | 0.301 | 58/200 | $1.98 |
| 8 | Anthropic Claude Haiku 4.5 | 25.0% | 0.317 | 50/200 | $1.06 |
| 9 | DeepSeek V3.2 | 23.5% | 0.314 | 47/200 | $0.17 |
| 10 | Zhipu GLM-5 | 19.5% | 0.268 | 39/200 | $2.32 |
| 11 | OpenAI GPT-5 Mini | 17.5% | 0.307 | 35/200 | $0.71 |
| 12 | Qwen 3.5-27B | 15.0% | 0.259 | 30/200 | $4.53 |
| 13 | MiniMax M2.5 | 14.5% | 0.248 | 29/200 | $0.47 |
| 14 | Qwen 3.5-35B-A3B | 11.0% | 0.235 | 22/200 | $1.01 |
| 15 | Google Gemini 3.1 Pro | 6.5% | 0.093 | 13/200 | $9.96 |
| 16 | StepFun Step 3.5 Flash | 0.0% | 0.000 | 0/200 | $0.00 |

*All models evaluated on identical 200 CVE instances. Total evaluation cost across all 16 models: $49.34.*

### Performance by Difficulty Tier

| Model | Tier 1 (Pattern) | Tier 2 (Logic) | Tier 3 (Deep) |
|-------|:-----------------:|:---------------:|:--------------:|
| GPT-5.3 Codex | 61.2% | 53.7% | 51.5% |
| Claude Opus 4.6 | 50.7% | 43.3% | 42.4% |
| GPT-5.4 | 46.3% | 32.8% | 48.5% |
| Claude Sonnet 4.6 | 41.8% | 40.3% | 43.9% |
| GPT-5.2 | 47.8% | 41.8% | 36.4% |
| Gemini 3 Flash | 35.8% | 26.9% | 37.9% |

**Tier 1** = Pattern-matching fixes (XSS, SQL injection, path traversal)
**Tier 2** = Logic fixes (authorization, CSRF, information disclosure)
**Tier 3** = Deep reasoning (code injection, resource exhaustion, input validation)

### Best Value Models

| Model | Pass Rate | Cost per Instance | Cost per Pass |
|-------|:---------:|:-----------------:|:-------------:|
| DeepSeek V3.2 | 23.5% | $0.001 | $0.004 |
| Gemini 3 Flash | 33.5% | $0.002 | $0.005 |
| GPT-5.4 | 42.5% | $0.010 | $0.023 |
| Claude Sonnet 4.6 | 42.0% | $0.018 | $0.043 |
| GPT-5.3 Codex | 57.0% | $0.031 | $0.056 |

---

## About VulnBench

### Dataset

VulnBench is constructed from real CVEs sourced from the GitHub Advisory Database, enriched with NVD metadata:

| Property | Value |
|----------|-------|
| **CVEs in database** | 10,000+ (2013-2026) |
| **Benchmark instances** | 1,650 (full) / 200 (curated evaluation subset) |
| **Unique repositories** | 888 (full) / 200 (curated subset) |
| **Ecosystems** | npm, pip, Maven, RubyGems, Composer, Rust, Swift |
| **CWE types** | 55 unique |
| **Severity distribution** | 21 critical, 42 high, 137 medium |
| **Mean patch size** | 36 lines changed across 1.9 files |
| **CVE year range** | 2013-2026 (55% from 2024-2026) |
| **Difficulty tiers** | Balanced: 67 / 67 / 66 |

### Top CWE Categories

| CWE | Description | Count |
|-----|------------|:-----:|
| CWE-79 | Cross-Site Scripting (XSS) | 38 |
| CWE-22 | Path Traversal | 25 |
| CWE-400 | Uncontrolled Resource Consumption | 25 |
| CWE-20 | Improper Input Validation | 23 |
| CWE-94 | Code Injection | 19 |
| CWE-1321 | Prototype Pollution | 5 |
| CWE-1333 | ReDoS | 5 |
| CWE-89 | SQL Injection | 4 |
| CWE-200 | Information Disclosure | 4 |

### Evaluation Methodology

Each model receives:
1. The CVE description and severity information
2. CWE-specific guidance for the vulnerability class
3. Optional vulnerable source context from the affected repository snapshot
4. Optional file localization hints, configurable at evaluation time
5. Instructions to generate a minimal unified diff that fixes the vulnerability

Default evaluation settings in this repo are conservative:

- `--include-source` is enabled by default
- `--file-hint-mode description` derives file localization only from filenames present in the advisory text
- `--file-hint-mode gold` is still supported for ablations, but should be reported separately because those hints come from the reference fix
- Benchmark generation scrubs direct patch hashes, commit URLs, exact fix references, and versioned patch hints from advisory text

**Scoring** uses an LLM-as-judge approach (Claude Opus 4.6) that compares each candidate patch against the ground-truth fix commit:

- **Root cause**: Does the patch address the underlying vulnerability?
- **Safety**: Does it avoid introducing new security issues?
- **Scope**: Does it cover the full extent of the required fix?
- Score range: 0.0 - 1.0. An instance passes only when the judge returns `verdict="pass"` and `score >= 0.5`

The harness stores normalized and raw judge verdicts, flags score/verdict disagreements, and tracks judge cost separately so judge behavior can be audited directly.

---

## Reproduce the Results

### Requirements

- Python 3.10+
- `gh` CLI (authenticated via `gh auth login`)
- OpenRouter API key (or individual provider keys)

### Setup

```bash
git clone https://github.com/vulnbench/vulnbench.git
cd vulnbench
pip install -r requirements.txt

# Set your API key
echo "OPENROUTER_API_KEY=sk-or-..." > .env
```

### Run Evaluation

```bash
# Single model
python -m benchmark.run_eval \
    --benchmark data/benchmark/vulnbench_200.json \
    --model openrouter/openai/gpt-5.4 \
    --include-source \
    --file-hint-mode description \
    --output results/my_eval.json

# Compare multiple models
python -m benchmark.compare \
    --benchmark data/benchmark/vulnbench_200.json \
    --models openrouter/openai/gpt-5.4 openrouter/anthropic/claude-sonnet-4.6 \
    --include-source \
    --file-hint-mode description \
    --output results/comparison.json

# Best-of-N runs (report separately from single-run scores)
python -m benchmark.run_best_of_n \
    --benchmark data/benchmark/vulnbench_200.json \
    --model openrouter/openai/gpt-5.4 \
    --runs 3 \
    --include-source \
    --file-hint-mode description \
    --output results/best3_gpt-5.4.json
```

### Judge Validation

```bash
# Summarize contradictions / near-threshold cases
python -m benchmark.judge_validation \
    --report results/my_eval.json

# Export a human review sample
python -m benchmark.judge_validation \
    --report results/my_eval.json \
    --sample-output results/my_eval_review_sample.json \
    --sample-size 50

# Compare multiple reports (for inter-judge agreement or reruns)
python -m benchmark.judge_validation \
    --compare results/eval_judge_a.json results/eval_judge_b.json
```

### Sanitize Existing Benchmark Files

```bash
python -m benchmark.sanitize_dataset \
    data/benchmark/vulnbench_full.json \
    data/benchmark/vulnbench_200.json \
    data/benchmark/vulnbench_mini.json
```

### Build Dataset from Scratch

```bash
# Full pipeline: collect CVEs -> enrich -> resolve -> version -> validate -> benchmark
python main.py

# Or run individual stages
python main.py --stage collect --limit 100
python main.py --stage benchmark --benchmark-mini-size 200
```

### Custom Judge Model

The default judge is Claude Opus 4.6 via OpenRouter. Override with any LiteLLM-compatible model:

```bash
python -m benchmark.run_eval \
    --benchmark data/benchmark/vulnbench_200.json \
    --model openrouter/openai/gpt-5.4 \
    --judge-model openrouter/openai/gpt-5.4
```

---

## Architecture

### Data Pipeline

Six sequential stages with checkpoint persistence (safe to interrupt and resume):

1. **Collect** — Fetch advisories from GitHub Advisory Database via `gh` CLI
2. **Enrich** — Add CVSS scores and CWE IDs from NVD API
3. **Resolve** — Map packages to GitHub repo URLs via registry lookups
4. **Version** — Find vulnerable versions, construct download URLs, extract fix commits
5. **Validate** — Deduplicate, filter incomplete records
6. **Benchmark** — Generate VulnBench instances with quality scoring and difficulty tiers

### Evaluation Harness

- `benchmark/run_eval.py` — Single-model evaluation with LLM judge
- `benchmark/compare.py` — Multi-model comparison with summary tables
- `benchmark/run_best_of_n.py` — Best-of-N runner for variance reduction
- `benchmark/adapters/` — Protocol-based model adapters (LiteLLM supports 100+ providers)

### Difficulty Tiers

| Tier | Category | CWE Examples | Description |
|:----:|----------|-------------|-------------|
| 1 | Pattern | CWE-79, CWE-89, CWE-22 | Well-known fix patterns (escape output, parameterize queries, sanitize paths) |
| 2 | Logic | CWE-862, CWE-352, CWE-200 | Requires understanding application logic (add auth checks, CSRF tokens) |
| 3 | Deep | CWE-94, CWE-400, CWE-20 | Requires deep reasoning about code execution, resource limits, input validation |

---

## Data Outputs

| File | Description |
|------|-------------|
| `data/cve_database.json` | Full CVE database (10,000+ records) |
| `data/benchmark/vulnbench_full.json` | Full benchmark (1,650 instances) |
| `data/benchmark/vulnbench_200.json` | Curated 200-instance evaluation subset |
| `results/v200_*.json` | Per-model evaluation reports |

---

## Citation

If you use VulnBench in your research, please cite:

```
@misc{vulnbench2026,
  title={VulnBench: Evaluating LLMs on Real-World Security Patch Generation},
  author={Ghost Security},
  year={2026},
  url={https://github.com/vulnbench/vulnbench}
}
```

## License

This project is provided for research purposes. The CVE data is sourced from public databases (GitHub Advisory Database, NVD). Benchmark instances reference publicly available open-source repositories.
