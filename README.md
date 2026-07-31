# VulnBench: Can LLMs Fix Real-World Security Vulnerabilities?

**A benchmark for evaluating large language models on open-source security patch generation.**

VulnBench contains a **full benchmark of 1,650 real CVEs** and a **curated evaluation subset of 200 instances**, built from the GitHub Advisory Database and NVD. Models receive a sanitized advisory (and, where localizable, vulnerable source context) and must produce a unified diff; a pinned cross-vendor LLM judge panel scores each patch against the ground-truth fix.

> Presented at **RSA Conference 2026** by [Ghost Security](https://ghost.security)

---

## Results (v3 — Protocol v2)

The current leaderboard is [**`RESULTS_V3.md`**](RESULTS_V3.md), produced
under the audited Protocol v2 harness (uniform token budget, pinned
cross-vendor judge panel, mean-of-3-runs with confidence intervals, no
model judging its own patches). Top of the board on the curated
200-instance benchmark:

| Rank | Model | Pass rate | 95% CI | pass@3 |
|---:|---|---:|:---:|---:|
| 1 | **anthropic/claude-opus-5** | 64.3% | 60.4–68.1% | 80.5% |
| 2 | openai/gpt-5.6-sol | 42.2% | 38.3–46.2% | 56.5% |
| 3 | openai/gpt-5.3-codex | 35.7% | 31.9–39.6% | 50.5% |

**Claude Opus 5 leads decisively** — roughly double the next-best model,
with non-overlapping intervals. Full 24-model table, tie groups, and
per-model "why" cards ([`results/v3/analysis/`](results/v3/analysis/README.md))
in `RESULTS_V3.md`. Five mid-tier models were still completing at
publication and are added in a follow-up; four latency-outlier models
(5–16 min/patch) are reported separately.

### Why the earlier numbers were retired

A 91-agent adversarial audit (see [`REVIEW_FINDINGS.md`](REVIEW_FINDINGS.md))
found the pre-v3 leaderboards were dominated by harness artifacts — chiefly a
4,096-token budget that reasoning models exhausted on hidden reasoning
(empty patches scored as failures on up to 100% of instances), plus
inconsistent judges across rows and a selection-biased best-of-3. Those
numbers are retired; all 81 findings and their fixes are in
`REVIEW_FINDINGS.md`, and the v3 results above supersede them. Gemini 3.1 Pro
is the clearest example of the fix: it sat near the bottom (~2%) in the old
leaderboard and lands at 31.2% (#6) under v3.

---

## About VulnBench

### Datasets

Two versioned datasets are shipped (sanitizer v2, 2026-07):

| Property | VulnBench-200 (curated) | VulnBench-1650 (full) |
|----------|------------------------|----------------------|
| Instances | 200 | 1,650 |
| Unique repositories | 200 | 888 |
| Unique primary CWEs | 48 | 207 |
| Severity (crit / high / med) | 21 / 42 / 137 | 214 / 448 / 988 |
| Difficulty tiers (1/2/3) | 67 / 67 / 66 | 354 / 1,106 / 190 |
| Ecosystems | npm 134, pip 54, maven 5, rubygems 3, other 4 | npm 1,163, pip 474, other 13 |
| Mean gold patch | 36 lines / 1.9 files | 69 lines / 3.2 files |
| CVE years | 2013–2026 (60% ≥ 2024) | 2013–2026 (59% ≥ 2024) |

Top CWE categories (curated set): XSS (CWE-79, 38), Path Traversal (CWE-22,
25), Resource Consumption (CWE-400, 25), Input Validation (CWE-20, 23),
Code Injection (CWE-94, 18).

The full set is more repo-concentrated and tier-imbalanced than the curated
set (tier 2 is the default bucket for unmapped CWEs); prefer the curated set
for model comparisons and treat tiers as a browsing aid, not a validated
difficulty scale.

### Evaluation protocol (v2 summary)

The complete normative specification is [`METHODOLOGY.md`](METHODOLOGY.md).
Highlights:

- **Identical treatment for every model.** Same prompts, temperature 0,
  16,384-token completion budget with a uniform escalation ladder when
  hidden reasoning exhausts it (retry at 32,768, then with reasoning
  excluded). No per-model configuration of any kind — enforced by test.
- **Pinned cross-vendor judge panel** (Claude Opus 4.8 + GPT-5.5): pass
  requires a strict majority AND median score ≥ 0.5; split votes are
  adjudicated by a third-vendor tie-breaker judge (Gemini 3.5 Flash).
  **No model ever judges its own patches** — a candidate appearing on the
  panel has its seat filled by the adjudicator.
- **Statistics, not point estimates.** Mean pass rate across 3 independent
  runs with 95% Wilson intervals; pass@3 reported separately; leaderboard
  ranks carry statistical tie groups from a paired bootstrap. "Best run of
  N" is never reported.
- **Artifact accounting.** Every instance records finish reason, truncation,
  parse mode, provider, retries, and judge quorum, so harness/provider
  failures are visible and gated (rows with > 2% artifacts are not
  publishable).
- **Provenance.** Every report stamps the harness git commit, dataset
  SHA-256, and all generation/judge parameters.

### Per-model "why" reports

`benchmark/model_report.py` turns raw results into the benchmark's most
useful output: for every model, a markdown card and JSON payload explaining
*why* it performed the way it did — failure-mode taxonomy (budget
exhaustion, empty response, non-diff output, wrong-file patch, near-miss,
insufficient fix), judge-reasoning clusters, pass rates by CWE / tier /
ecosystem / severity / CVE year with confidence intervals and deviations
from the suite median, run-to-run variance, and cost. The suite index it
generates is the canonical leaderboard rendering and refuses to rank models
evaluated under different judge configurations.

```bash
python -m benchmark.model_report \
    --benchmark data/benchmark/vulnbench_200.json \
    --reports results/run?_openrouter_*.json \
    --output-dir results/analysis
```

---

## Running an evaluation

### Requirements

- Python 3.9+
- OpenRouter API key (or individual provider keys via LiteLLM)
- `gh` CLI (only for building datasets from scratch)

### Security notice: litellm supply-chain attack

> **litellm 1.82.7 / 1.82.8 contain a malicious credential-stealing
> payload** ([BerriAI/litellm#24512](https://github.com/BerriAI/litellm/issues/24512)).
> VulnBench pins its dependency to exclude these versions and halts at
> startup if the malicious `litellm_init.pth` is detected. If you ever
> installed an affected version: remove it, delete the `.pth` file, and
> rotate all credentials.

### Setup

```bash
git clone https://github.com/vulnbench/vulnbench.git
cd vulnbench
pip install -r requirements.txt
echo "OPENROUTER_API_KEY=sk-or-..." > .env
```

### Single model, single run

```bash
python -m benchmark.run_eval \
    --benchmark data/benchmark/vulnbench_200.json \
    --model openrouter/openai/gpt-5.5 \
    --include-source \
    --file-hint-mode description \
    --output results/my_eval.json
```

### Leaderboard row (3 independent runs, mean ± CI)

```bash
python -m benchmark.run_best_of_n \
    --benchmark data/benchmark/vulnbench_200.json \
    --model openrouter/openai/gpt-5.5 \
    --runs 3 \
    --include-source \
    --file-hint-mode description \
    --output results/mean3_gpt-5.5.json
```

The summary report's `metadata.across_runs` holds the headline numbers
(mean pass rate, std, pooled Wilson CI, pass@3). Suite runners:
`./run_curated_200_best3.sh`, `./run_full_1650.sh` (models in
`benchmark/model_suites.sh`).

### Re-judging stored patches under a pinned panel

When the judge panel changes, stored patches are re-scored — generation is
never silently redone and mixed-judge tables are never published:

```bash
python -m benchmark.rejudge \
    --benchmark data/benchmark/vulnbench_200.json \
    --reports results/run?_openrouter_*.json \
    --judge-models openrouter/anthropic/claude-opus-4.8 openrouter/openai/gpt-5.5 \
    --output-dir results/rejudged \
    --dry-run   # prints judge-call count and cost estimate first
```

### Judge validation

```bash
python -m benchmark.judge_validation --report results/my_eval.json
python -m benchmark.judge_validation --report results/my_eval.json \
    --sample-output results/review_sample.json --sample-size 50
python -m benchmark.judge_validation --compare results/a.json results/b.json
```

### Sanitize / rebuild datasets

```bash
python -m benchmark.sanitize_dataset data/benchmark/vulnbench_200.json ...
python main.py                 # full pipeline: collect → enrich → resolve → version → validate → benchmark
```

---

## Limitations

Read before citing any VulnBench number:

- **LLM-as-judge.** Patches are scored by LLMs against the gold fix, not by
  executing tests. Judges are imperfect; the cross-vendor panel, third-vendor
  adjudication, self-judging exclusion, and stored per-judge artifacts
  mitigate but do not eliminate this. A mechanical apply-check and human
  calibration study are on the roadmap.
- **Contamination.** CVEs and their fixes are public and may appear in
  training data. Pass rates by CVE year are reported per model so readers
  can weight post-cutoff instances; contamination-freedom is not claimed.
- **Source context is partial.** With description-derived localization,
  most instances carry no source snippet (the advisory names no files);
  this is uniform across models and recorded per instance
  (`source_context_present`). Gold-hint mode requires a hints-retained
  dataset variant and is currently inert on the shipped datasets.
- **Dataset noise.** Known issues queued for the next dataset release:
  some source snapshots are not the exact pre-fix revision, some gold
  patches are release commits rather than code fixes, and the full set
  contains duplicate gold diffs and repo concentration. See
  `REVIEW_FINDINGS.md` for quantification.
- **Tiers are heuristic.** CWE-based tiers do not empirically order
  difficulty; rankings never depend on them.

---

## Repository layout

| Path | Purpose |
|------|---------|
| `benchmark/run_eval.py` | Core evaluation harness (prompt → patch → judge panel) |
| `benchmark/run_best_of_n.py` | Multi-run evaluation with mean ± CI reporting |
| `benchmark/rejudge.py` | Re-score stored patches under a pinned judge panel |
| `benchmark/model_report.py` | Per-model "why" cards + comparability-guarded leaderboard |
| `benchmark/stats.py` | Wilson CIs, paired bootstrap, tie groups |
| `benchmark/judge_validation.py` | Judge agreement / human-review sampling |
| `benchmark/sanitize_dataset.py` | Advisory leakage scrubbing (v2) |
| `benchmark/provenance.py` | Harness/dataset version stamping |
| `src/` | Dataset construction pipeline (GHSA → NVD → repo → instance) |
| `METHODOLOGY.md` | Normative evaluation protocol (v2) |
| `REVIEW_FINDINGS.md` | 2026-07 audit: 81 verified findings + remediation status |

## Citation

```
@misc{vulnbench2026,
  title={VulnBench: Evaluating LLMs on Real-World Security Patch Generation},
  author={Ghost Security},
  year={2026},
  url={https://github.com/vulnbench/vulnbench}
}
```

## License

**Not yet licensed** — a license grant (code + dataset) is pending; the CVE
metadata derives from the GitHub Advisory Database (CC-BY 4.0, attribution
being added) and NVD, and benchmark instances reference publicly available
open-source repositories whose individual licenses apply to quoted patch
content. Do not redistribute until this section is resolved.
