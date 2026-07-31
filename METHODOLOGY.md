# VulnBench Evaluation Methodology (Protocol v2)

This document is the normative specification for producing publishable
VulnBench numbers. Anything not measured under this protocol must be labeled
as such. Protocol v1 results (published before 2026-07) are affected by the
issues in [Appendix B](#appendix-b-why-v1-results-were-retired) and must not
be mixed with v2 results.

## Task definition

Each instance gives a model:

1. A sanitized CVE advisory (description, CWE, severity, package) with fix
   commits, patch URLs, and "fixed in version" references removed.
2. CWE-class guidance (identical text for every model).
3. Vulnerable source context: up to 3 files / 6,000 characters from the
   affected repository snapshot, localized by filenames appearing in the
   advisory text (`--file-hint-mode description`). When the advisory names no
   files, the instance carries **no source context**; this is uniform across
   models and reported as `source_context_present` per instance.
4. Instructions to output a minimal unified diff.

The model must produce a unified diff that fixes the vulnerability's root
cause. `--file-hint-mode gold` (file hints derived from the reference fix) is
an ablation and is never mixed into the main leaderboard.

## Generation settings (identical for every model)

| Setting | Value | Rationale |
|---|---|---|
| Temperature | 0.0 | Determinism where providers honor it |
| Completion budget | 16,384 tokens (includes provider reasoning) | Reasoning models must not exhaust the budget before emitting content |
| Truncation escalation | If content is empty and the budget was exhausted, retry once at 32,768 tokens, then once with provider reasoning excluded | Applied uniformly — no per-model special cases |
| Adapter retries | 3 attempts, exponential backoff, empty responses retried | Transient provider failures must not score as model failures |
| Provider routing | OpenRouter, default routing | Recorded per response |

Every instance result records `finish_reason`, `truncated`,
`empty_after_retries`, `generation_error`, attempt counts, and token/cost
accounting, so harness artifacts are distinguishable from model failures in
the published data.

## Judging

Stored patches are scored by a **pinned cross-vendor judge panel**:

- `openrouter/anthropic/claude-opus-4.8`
- `openrouter/openai/gpt-5.5`

Each judge sees the sanitized advisory, the gold (reference) patch, and the
candidate patch, and returns `{score, verdict, reasoning}` at temperature 0.
A single judge's normalized verdict is `pass` iff its raw verdict is `pass`
**and** its score ≥ 0.5. The judge prompt states explicitly that a candidate
does not need to match the gold patch — semantically different but valid
fixes should pass.

**Consensus rule (`adjudicated_majority`):**

- Both judges pass → pass. Both fail → fail.
- Split → a third cross-vendor adjudicator judge
  (`openrouter/google/gemini-3.5-flash` by default) breaks the tie, making
  the effective rule majority-of-3.
- If no adjudicator is configured, a split resolves to **fail** and the
  report is stamped `fail_on_tie_no_adjudicator`.

Judge identity, panel composition, and voting rule are stamped into every
report. Reports judged under different panels are **never ranked in the same
table**; `benchmark.rejudge` re-scores stored patches under the pinned panel
when the panel changes (generation is never silently redone).

Known limitation: LLM judges are imperfect and same-vendor judging risks
self-preference bias. The panel is cross-vendor, split decisions are
adjudicated by a third vendor, and `benchmark.judge_validation` supports
exporting human-review samples and measuring inter-judge agreement. Judge
disagreement rates are published with each release.

## Metrics and statistics

- **Primary metric:** mean pass rate across 3 independent runs, with a 95%
  Wilson interval over pooled trials (600 for VulnBench-200).
- **Secondary:** `pass@3` (passed in ≥1 run) and `all-runs` (passed in every
  run), reported separately and labeled. "Best run of N" is **not** reported:
  selecting the maximum of noisy runs inflates scores by selection bias.
- **Ranking:** leaderboard rows are assigned statistical tie groups via a
  paired bootstrap over instances (10,000 resamples, α = 0.05). Rows in the
  same group are reported as ties.
- **Quality gate:** a leaderboard row is publishable only if infrastructure
  failures (adapter errors, judge errors, empty-after-retries responses)
  affect < 2% of its instances. Rows failing the gate are listed separately
  with the failure rate, not ranked.
- **Answer rate** (share of instances with a parseable non-empty diff) is
  published beside pass rate so format/latency issues are visible rather
  than silently folded into "capability."

## Provenance and reproducibility

Every report stamps: harness git commit, dataset SHA-256, benchmark path,
model ID, all adapter parameters, judge panel and voting rule, and
evaluation timestamp. Published leaderboards state the exact dataset version
and harness commit they were produced from. The per-model analysis
(`benchmark.model_report`) is generated from stored results only and is
reproducible byte-for-byte from the repository.

## Dataset

Instances derive from the GitHub Advisory Database enriched with NVD
metadata; the gold patch is the advisory's fix commit. Sanitization removes
direct patch pointers from prompt-visible text (`benchmark.sanitize_dataset`
re-checks existing files). Dataset releases are versioned; VulnBench-200 and
VulnBench-1650 stats (severity, CWE, tier distributions) are reported per
dataset version in the README.

### Contamination

CVEs and their fixes are public. Models may have seen the gold patch in
training. Mitigations and disclosures:

- Pass rates are reported **by CVE year** in every per-model analysis;
  a model whose pass rate is dramatically higher on pre-cutoff CVEs is
  flagged in its analysis card.
- 55% of instances postdate 2024, and instances from 2025–2026 postdate
  most current training cutoffs; year-sliced results allow readers to
  weight recent instances.
- We do not claim contamination-freedom. The benchmark measures patch
  generation under realistic disclosure conditions, and the year-sliced
  view bounds the effect.

### Difficulty tiers

Tiers are assigned by CWE class heuristics (pattern / logic / deep). They
are a browsing aid, not a validated difficulty measure; observed pass rates
do not always order tier 3 below tier 2. Rankings never depend on tier
weighting.

## Per-model analysis output

`python -m benchmark.model_report` produces, for every model, a markdown
card and JSON payload answering *why* the model scored what it scored:

- pass rate by CWE, difficulty tier, ecosystem, severity, and CVE year with
  Wilson intervals, and deviations from the suite median;
- a failure-mode taxonomy (adapter error, empty response, non-diff output,
  truncation, wrong-file patch, near-miss, insufficient fix, off-target);
- clustering of judge fail reasoning (wrong location, incomplete scope,
  root cause missed, regression risk, invalid patch);
- run-to-run variance, cost, latency, and token statistics;
- a deterministic narrative summarizing the above.

These cards are part of the benchmark's published output; the suite index
(`results/analysis/README.md`) is the canonical leaderboard rendering and
enforces the comparability grouping described above.

---

## Appendix A: Reproducing a leaderboard row

```bash
python -m benchmark.run_best_of_n \
    --benchmark data/benchmark/vulnbench_200.json \
    --model openrouter/<vendor>/<model> \
    --runs 3 \
    --include-source \
    --file-hint-mode description \
    --output results/best3_<vendor>_<model>.json

python -m benchmark.model_report \
    --benchmark data/benchmark/vulnbench_200.json \
    --reports results/run?_openrouter_<vendor>_<model>.json \
    --output-dir results/analysis
```

## Appendix B: Why v1 results were retired

The v1 published leaderboards (RSA 2026 era) were retired after an internal
audit (2026-07; 81 verified findings, full record in `REVIEW_FINDINGS.md`).
The defects that invalidated the published numbers:

1. **Token-budget artifact.** Generation used a 4,096-token completion
   budget that included provider reasoning. Reasoning-heavy models exhausted
   it and returned empty text on a large share of instances (up to 200/200
   for one model), which was scored as failure. Rankings partially measured
   token-budget behavior, not patching ability.
2. **Mixed judges.** One leaderboard combined rows scored by three different
   judge regimes: Claude Opus 4.6 solo, Claude Opus 4.8 solo (including
   Anthropic models judged by an Anthropic judge), and a two-judge panel
   used for one model only.
3. **Retroactive tie rule + self-judging.** The panel's split-vote rule was
   flipped from tie→fail to tie→pass after runs completed and stored
   results were re-scored under it — with GPT-5.5 simultaneously a panel
   judge and the #2-ranked competitor, its own vote decisive on 10 of its
   66 published passes.
4. **Ratchet merge.** The published site merged old and re-run rows with a
   keep-prior-unless-improved rule — a one-way selection filter — on top of
   a validation rerun in which 43.5% of rows were provider billing failures
   scored as 0.0.
5. **Best-of-3 selection bias.** The published number was the best whole
   run of three by pass rate, inflating scores by run-level noise.
6. **Per-model special-casing.** One model had provider reasoning disabled
   by default in the adapter and absorbed its provider's failures as model
   failures; no other model was configured specially.
7. **Infrastructure failures scored as model failures**, invisible in the
   published tables (no finish_reason, no error fields in old results).
8. **Documentation drift.** The stated pass rule (verdict pass AND score
   ≥ 0.5) was violated by 42 published passes; the README described judges
   and dataset statistics that did not match the code or data.

Protocol v2 removes all of these: uniform escalating budgets, a pinned
cross-vendor panel with adjudicated ties and self-judging exclusion,
mean-of-runs reporting with intervals, artifact quality gates, provenance
stamping, and no per-model configuration of any kind. Dataset-level issues
(snapshot mismatch, gold-patch validity, duplicates, licensing) are tracked
in `REVIEW_FINDINGS.md` for the next dataset release.
