"""Per-model performance analysis ("why" reports) for VulnBench.

Consumes evaluation report JSONs plus the benchmark dataset and emits, for
each model, a markdown card and a JSON payload explaining WHERE the model
succeeded or failed (by CWE, difficulty tier, ecosystem, severity, CVE year)
and WHY (failure-mode taxonomy over patches and judge reasoning). Also emits
a suite index with a comparability-guarded leaderboard: rows are grouped by
evaluation configuration (judge panel, hint mode, source inclusion) and rows
evaluated under different configurations are never ranked against each other.

Everything is computed deterministically from stored results — no model or
judge API calls are made.

Usage:
    # One model, one or more repeated runs
    python -m benchmark.model_report \
        --benchmark data/benchmark/vulnbench_200.json \
        --reports results/run1_openrouter_openai_gpt-5.5.json \
                  results/run2_openrouter_openai_gpt-5.5.json \
        --output-dir results/analysis

    # Whole suite at once (files are grouped by metadata.model)
    python -m benchmark.model_report \
        --benchmark data/benchmark/vulnbench_200.json \
        --reports results/run?_openrouter_*.json \
        --output-dir results/analysis
"""

from __future__ import annotations

import argparse
import json
import logging
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from benchmark.stats import (
    extract_passed_map,
    multi_run_pass_summary,
    pass_rate_by,
    rank_tie_groups,
    wilson_interval,
)

logger = logging.getLogger(__name__)

DEFAULT_MAX_TOKENS = 4096
TRUNCATION_FRACTION = 0.98
MIN_BUCKET_N = 5

DIFF_FILE_RE = re.compile(r"^(?:diff --git a/(\S+) b/\S+|\+\+\+ b/(\S+))", re.M)
DIFF_MARKER_RE = re.compile(r"(?m)^(diff --git|--- |\+\+\+ |@@ )")

# Ordered failure taxonomy: the first matching mode is assigned.
FAILURE_MODE_DESCRIPTIONS = {
    "adapter_error": "the provider/API call failed after retries (not a model capability signal)",
    "judge_error": "the judge failed to score the patch (not a model capability signal)",
    "budget_exhausted": "the model spent the entire completion budget (likely on hidden reasoning) and returned no visible text — a harness/config artifact, not a capability signal",
    "empty_patch": "the provider returned no patch text without exhausting the token budget",
    "not_a_diff": "the model responded with prose or code instead of a unified diff",
    "likely_truncated": "the diff appears cut off by the completion token limit",
    "wrong_file": "the patch modifies files unrelated to the ground-truth fix",
    "near_miss": "the judge scored the patch just below the pass threshold",
    "insufficient_fix": "the model understood the issue but the fix was judged inadequate",
    "off_target": "the patch was judged irrelevant to the vulnerability",
}

# Failure modes that say more about the harness/provider than the model.
ARTIFACT_MODES = {"adapter_error", "judge_error", "budget_exhausted", "empty_patch"}

REASONING_CLUSTERS = [
    ("wrong-location", re.compile(
        r"different file|unrelated|wrong file|not the affected|different component|unconfirmed code path", re.I)),
    ("incomplete-scope", re.compile(
        r"incomplete|does not cover|misses|missing|partial|only addresses|other affected", re.I)),
    ("root-cause-missed", re.compile(
        r"root cause|symptom|does not address the underlying|superficial", re.I)),
    ("regression-risk", re.compile(
        r"introduces|breaks|new vulnerabilit|regression|side effect", re.I)),
    ("invalid-patch", re.compile(
        r"malformed|invalid diff|cannot be applied|not a valid|empty", re.I)),
]


def load_benchmark_index(path: Path) -> Dict[str, dict]:
    """instance_id -> instance metadata used for attribution."""
    data = json.loads(path.read_text())
    index: Dict[str, dict] = {}
    for inst in data.get("instances", []):
        gold = inst.get("gold_patch", {}) or {}
        cve = inst.get("cve_id", "")
        year_match = re.match(r"CVE-(\d{4})-", cve)
        index[inst["instance_id"]] = {
            "cve_id": cve,
            "cve_year": year_match.group(1) if year_match else "unknown",
            "primary_cwe": inst.get("primary_cwe", "") or "unknown",
            "severity": inst.get("severity", "") or "unknown",
            "cvss_score": inst.get("cvss_score"),
            "ecosystem": inst.get("ecosystem", "") or "unknown",
            "difficulty_tier": inst.get("difficulty_tier", "") or "unknown",
            "package_name": inst.get("package_name", ""),
            "gold_files": [
                f.get("path", f) if isinstance(f, dict) else f
                for f in gold.get("files_changed", [])
            ],
            "gold_lines_changed": (gold.get("total_additions", 0) or 0)
            + (gold.get("total_deletions", 0) or 0),
        }
    return index


def patch_touched_files(patch: str) -> List[str]:
    files = []
    for a_path, b_path in DIFF_FILE_RE.findall(patch):
        path = a_path or b_path
        if path and path not in files:
            files.append(path)
    return files


def files_overlap(patch_files: List[str], gold_files: List[str]) -> bool:
    if not patch_files or not gold_files:
        return False
    gold_full = set(gold_files)
    gold_base = {Path(g).name for g in gold_files}
    for f in patch_files:
        if f in gold_full or Path(f).name in gold_base:
            return True
    return False


def classify_failure(result: dict, inst: Optional[dict], max_tokens: int) -> str:
    """Assign one failure mode to a non-passing instance result."""
    analysis = result.get("patch_analysis", {}) or {}
    raw_verdict = analysis.get("raw_judge_verdict", "")
    if result.get("generation_error") or raw_verdict == "adapter_error":
        return "adapter_error"
    if raw_verdict == "judge_error":
        return "judge_error"

    patch = result.get("model_patch", "") or ""
    completion = result.get("completion_tokens", 0) or 0
    budget_burned = max_tokens and completion >= TRUNCATION_FRACTION * max_tokens
    if not patch.strip():
        return "budget_exhausted" if budget_burned else "empty_patch"
    if not DIFF_MARKER_RE.search(patch):
        return "not_a_diff"
    if budget_burned:
        return "likely_truncated"

    if inst and inst.get("gold_files"):
        touched = patch_touched_files(patch)
        if touched and not files_overlap(touched, inst["gold_files"]):
            return "wrong_file"

    score = result.get("score", 0.0) or 0.0
    if score >= 0.4:
        return "near_miss"
    if score >= 0.2:
        return "insufficient_fix"
    return "off_target"


def cluster_judge_reasoning(reasoning: str) -> str:
    for name, pattern in REASONING_CLUSTERS:
        if pattern.search(reasoning):
            return name
    return "other"


def percentile(values: List[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * pct
    lo = int(k)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def eval_config_key(metadata: dict) -> str:
    """Configuration fingerprint; only rows sharing it are comparable."""
    judges = metadata.get("judge_models") or [metadata.get("judge_model", "?")]
    return json.dumps(
        {
            "benchmark": Path(str(metadata.get("benchmark", "?"))).name,
            "judges": sorted(judges),
            "include_source": metadata.get("include_source"),
            "file_hint_mode": metadata.get("file_hint_mode"),
            "voting_rule": metadata.get("consensus_voting_rule", "score_threshold"),
        },
        sort_keys=True,
    )


def analyze_model(
    model: str,
    reports: List[dict],
    bench_index: Dict[str, dict],
) -> dict:
    """Build the full analysis payload for one model across its runs."""
    reports = sorted(
        reports, key=lambda r: r.get("metadata", {}).get("evaluated_at", "")
    )
    primary = reports[-1]  # most recent run drives per-instance attribution
    metadata = primary.get("metadata", {})
    max_tokens = metadata.get("max_tokens") or DEFAULT_MAX_TOKENS

    config_keys = {eval_config_key(r.get("metadata", {})) for r in reports}
    config_warning = (
        "Runs for this model used differing evaluation configurations and are "
        "not directly comparable." if len(config_keys) > 1 else ""
    )

    results = primary.get("results", [])
    enriched = []
    for r in results:
        inst = bench_index.get(r.get("instance_id", ""))
        row = dict(r)
        if inst:
            row.update(
                primary_cwe=inst["primary_cwe"],
                severity=inst["severity"],
                cve_year=inst["cve_year"],
                gold_lines_changed=inst["gold_lines_changed"],
            )
        enriched.append(row)

    n = len(enriched)
    passed = sum(1 for r in enriched if r.get("passed"))
    low, high = wilson_interval(passed, n) if n else (0.0, 0.0)

    failure_modes: Counter = Counter()
    reasoning_clusters: Counter = Counter()
    infra_failures = 0
    answered = 0
    for r in enriched:
        patch = (r.get("model_patch") or "").strip()
        if patch and DIFF_MARKER_RE.search(patch):
            answered += 1
        if r.get("passed"):
            continue
        inst = bench_index.get(r.get("instance_id", ""))
        mode = classify_failure(r, inst, max_tokens)
        failure_modes[mode] += 1
        if mode in ARTIFACT_MODES:
            infra_failures += 1
        reasoning = (r.get("patch_analysis", {}) or {}).get("judge_reasoning", "")
        if reasoning and mode not in ARTIFACT_MODES:
            reasoning_clusters[cluster_judge_reasoning(reasoning)] += 1

    run_summary = multi_run_pass_summary([extract_passed_map(r.get("results", [])) for r in reports])

    gen_times = [r.get("generation_time_s", 0.0) for r in enriched]
    costs = [r.get("cost_usd", 0.0) for r in enriched]
    completion_tokens = [r.get("completion_tokens", 0) for r in enriched]
    reasoning_tokens = [r.get("reasoning_tokens", 0) for r in enriched]

    breakdowns = {
        "difficulty_tier": pass_rate_by(enriched, "difficulty_tier"),
        "primary_cwe": pass_rate_by(enriched, "primary_cwe"),
        "ecosystem": pass_rate_by(enriched, "ecosystem"),
        "severity": pass_rate_by(enriched, "severity"),
        "cve_year": pass_rate_by(enriched, "cve_year"),
    }

    return {
        "model": model,
        "display_name": model.replace("openrouter/", ""),
        "metadata": {
            "runs": len(reports),
            "evaluated_at": metadata.get("evaluated_at", ""),
            "judge_models": metadata.get("judge_models")
            or [metadata.get("judge_model", "")],
            "include_source": metadata.get("include_source"),
            "file_hint_mode": metadata.get("file_hint_mode"),
            "max_tokens": max_tokens,
            "config_key": eval_config_key(metadata),
            "config_warning": config_warning,
        },
        "headline": {
            "instances": n,
            "passed": passed,
            "pass_rate": round(passed / n, 4) if n else 0.0,
            "wilson_95": (round(low, 4), round(high, 4)),
            "mean_score": round(
                sum(r.get("score", 0.0) for r in enriched) / n, 4
            ) if n else 0.0,
            "answer_rate": round(answered / n, 4) if n else 0.0,
        },
        "runs": run_summary,
        "failure_modes": dict(failure_modes.most_common()),
        "infra_failure_count": infra_failures,
        "judge_reasoning_clusters": dict(reasoning_clusters.most_common()),
        "breakdowns": breakdowns,
        "efficiency": {
            "total_cost_usd": round(sum(costs), 4),
            "cost_per_pass_usd": round(sum(costs) / passed, 4) if passed else None,
            "median_gen_time_s": round(percentile(gen_times, 0.5), 2),
            "p90_gen_time_s": round(percentile(gen_times, 0.9), 2),
            "median_completion_tokens": int(percentile(completion_tokens, 0.5)),
            "total_reasoning_tokens": sum(reasoning_tokens),
        },
        "passed_map": extract_passed_map(results),
    }


def _deviations_vs_suite(
    analysis: dict,
    suite_medians: Dict[str, Dict[str, float]],
) -> Tuple[List[str], List[str]]:
    """Dimensions where this model deviates most from the suite median."""
    strengths, weaknesses = [], []
    for dim, buckets in analysis["breakdowns"].items():
        for value, cell in buckets.items():
            if cell["n"] < MIN_BUCKET_N:
                continue
            median = suite_medians.get(dim, {}).get(value)
            if median is None:
                continue
            delta = cell["pass_rate"] - median
            label = f"{dim.replace('_', ' ')} {value}"
            entry = (
                f"{label}: {cell['pass_rate']:.0%} vs suite median "
                f"{median:.0%} (n={cell['n']})"
            )
            if delta >= 0.10:
                strengths.append((delta, entry))
            elif delta <= -0.10:
                weaknesses.append((delta, entry))
    strengths.sort(reverse=True)
    weaknesses.sort()
    return [e for _, e in strengths[:5]], [e for _, e in weaknesses[:5]]


def build_narrative(analysis: dict, strengths: List[str], weaknesses: List[str]) -> str:
    """Deterministic plain-language explanation of the model's performance."""
    head = analysis["headline"]
    name = analysis["display_name"]
    low, high = head["wilson_95"]
    lines = [
        f"{name} passed {head['passed']}/{head['instances']} instances "
        f"({head['pass_rate']:.1%}, 95% CI {low:.1%}–{high:.1%}) with a mean "
        f"judge score of {head['mean_score']:.3f}."
    ]

    runs = analysis["runs"]
    if runs["runs"] > 1:
        rates = ", ".join(f"{r:.1%}" for r in runs["per_run_pass_rates"])
        lines.append(
            f"Across {runs['runs']} independent runs the pass rate was {rates} "
            f"(mean {runs['mean_pass_rate']:.1%} ± {runs['pass_rate_std']:.1%}); "
            f"{runs['pass_at_k']:.1%} of instances passed in at least one run and "
            f"{runs['all_runs_pass_rate']:.1%} passed in every run — the gap "
            "between those two numbers is the model's run-to-run variance."
        )

    modes = analysis["failure_modes"]
    total_failures = sum(modes.values())
    if total_failures:
        top = list(modes.items())[:3]
        parts = [
            f"{count} ({count / total_failures:.0%}) because "
            f"{FAILURE_MODE_DESCRIPTIONS.get(mode, mode)}"
            for mode, count in top
        ]
        lines.append(
            f"Of the {total_failures} failed instances in the reference run: "
            + "; ".join(parts) + "."
        )

    burned = modes.get("budget_exhausted", 0)
    if head["instances"] and burned / head["instances"] >= 0.05:
        lines.append(
            f"⚠ On {burned} instances ({burned / head['instances']:.0%} of the "
            "benchmark) the model exhausted the completion token budget without "
            "emitting any visible text — almost always hidden reasoning consuming "
            "the shared budget. These score 0 but say more about the token limit "
            "than about the model's patching ability; the pass rate is a lower "
            "bound until the run is repeated with an adequate budget."
        )

    infra = analysis["infra_failure_count"]
    if infra:
        lines.append(
            f"In total, {infra} failures ({infra / max(head['instances'], 1):.0%}) "
            "were harness or provider artifacts (API errors, empty responses, "
            "exhausted budgets) rather than judged model mistakes. Under the v2 "
            "quality gate, rows above 2% artifacts are not publishable."
        )

    answer_rate = head.get("answer_rate", 0.0)
    if answer_rate < 0.9:
        lines.append(
            f"The model produced a parseable diff on only {answer_rate:.0%} of "
            "instances (answer rate); capability comparisons against models with "
            "higher answer rates are confounded until this is resolved."
        )

    clusters = analysis["judge_reasoning_clusters"]
    if clusters:
        top_cluster, count = next(iter(clusters.items()))
        explain = {
            "wrong-location": "it most often patched a plausible but wrong file or "
            "code path — a localization failure, expected to improve with better "
            "file hints or source context",
            "incomplete-scope": "its patches most often fixed part of the issue "
            "but missed other affected paths the gold fix covered",
            "root-cause-missed": "its patches most often treated symptoms rather "
            "than the underlying root cause",
            "regression-risk": "its patches most often risked breaking existing "
            "behavior or introducing new issues",
            "invalid-patch": "its output most often failed to form an applicable diff",
        }.get(top_cluster)
        if explain:
            lines.append(
                f"Judge reasoning on failures clusters on '{top_cluster}' "
                f"({count} instances): {explain}."
            )

    if strengths:
        lines.append("Relative strengths: " + "; ".join(strengths) + ".")
    if weaknesses:
        lines.append("Relative weaknesses: " + "; ".join(weaknesses) + ".")

    eff = analysis["efficiency"]
    if eff["cost_per_pass_usd"] is not None:
        lines.append(
            f"Cost: ${eff['total_cost_usd']:.2f} total generation spend, "
            f"${eff['cost_per_pass_usd']:.2f} per passing patch, median "
            f"generation time {eff['median_gen_time_s']:.0f}s."
        )

    if analysis["metadata"]["config_warning"]:
        lines.append("⚠ " + analysis["metadata"]["config_warning"])

    return "\n\n".join(lines)


def _breakdown_table(buckets: Dict[str, dict]) -> List[str]:
    rows = ["| Value | n | Passed | Pass rate | 95% CI |", "|---|---:|---:|---:|---|"]
    for value, cell in buckets.items():
        low, high = cell["wilson_95"]
        rows.append(
            f"| {value} | {cell['n']} | {cell['passed']} | "
            f"{cell['pass_rate']:.1%} | {low:.1%}–{high:.1%} |"
        )
    return rows


def render_markdown(analysis: dict, narrative: str) -> str:
    md = [f"# {analysis['display_name']} — VulnBench performance analysis", ""]
    meta = analysis["metadata"]
    md += [
        f"*Runs: {meta['runs']} · Judges: {', '.join(meta['judge_models'])} · "
        f"hint mode: {meta['file_hint_mode']} · source context: "
        f"{meta['include_source']} · max_tokens: {meta['max_tokens']}*",
        "",
        "## Why this model performed the way it did",
        "",
        narrative,
        "",
        "## Failure modes",
        "",
        "| Mode | Count | Meaning |",
        "|---|---:|---|",
    ]
    for mode, count in analysis["failure_modes"].items():
        md.append(f"| {mode} | {count} | {FAILURE_MODE_DESCRIPTIONS.get(mode, '')} |")

    if analysis["judge_reasoning_clusters"]:
        md += ["", "## Judge reasoning clusters (failures)", "",
               "| Cluster | Count |", "|---|---:|"]
        for cluster, count in analysis["judge_reasoning_clusters"].items():
            md.append(f"| {cluster} | {count} |")

    for dim, title in [
        ("difficulty_tier", "By difficulty tier"),
        ("primary_cwe", "By CWE"),
        ("ecosystem", "By ecosystem"),
        ("severity", "By severity"),
        ("cve_year", "By CVE year"),
    ]:
        md += ["", f"## {title}", ""] + _breakdown_table(analysis["breakdowns"][dim])

    md += [
        "",
        "---",
        "*Generated by `benchmark.model_report` from stored evaluation results; "
        "no additional model calls were made. Wilson intervals; failure modes "
        "assigned by the first matching rule in the taxonomy.*",
    ]
    return "\n".join(md)


def render_index(
    analyses: List[dict],
    tie_rows_by_config: Dict[str, List[dict]],
) -> str:
    md = ["# VulnBench model analyses", ""]
    by_config: Dict[str, List[dict]] = defaultdict(list)
    for a in analyses:
        by_config[a["metadata"]["config_key"]].append(a)

    multiple = len(by_config) > 1
    if multiple:
        md += [
            "> ⚠ **Comparability notice:** the analyses below were produced under "
            "more than one evaluation configuration (different judge panels or "
            "prompt settings). Models are only ranked against models that share "
            "their configuration; cross-table comparisons are not valid.",
            "",
        ]

    for config_key, group in by_config.items():
        config = json.loads(config_key)
        md += [
            f"## Configuration: judges={', '.join(config['judges'])} · "
            f"hints={config['file_hint_mode']} · source={config['include_source']} · "
            f"voting={config['voting_rule']} · dataset={config['benchmark']}",
            "",
            "| Rank | Model | Pass rate (mean of runs) | 95% CI (pooled) | pass@k | Answer rate | Runs | Artifact failures | Report |",
            "|---:|---|---:|---|---:|---:|---:|---:|---|",
        ]
        group.sort(key=lambda a: -a["runs"]["mean_pass_rate"])
        ties = {
            row["model"]: row["tie_group"]
            for row in tie_rows_by_config.get(config_key, [])
        }
        for i, a in enumerate(group, 1):
            runs = a["runs"]
            low, high = runs["pooled_wilson_95"]
            tie = ties.get(a["model"])
            rank = f"{i}" + (f" (tie group {tie})" if tie else "")
            slug = a["display_name"].replace("/", "_")
            md.append(
                f"| {rank} | {a['display_name']} | {runs['mean_pass_rate']:.1%} | "
                f"{low:.1%}–{high:.1%} | {runs['pass_at_k']:.1%} | "
                f"{a['headline']['answer_rate']:.0%} | {runs['runs']} | "
                f"{a['infra_failure_count']} | [{slug}.md]({slug}.md) |"
            )
        md += [
            "",
            "*Models in the same tie group are statistically indistinguishable "
            "(paired bootstrap over instances, p ≥ 0.05). pass@k = passed in at "
            "least one run — report it separately from single-run pass rate.*",
            "",
        ]
    return "\n".join(md)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="VulnBench per-model analysis")
    parser.add_argument("--benchmark", required=True, type=Path)
    parser.add_argument("--reports", required=True, nargs="+", type=Path)
    parser.add_argument("--output-dir", default=Path("results/analysis"), type=Path)
    args = parser.parse_args()

    bench_index = load_benchmark_index(args.benchmark)

    by_model: Dict[str, List[dict]] = defaultdict(list)
    for path in args.reports:
        try:
            report = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Skipping unreadable report %s: %s", path, exc)
            continue
        model = report.get("metadata", {}).get("model")
        if not model:
            logger.warning("Skipping %s: no metadata.model", path)
            continue
        by_model[model].append(report)

    if not by_model:
        raise SystemExit("No usable reports found")

    analyses = [
        analyze_model(model, reports, bench_index)
        for model, reports in sorted(by_model.items())
    ]

    # Suite medians per dimension bucket, per configuration group
    by_config: Dict[str, List[dict]] = defaultdict(list)
    for a in analyses:
        by_config[a["metadata"]["config_key"]].append(a)

    suite_medians_by_config: Dict[str, Dict[str, Dict[str, float]]] = {}
    for config_key, group in by_config.items():
        medians: Dict[str, Dict[str, float]] = defaultdict(dict)
        dims = group[0]["breakdowns"].keys()
        for dim in dims:
            values = {v for a in group for v in a["breakdowns"][dim]}
            for value in values:
                rates = sorted(
                    a["breakdowns"][dim][value]["pass_rate"]
                    for a in group
                    if value in a["breakdowns"][dim]
                )
                if rates:
                    medians[dim][value] = rates[len(rates) // 2]
        suite_medians_by_config[config_key] = medians

    tie_rows_by_config: Dict[str, List[dict]] = {}
    for config_key, group in by_config.items():
        if len(group) > 1:
            ordered = sorted(group, key=lambda a: -a["runs"]["mean_pass_rate"])
            tie_rows_by_config[config_key] = rank_tie_groups(
                [(a["model"], a["passed_map"]) for a in ordered]
            )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    for analysis in analyses:
        medians = suite_medians_by_config[analysis["metadata"]["config_key"]]
        strengths, weaknesses = _deviations_vs_suite(analysis, medians)
        narrative = build_narrative(analysis, strengths, weaknesses)
        analysis["narrative"] = narrative
        analysis["relative_strengths"] = strengths
        analysis["relative_weaknesses"] = weaknesses

        slug = analysis["display_name"].replace("/", "_")
        payload = {k: v for k, v in analysis.items() if k != "passed_map"}
        (args.output_dir / f"{slug}.json").write_text(json.dumps(payload, indent=2))
        (args.output_dir / f"{slug}.md").write_text(
            render_markdown(analysis, narrative)
        )
        logger.info("Wrote %s.md", args.output_dir / slug)

    index = render_index(analyses, tie_rows_by_config)
    (args.output_dir / "README.md").write_text(index)
    logger.info("Wrote %s", args.output_dir / "README.md")


if __name__ == "__main__":
    main()
