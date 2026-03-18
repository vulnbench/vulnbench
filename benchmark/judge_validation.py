"""Utilities for auditing judge behavior and exporting human review samples."""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path


def load_report(path: Path) -> dict:
    return json.loads(path.read_text())


def summarize_report(report: dict) -> dict:
    results = report.get("results", [])
    contradictions = [
        r for r in results
        if not r.get("patch_analysis", {}).get("judge_consistent", True)
    ]
    near_threshold = [
        r for r in results
        if 0.4 <= float(r.get("score", 0.0)) <= 0.6
    ]
    passes = sum(1 for r in results if r.get("passed"))
    return {
        "instances": len(results),
        "passes": passes,
        "pass_rate": round(passes / len(results), 4) if results else 0.0,
        "judge_contradictions": len(contradictions),
        "near_threshold_cases": len(near_threshold),
    }


def export_human_review_sample(report: dict, output_path: Path, sample_size: int, seed: int) -> None:
    rng = random.Random(seed)
    results = report.get("results", [])
    near_threshold = [
        r for r in results
        if 0.4 <= float(r.get("score", 0.0)) <= 0.6
    ]
    contradictions = [
        r for r in results
        if not r.get("patch_analysis", {}).get("judge_consistent", True)
    ]

    chosen: dict[str, dict] = {}
    prioritized = contradictions + near_threshold
    rng.shuffle(prioritized)
    for row in prioritized:
        if len(chosen) >= sample_size:
            break
        chosen[row["instance_id"]] = row

    remaining = [r for r in results if r["instance_id"] not in chosen]
    rng.shuffle(remaining)
    for row in remaining:
        if len(chosen) >= sample_size:
            break
        chosen[row["instance_id"]] = row

    output = []
    for row in chosen.values():
        analysis = row.get("patch_analysis", {})
        output.append(
            {
                "instance_id": row.get("instance_id"),
                "cve_id": row.get("cve_id"),
                "score": row.get("score"),
                "passed": row.get("passed"),
                "judge_verdict": analysis.get("judge_verdict"),
                "raw_judge_verdict": analysis.get("raw_judge_verdict"),
                "judge_consistent": analysis.get("judge_consistent"),
                "judge_reasoning": analysis.get("judge_reasoning"),
                "model_patch": row.get("model_patch"),
            }
        )

    payload = {
        "metadata": {
            "source_report": report.get("metadata", {}),
            "sample_size": len(output),
            "seed": seed,
        },
        "items": output,
    }
    output_path.write_text(json.dumps(payload, indent=2) + "\n")


def compare_reports(paths: list[Path]) -> dict:
    reports = [load_report(path) for path in paths]
    by_instance: dict[str, list[tuple[str, dict]]] = {}
    for path, report in zip(paths, reports):
        for row in report.get("results", []):
            by_instance.setdefault(row["instance_id"], []).append((path.name, row))

    shared = {k: v for k, v in by_instance.items() if len(v) == len(paths)}
    if not shared:
        return {"shared_instances": 0, "pass_agreement": 0.0, "mean_abs_score_diff": 0.0}

    agreements = 0
    score_diffs = []
    for rows in shared.values():
        passes = [bool(row.get("passed")) for _, row in rows]
        scores = [float(row.get("score", 0.0)) for _, row in rows]
        if len(set(passes)) == 1:
            agreements += 1
        score_diffs.append(max(scores) - min(scores))

    return {
        "shared_instances": len(shared),
        "pass_agreement": round(agreements / len(shared), 4),
        "mean_abs_score_diff": round(sum(score_diffs) / len(score_diffs), 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit VulnBench judge outputs")
    parser.add_argument("--report", type=str, help="Single evaluation report to summarize")
    parser.add_argument(
        "--compare",
        nargs="+",
        help="Two or more evaluation reports to compare for inter-judge agreement",
    )
    parser.add_argument("--sample-output", type=str, help="Write a human review sample JSON")
    parser.add_argument("--sample-size", type=int, default=50)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    if args.report:
        report = load_report(Path(args.report))
        print(json.dumps(summarize_report(report), indent=2))
        if args.sample_output:
            export_human_review_sample(
                report,
                Path(args.sample_output),
                sample_size=args.sample_size,
                seed=args.seed,
            )
            print(f"Wrote review sample to {args.sample_output}")

    if args.compare:
        print(json.dumps(compare_reports([Path(p) for p in args.compare]), indent=2))


if __name__ == "__main__":
    main()
