"""Re-judge stored patches under a pinned judge configuration.

The generation step is the expensive part of an evaluation; judging is
cheap by comparison. When the judge model or voting rule changes, existing
reports become incomparable — but the stored patches are still valid. This
tool re-scores the patches from existing report files under a single pinned
judge panel, producing directly comparable reports WITHOUT re-running any
generation.

This is the sanctioned way to fix a leaderboard that mixes judge versions:
re-judge every report under the same panel, then rebuild the leaderboard
from the re-judged files.

Usage:
    # Estimate cost first
    python -m benchmark.rejudge \
        --benchmark data/benchmark/vulnbench_200.json \
        --reports results/run?_openrouter_*.json \
        --judge-models openrouter/anthropic/claude-opus-4.8 \
                       openrouter/openai/gpt-5.5 \
        --output-dir results/rejudged \
        --dry-run

    # Then run it (per-report .partial checkpoints; safe to interrupt)
    python -m benchmark.rejudge ... (same args without --dry-run)
"""

from __future__ import annotations

from dotenv import load_dotenv
load_dotenv()

import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from tqdm import tqdm

from benchmark.eval_models import EvalReport, InstanceResult
from benchmark.provenance import provenance_metadata
from benchmark.run_eval import (
    JUDGE_MODEL,
    combine_judge_analyses,
    compute_aggregate,
    judge_patch_with_models,
    _adapter_error_analysis,
)
from src.benchmark_models import BenchmarkDatabase, BenchmarkInstance

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Rough per-judge-call cost used only for --dry-run estimates; actual cost
# is measured from responses and recorded per instance.
EST_COST_PER_JUDGE_CALL_USD = 0.012


def rejudge_result(
    result: InstanceResult,
    instance: BenchmarkInstance,
    judge_models: List[str],
) -> InstanceResult:
    """Rebuild one InstanceResult with fresh judge analyses."""
    if result.generation_error:
        analyses = {
            model: _adapter_error_analysis(result.generation_error, judge_model=model)
            for model in judge_models
        }
        analysis = (
            analyses[judge_models[0]]
            if len(judge_models) == 1
            else combine_judge_analyses(analyses)
        )
    else:
        analysis, analyses = judge_patch_with_models(
            instance,
            result.model_patch,
            judge_models,
        )

    updated = result.model_copy(deep=True)
    updated.patch_analysis = analysis
    updated.judge_analyses = analyses
    updated.score = analysis.judge_score
    updated.passed = analysis.judge_verdict == "pass"
    updated.judge_cost_usd = analysis.judge_cost_usd
    return updated


def main() -> None:
    parser = argparse.ArgumentParser(description="VulnBench re-judge tool")
    parser.add_argument("--benchmark", required=True, type=Path)
    parser.add_argument("--reports", required=True, nargs="+", type=Path)
    parser.add_argument(
        "--judge-models",
        nargs="+",
        default=[JUDGE_MODEL],
        help="Pinned judge panel applied to every report",
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--limit", type=int, default=0, help="Max instances per report (0=all)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be re-judged and the estimated cost, then exit",
    )
    parser.add_argument(
        "--resume",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Resume from per-report .partial checkpoints (default: true)",
    )
    args = parser.parse_args()

    bench_data = json.loads(args.benchmark.read_text())
    benchmark = BenchmarkDatabase(**bench_data)
    instances_by_id: Dict[str, BenchmarkInstance] = {
        inst.instance_id: inst for inst in benchmark.instances
    }

    total_judged_calls = 0
    plans = []
    for report_path in args.reports:
        try:
            report = EvalReport(**json.loads(report_path.read_text()))
        except Exception as exc:
            logger.warning("Skipping unreadable report %s: %s", report_path, exc)
            continue
        results = report.results[: args.limit] if args.limit else report.results
        judgeable = sum(
            1
            for r in results
            if r.model_patch.strip() and not r.generation_error
        )
        total_judged_calls += judgeable * len(args.judge_models)
        plans.append((report_path, report, results, judgeable))

    est_cost = total_judged_calls * EST_COST_PER_JUDGE_CALL_USD
    logger.info(
        "%d reports, %d judge calls, estimated cost ~$%.2f (panel: %s)",
        len(plans),
        total_judged_calls,
        est_cost,
        ", ".join(args.judge_models),
    )
    if args.dry_run:
        for report_path, report, results, judgeable in plans:
            print(
                f"  {report_path.name}: {len(results)} instances, "
                f"{judgeable} judgeable patches"
            )
        print(f"\nEstimated total cost: ~${est_cost:.2f}")
        return

    args.output_dir.mkdir(parents=True, exist_ok=True)

    for report_path, report, results, _ in plans:
        out_path = args.output_dir / report_path.name
        checkpoint_path = out_path.with_name(out_path.name + ".partial")

        done: Dict[str, InstanceResult] = {}
        if args.resume and checkpoint_path.exists():
            try:
                checkpoint = EvalReport(**json.loads(checkpoint_path.read_text()))
                if checkpoint.metadata.get("rejudge_models") == args.judge_models:
                    done = {r.instance_id: r for r in checkpoint.results}
                    logger.info(
                        "Resuming %s with %d re-judged instances",
                        out_path.name,
                        len(done),
                    )
            except Exception as exc:
                logger.warning("Ignoring checkpoint %s: %s", checkpoint_path, exc)

        rejudged: List[InstanceResult] = [
            done[r.instance_id] for r in results if r.instance_id in done
        ]
        remaining = [r for r in results if r.instance_id not in done]

        def flush(target: Path) -> None:
            new_report = EvalReport(
                metadata={
                    **report.metadata,
                    "rejudged_at": datetime.now(timezone.utc).isoformat(),
                    "rejudged_from": str(report_path),
                    "original_judge_models": report.metadata.get("judge_models")
                    or [report.metadata.get("judge_model", "")],
                    "judge_model": args.judge_models[0],
                    "judge_models": args.judge_models,
                    "rejudge_models": args.judge_models,
                    **provenance_metadata(args.benchmark),
                },
                aggregate=compute_aggregate(rejudged),
                results=rejudged,
            )
            tmp = target.with_name(target.name + ".tmp")
            tmp.write_text(json.dumps(new_report.model_dump(), indent=2))
            tmp.replace(target)

        for result in tqdm(remaining, desc=out_path.name):
            instance = instances_by_id.get(result.instance_id)
            if instance is None:
                logger.warning(
                    "Instance %s not in benchmark; keeping original scoring",
                    result.instance_id,
                )
                rejudged.append(result)
                continue
            rejudged.append(rejudge_result(result, instance, args.judge_models))
            flush(checkpoint_path)

        # Preserve the original instance order
        order = {r.instance_id: i for i, r in enumerate(results)}
        rejudged.sort(key=lambda r: order.get(r.instance_id, 1 << 30))

        flush(out_path)
        if checkpoint_path.exists():
            checkpoint_path.unlink()
        report_aggregate = compute_aggregate(rejudged)
        logger.info(
            "%s: pass_rate %.1f%% -> %.1f%% under pinned panel",
            out_path.name,
            report.aggregate.pass_rate * 100,
            report_aggregate.pass_rate * 100,
        )


if __name__ == "__main__":
    main()
