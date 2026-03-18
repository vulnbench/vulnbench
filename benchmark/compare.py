"""Multi-model comparison CLI for VulnBench.

Usage:
    python -m benchmark.compare \
        --benchmark data/benchmark/vulnbench_mini.json \
        --models openrouter/openai/gpt-5.4 openrouter/anthropic/claude-sonnet-4.6 \
        --output results/comparison.json \
        --limit 20
"""

from __future__ import annotations

from dotenv import load_dotenv
load_dotenv()

import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field
from tqdm import tqdm

from benchmark.adapters.litellm_adapter import LiteLLMAdapter
from benchmark.eval_models import EvalReport, InstanceResult
from benchmark.run_eval import (
    JUDGE_MODEL,
    build_report,
    evaluate_instance,
    print_report_summary,
)
from src.benchmark_models import BenchmarkDatabase

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


class ComparisonReport(BaseModel):
    """Side-by-side evaluation results across multiple models."""

    metadata: dict = Field(default_factory=dict)
    models: list[str] = Field(default_factory=list)
    reports: dict[str, EvalReport] = Field(default_factory=dict)
    summary_table: list[dict] = Field(default_factory=list)


def build_summary_table(
    models: list[str],
    reports: dict[str, EvalReport],
) -> list[dict]:
    """Build a summary table with one row per model."""
    rows = []
    for model in models:
        report = reports[model]
        agg = report.aggregate
        rows.append(
            {
                "model": model,
                "instances": agg.total_instances,
                "passed": agg.total_passed,
                "pass_rate": agg.pass_rate,
                "mean_score": agg.mean_score,
                "mean_gen_time_s": agg.mean_generation_time_s,
                "model_cost_usd": agg.total_cost_usd,
                "judge_cost_usd": agg.total_judge_cost_usd,
                "total_tokens": agg.total_prompt_tokens + agg.total_completion_tokens,
            }
        )
    return rows


def print_comparison_table(summary_table: list[dict]) -> None:
    """Print a formatted comparison table to stdout."""
    if not summary_table:
        return

    print(f"\n{'=' * 90}")
    print("  VulnBench Model Comparison")
    print(f"{'=' * 90}")

    print(
        f"  {'Model':<35} {'Pass%':>6} {'Score':>6} "
        f"{'Time':>6} {'ModelCost':>9} {'JudgeCost':>9}"
    )
    print(
        f"  {'-' * 35} {'-' * 6} {'-' * 6} "
        f"{'-' * 6} {'-' * 9} {'-' * 9}"
    )

    for row in summary_table:
        model_display = row["model"]
        if len(model_display) > 33:
            model_display = model_display[:30] + "..."
        print(
            f"  {model_display:<35} "
            f"{row['pass_rate']:>5.1%} "
            f"{row['mean_score']:>6.3f} "
            f"{row['mean_gen_time_s']:>5.1f}s "
            f"${row['model_cost_usd']:>8.4f} "
            f"${row['judge_cost_usd']:>8.4f}"
        )

    print(f"{'=' * 90}")


def main():
    parser = argparse.ArgumentParser(
        description="VulnBench Multi-Model Comparison"
    )
    parser.add_argument(
        "--benchmark",
        type=str,
        required=True,
        help="Path to benchmark JSON",
    )
    parser.add_argument(
        "--models",
        type=str,
        nargs="+",
        required=True,
        help="LiteLLM model identifiers to compare",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.0,
        help="Sampling temperature (default: 0.0)",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=4096,
        help="Max response tokens (default: 4096)",
    )
    parser.add_argument(
        "--judge-model",
        type=str,
        default=JUDGE_MODEL,
        help=f"LiteLLM model ID for the judge (default: {JUDGE_MODEL})",
    )
    parser.add_argument(
        "--include-source",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Include vulnerable source snippets in prompts (default: true)",
    )
    parser.add_argument(
        "--file-hint-mode",
        choices=("none", "description", "gold"),
        default="description",
        help="How to localize source files: none, description-derived, or gold hints",
    )
    parser.add_argument(
        "--max-source-files",
        type=int,
        default=3,
        help="Max number of source files to include in prompt context",
    )
    parser.add_argument(
        "--max-source-chars",
        type=int,
        default=6000,
        help="Max total source characters to include in prompt context",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="results/comparison.json",
        help="Output path for comparison report",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Max instances to evaluate per model (0=all)",
    )

    args = parser.parse_args()

    # Load benchmark
    logger.info("Loading benchmark from %s", args.benchmark)
    bench_data = json.loads(Path(args.benchmark).read_text())
    benchmark = BenchmarkDatabase(**bench_data)
    instances = benchmark.instances

    if args.limit > 0:
        instances = instances[: args.limit]

    logger.info(
        "Comparing %d models on %d instances (judge: %s)",
        len(args.models), len(instances), args.judge_model,
    )

    # Evaluate each model
    reports: dict[str, EvalReport] = {}
    output_dir = Path(args.output).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    for model_name in args.models:
        logger.info("Evaluating model: %s", model_name)
        adapter = LiteLLMAdapter(
            model=model_name,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
        )

        results: list[InstanceResult] = []
        pbar = tqdm(instances, desc=f"  {model_name}")
        for instance in pbar:
            result = evaluate_instance(
                instance,
                adapter,
                judge_model=args.judge_model,
                include_source=args.include_source,
                file_hint_mode=args.file_hint_mode,
                max_source_files=args.max_source_files,
                max_source_chars=args.max_source_chars,
            )
            results.append(result)
            pbar.set_postfix(
                passed=sum(1 for r in results if r.passed),
                score=f"{sum(r.score for r in results) / len(results):.3f}",
            )

        report = build_report(
            results,
            benchmark_path=args.benchmark,
            model_name=model_name,
            judge_model=args.judge_model,
            include_source=args.include_source,
            file_hint_mode=args.file_hint_mode,
        )
        reports[model_name] = report

        # Write per-model report
        safe_name = model_name.replace("/", "_")
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        per_model_path = output_dir / f"eval_report_{safe_name}_{ts}.json"
        per_model_path.write_text(json.dumps(report.model_dump(), indent=2))
        logger.info("Per-model report written to %s", per_model_path)

        print_report_summary(report.aggregate)

    # Build comparison report
    summary_table = build_summary_table(args.models, reports)

    comparison = ComparisonReport(
        metadata={
            "benchmark": args.benchmark,
            "evaluated_at": datetime.now(timezone.utc).isoformat() + "Z",
            "total_instances": len(instances),
            "models": args.models,
            "judge_model": args.judge_model,
            "temperature": args.temperature,
            "max_tokens": args.max_tokens,
            "include_source": args.include_source,
            "file_hint_mode": args.file_hint_mode,
        },
        models=args.models,
        reports=reports,
        summary_table=summary_table,
    )

    comparison_path = Path(args.output)
    comparison_path.write_text(json.dumps(comparison.model_dump(), indent=2))

    print_comparison_table(summary_table)
    print(f"  Comparison report written to: {comparison_path}")


if __name__ == "__main__":
    main()
