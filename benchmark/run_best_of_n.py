"""Run each model N times and keep the best score.

Usage:
    python -m benchmark.run_best_of_n \
        --benchmark data/benchmark/vulnbench_mini.json \
        --model openrouter/openai/gpt-5.4 \
        --runs 3 \
        --output results/best3_gpt-5.4.json
"""

from __future__ import annotations

from dotenv import load_dotenv
load_dotenv()

import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from benchmark.adapters.litellm_adapter import LiteLLMAdapter
from benchmark.eval_models import EvalReport, InstanceResult
from benchmark.run_eval import (
    JUDGE_MODEL,
    build_report,
    compute_aggregate,
    evaluate_instance,
    print_report_summary,
)
from src.benchmark_models import BenchmarkDatabase

from tqdm import tqdm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="VulnBench Best-of-N Runner")
    parser.add_argument("--benchmark", type=str, required=True)
    parser.add_argument("--model", type=str, required=True)
    parser.add_argument("--runs", type=int, default=3, help="Number of runs (default: 3)")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-tokens", type=int, default=4096)
    parser.add_argument("--judge-model", type=str, default=JUDGE_MODEL)
    parser.add_argument(
        "--include-source",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    parser.add_argument(
        "--file-hint-mode",
        choices=("none", "description", "gold"),
        default="description",
    )
    parser.add_argument("--max-source-files", type=int, default=3)
    parser.add_argument("--max-source-chars", type=int, default=6000)
    parser.add_argument("--output", type=str, default="results/best_of_n.json")
    parser.add_argument("--limit", type=int, default=0)

    args = parser.parse_args()

    # Load benchmark
    bench_data = json.loads(Path(args.benchmark).read_text())
    benchmark = BenchmarkDatabase(**bench_data)
    instances = benchmark.instances
    if args.limit > 0:
        instances = instances[: args.limit]

    logger.info(
        "Best-of-%d: model=%s, instances=%d, judge=%s",
        args.runs, args.model, len(instances), args.judge_model,
    )

    all_run_reports: list[EvalReport] = []
    output_dir = Path(args.output).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    for run_idx in range(1, args.runs + 1):
        logger.info("=== Run %d/%d ===", run_idx, args.runs)

        adapter = LiteLLMAdapter(
            model=args.model,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
        )

        results: list[InstanceResult] = []
        pbar = tqdm(instances, desc=f"Run {run_idx}/{args.runs}")
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
            model_name=args.model,
            judge_model=args.judge_model,
            include_source=args.include_source,
            file_hint_mode=args.file_hint_mode,
        )
        all_run_reports.append(report)

        # Save individual run
        safe_name = args.model.replace("/", "_")
        run_path = output_dir / f"run{run_idx}_{safe_name}.json"
        run_path.write_text(json.dumps(report.model_dump(), indent=2))

        print(f"\n  Run {run_idx}: pass_rate={report.aggregate.pass_rate:.1%}, "
              f"mean_score={report.aggregate.mean_score:.3f}")

    # Pick best run by pass_rate, then mean_score as tiebreaker
    best_report = max(
        all_run_reports,
        key=lambda r: (r.aggregate.pass_rate, r.aggregate.mean_score),
    )
    best_idx = all_run_reports.index(best_report) + 1

    # Add best-of-N metadata
    best_report.metadata["best_of_n"] = args.runs
    best_report.metadata["best_run"] = best_idx
    best_report.metadata["all_runs"] = [
        {
            "run": i + 1,
            "pass_rate": r.aggregate.pass_rate,
            "mean_score": r.aggregate.mean_score,
            "total_cost_usd": r.aggregate.total_cost_usd,
        }
        for i, r in enumerate(all_run_reports)
    ]

    # Write best report
    best_path = Path(args.output)
    best_path.write_text(json.dumps(best_report.model_dump(), indent=2))

    print(f"\n{'=' * 60}")
    print(f"  Best of {args.runs} runs: Run {best_idx}")
    print(f"{'=' * 60}")
    for i, r in enumerate(all_run_reports):
        marker = " ← BEST" if i + 1 == best_idx else ""
        print(f"  Run {i+1}: pass_rate={r.aggregate.pass_rate:.1%}, "
              f"mean_score={r.aggregate.mean_score:.3f}, "
              f"cost=${r.aggregate.total_cost_usd:.4f}{marker}")

    print_report_summary(best_report.aggregate)
    print(f"  Best report written to: {best_path}")


if __name__ == "__main__":
    main()
