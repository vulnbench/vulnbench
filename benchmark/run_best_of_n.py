"""Run each model N times and keep the best score.

Usage:
    python -m benchmark.run_best_of_n \
        --benchmark data/benchmark/vulnbench_mini.json \
        --model openrouter/openai/gpt-5.5 \
        --runs 3 \
        --output results/best3_gpt-5.5.json
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
    DEFAULT_JUDGE_MODELS,
    DEFAULT_MAX_TOKENS,
    DEFAULT_TIE_BREAKER_JUDGE,
    JUDGE_MODEL,
    build_report,
    compute_aggregate,
    evaluate_instance,
    print_report_summary,
)
from benchmark.stats import extract_passed_map, multi_run_pass_summary
from src.benchmark_models import BenchmarkDatabase

from tqdm import tqdm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def _write_report_atomic(path: Path, report: EvalReport) -> None:
    tmp_path = path.with_name(path.name + ".tmp")
    tmp_path.write_text(json.dumps(report.model_dump(), indent=2))
    tmp_path.replace(path)


def _report_matches_run(
    report: EvalReport,
    *,
    args: argparse.Namespace,
    active_judge_models: list[str],
    expected_instances: int,
    allow_partial: bool,
) -> bool:
    metadata = report.metadata
    total_instances = report.aggregate.total_instances
    if allow_partial:
        valid_size = 0 <= total_instances <= expected_instances
    else:
        valid_size = total_instances == expected_instances

    return (
        valid_size
        and metadata.get("model") == args.model
        and metadata.get("judge_models") == active_judge_models
        and metadata.get("include_source") is args.include_source
        and metadata.get("file_hint_mode") == args.file_hint_mode
        and metadata.get("max_tokens") == args.max_tokens
        and metadata.get("reasoning_effort") == args.reasoning_effort
        and metadata.get("reasoning_max_tokens") == args.reasoning_max_tokens
        and metadata.get("reasoning_exclude") is args.reasoning_exclude
        and metadata.get("adapter_max_attempts") == args.adapter_max_attempts
        and metadata.get("retry_empty_responses") is args.retry_empty_responses
        and metadata.get("adapter_process_timeout", args.adapter_process_timeout)
        is args.adapter_process_timeout
    )


def _build_run_report(
    results: list[InstanceResult],
    *,
    args: argparse.Namespace,
    active_judge_models: list[str],
) -> EvalReport:
    report = build_report(
        results,
        benchmark_path=args.benchmark,
        model_name=args.model,
        judge_model=active_judge_models[0],
        judge_models=active_judge_models,
        include_source=args.include_source,
        file_hint_mode=args.file_hint_mode,
        max_tokens=args.max_tokens,
        temperature=args.temperature,
        tie_breaker_judge=getattr(args, "tie_breaker_judge", None),
        reasoning_effort=args.reasoning_effort,
        reasoning_max_tokens=args.reasoning_max_tokens,
        reasoning_exclude=args.reasoning_exclude,
        adapter_max_attempts=args.adapter_max_attempts,
        retry_empty_responses=args.retry_empty_responses,
    )
    report.metadata["adapter_process_timeout"] = args.adapter_process_timeout
    return report


def main():
    parser = argparse.ArgumentParser(description="VulnBench Best-of-N Runner")
    parser.add_argument("--benchmark", type=str, required=True)
    parser.add_argument("--model", type=str, required=True)
    parser.add_argument("--runs", type=int, default=3, help="Number of runs (default: 3)")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS)
    parser.add_argument(
        "--completion-timeout",
        type=float,
        default=300.0,
        help=(
            "Per-request completion timeout in seconds (default: 300). Raise "
            "for models whose median latency approaches the limit, so a slow "
            "response succeeds on the first attempt instead of being killed "
            "and retried (retry storms leak child-process semaphores)."
        ),
    )
    parser.add_argument(
        "--reasoning-effort",
        choices=("none", "minimal", "low", "medium", "high", "xhigh", "default"),
        default=None,
        help="Optional LiteLLM/OpenAI reasoning effort to pass to the model",
    )
    parser.add_argument(
        "--reasoning-max-tokens",
        type=int,
        default=None,
        help="Optional OpenRouter reasoning.max_tokens value passed via extra_body",
    )
    parser.add_argument(
        "--reasoning-exclude",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Ask OpenRouter to exclude reasoning tokens from the response",
    )
    parser.add_argument(
        "--adapter-max-attempts",
        type=int,
        default=3,
        help="Max adapter-level completion attempts for LiteLLM models (default: 3)",
    )
    parser.add_argument(
        "--adapter-retry-backoff-base-s",
        type=float,
        default=2.0,
        help="Initial adapter retry backoff in seconds (default: 2.0)",
    )
    parser.add_argument(
        "--adapter-retry-backoff-max-s",
        type=float,
        default=60.0,
        help="Maximum adapter retry backoff in seconds (default: 60.0)",
    )
    parser.add_argument(
        "--adapter-retry-backoff-jitter-s",
        type=float,
        default=0.5,
        help="Random adapter retry jitter in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--retry-empty-responses",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Retry empty LiteLLM responses before scoring (default: true)",
    )
    parser.add_argument(
        "--adapter-process-timeout",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Run LiteLLM completions in a child process so blocking provider "
            "socket reads cannot exceed the adapter timeout (default: true)"
        ),
    )
    parser.add_argument("--judge-model", type=str, default=None)
    parser.add_argument(
        "--tie-breaker-judge", type=str, default=DEFAULT_TIE_BREAKER_JUDGE
    )
    parser.add_argument(
        "--judge-models",
        nargs="+",
        default=None,
        help=(
            "One or more LiteLLM judge model IDs. When multiple are provided, "
            "VulnBench stores each judge result and scores by consensus. "
            "Defaults to the standard multi-judge panel unless --judge-model "
            "is explicitly set."
        ),
    )
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
    parser.add_argument(
        "--resume",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Resume each run from per-instance checkpoints (default: true)",
    )

    args = parser.parse_args()

    # Load benchmark
    bench_data = json.loads(Path(args.benchmark).read_text())
    benchmark = BenchmarkDatabase(**bench_data)
    instances = benchmark.instances
    if args.limit > 0:
        instances = instances[: args.limit]
    if args.judge_models:
        active_judge_models = args.judge_models
    elif args.judge_model:
        active_judge_models = [args.judge_model]
    else:
        active_judge_models = DEFAULT_JUDGE_MODELS
    tie_breaker_judge = (
        None
        if (args.tie_breaker_judge or "").lower() in ("", "none")
        else args.tie_breaker_judge
    )

    logger.info(
        "Best-of-%d: model=%s, instances=%d, judges=%s",
        args.runs, args.model, len(instances), ", ".join(active_judge_models),
    )

    all_run_reports: list[EvalReport] = []
    output_dir = Path(args.output).parent
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_name = args.model.replace("/", "_")
    if args.reasoning_effort:
        safe_name = f"{safe_name}_effort-{args.reasoning_effort}"

    for run_idx in range(1, args.runs + 1):
        logger.info("=== Run %d/%d ===", run_idx, args.runs)

        run_path = output_dir / f"run{run_idx}_{safe_name}.json"
        checkpoint_path = output_dir / f"run{run_idx}_{safe_name}.json.partial"

        if args.resume and run_path.exists():
            try:
                report = EvalReport(**json.loads(run_path.read_text()))
                if _report_matches_run(
                    report,
                    args=args,
                    active_judge_models=active_judge_models,
                    expected_instances=len(instances),
                    allow_partial=False,
                ):
                    logger.info("Reusing completed run %d from %s", run_idx, run_path)
                    all_run_reports.append(report)
                    if checkpoint_path.exists():
                        checkpoint_path.unlink()
                    print(
                        f"\n  Run {run_idx}: pass_rate={report.aggregate.pass_rate:.1%}, "
                        f"mean_score={report.aggregate.mean_score:.3f} (resumed)"
                    )
                    continue
                logger.warning("Ignoring incompatible completed run %s", run_path)
            except Exception as exc:
                logger.warning("Ignoring unreadable completed run %s: %s", run_path, exc)

        adapter = LiteLLMAdapter(
            model=args.model,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
            timeout=args.completion_timeout,
            reasoning_effort=args.reasoning_effort,
            reasoning_max_tokens=args.reasoning_max_tokens,
            reasoning_exclude=args.reasoning_exclude,
            max_attempts=args.adapter_max_attempts,
            retry_backoff_base_s=args.adapter_retry_backoff_base_s,
            retry_backoff_max_s=args.adapter_retry_backoff_max_s,
            retry_backoff_jitter_s=args.adapter_retry_backoff_jitter_s,
            retry_empty_responses=args.retry_empty_responses,
            process_timeout=args.adapter_process_timeout,
        )

        results: list[InstanceResult] = []
        completed_ids: set[str] = set()
        if args.resume and checkpoint_path.exists():
            try:
                checkpoint = EvalReport(**json.loads(checkpoint_path.read_text()))
                if _report_matches_run(
                    checkpoint,
                    args=args,
                    active_judge_models=active_judge_models,
                    expected_instances=len(instances),
                    allow_partial=True,
                ):
                    results = checkpoint.results
                    completed_ids = {r.instance_id for r in results}
                    logger.info(
                        "Resuming run %d from %s with %d completed instances",
                        run_idx,
                        checkpoint_path,
                        len(results),
                    )
                else:
                    logger.warning("Ignoring incompatible checkpoint %s", checkpoint_path)
            except Exception as exc:
                logger.warning("Ignoring unreadable checkpoint %s: %s", checkpoint_path, exc)

        remaining_instances = [
            instance for instance in instances if instance.instance_id not in completed_ids
        ]
        pbar = tqdm(remaining_instances, desc=f"Run {run_idx}/{args.runs}")
        for instance in pbar:
            result = evaluate_instance(
                instance,
                adapter,
                judge_model=active_judge_models[0],
                judge_models=active_judge_models,
                include_source=args.include_source,
                file_hint_mode=args.file_hint_mode,
                max_source_files=args.max_source_files,
                max_source_chars=args.max_source_chars,
                candidate_model=args.model,
                tie_breaker_judge=tie_breaker_judge,
            )
            results.append(result)
            pbar.set_postfix(
                passed=sum(1 for r in results if r.passed),
                score=f"{sum(r.score for r in results) / len(results):.3f}",
            )
            if args.resume:
                checkpoint_report = _build_run_report(
                    results,
                    args=args,
                    active_judge_models=active_judge_models,
                )
                checkpoint_report.metadata["checkpoint"] = True
                checkpoint_report.metadata["best_of_n_run"] = run_idx
                _write_report_atomic(checkpoint_path, checkpoint_report)

        report = _build_run_report(
            results,
            args=args,
            active_judge_models=active_judge_models,
        )
        all_run_reports.append(report)

        # Save individual run
        _write_report_atomic(run_path, report)
        if args.resume and checkpoint_path.exists():
            checkpoint_path.unlink()

        print(f"\n  Run {run_idx}: pass_rate={report.aggregate.pass_rate:.1%}, "
              f"mean_score={report.aggregate.mean_score:.3f}")

    # Headline metric: mean pass rate across runs (with pooled Wilson CI).
    # The historical "best run" selection is an upward-biased order statistic
    # and is retained only as metadata, never as the reported number.
    across = multi_run_pass_summary(
        [extract_passed_map([res.model_dump() for res in r.results]) for r in all_run_reports]
    )
    # The written report carries the most recent run's per-instance results;
    # the cross-run metrics live in metadata.across_runs.
    summary_report = all_run_reports[-1]
    summary_report.metadata["runs"] = args.runs
    summary_report.metadata["primary_metric"] = "mean_pass_rate_across_runs"
    summary_report.metadata["across_runs"] = across
    summary_report.metadata["all_runs"] = [
        {
            "run": i + 1,
            "pass_rate": r.aggregate.pass_rate,
            "mean_score": r.aggregate.mean_score,
            "total_cost_usd": r.aggregate.total_cost_usd,
            "total_judge_cost_usd": r.aggregate.total_judge_cost_usd,
        }
        for i, r in enumerate(all_run_reports)
    ]
    summary_report.metadata["total_cost_usd_all_runs"] = round(
        sum(r.aggregate.total_cost_usd for r in all_run_reports), 6
    )

    summary_path = Path(args.output)
    summary_path.write_text(json.dumps(summary_report.model_dump(), indent=2))

    low, high = across["pooled_wilson_95"]
    print(f"\n{'=' * 60}")
    print(f"  {args.runs} independent runs of {args.model}")
    print(f"{'=' * 60}")
    for i, r in enumerate(all_run_reports):
        print(f"  Run {i+1}: pass_rate={r.aggregate.pass_rate:.1%}, "
              f"mean_score={r.aggregate.mean_score:.3f}, "
              f"cost=${r.aggregate.total_cost_usd:.4f}")
    print(
        f"\n  Mean pass rate: {across['mean_pass_rate']:.1%} "
        f"± {across['pass_rate_std']:.1%} (95% CI {low:.1%}–{high:.1%})"
    )
    print(f"  pass@{args.runs} (any run): {across['pass_at_k']:.1%}")
    print(f"  passed in every run: {across['all_runs_pass_rate']:.1%}")

    print_report_summary(summary_report.aggregate)
    print(f"  Summary report written to: {summary_path}")


if __name__ == "__main__":
    main()
