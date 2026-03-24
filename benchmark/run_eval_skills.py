"""VulnBench skills-augmented evaluation harness.

Extends the base harness by injecting structured security analysis
criteria into the prompt, giving models a multi-stage reasoning
framework derived from Ghost Security's SAST analysis methodology.

Usage:
    python -m benchmark.run_eval_skills \
        --benchmark data/benchmark/vulnbench_200.json \
        --model openrouter/openai/gpt-5.4 \
        --include-source \
        --file-hint-mode description \
        --output results/skills/eval_gpt-5.4.json
"""

from __future__ import annotations

from dotenv import load_dotenv
load_dotenv()

import argparse
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from tqdm import tqdm

from benchmark.adapters.litellm_adapter import LiteLLMAdapter
from benchmark.eval_models import EvalReport, InstanceResult
from benchmark.run_eval import (
    JUDGE_MODEL,
    build_report,
    build_source_context,
    judge_patch,
    parse_diff_from_output,
    print_report_summary,
    render_prompt,
    render_prompt_parts,
    _is_litellm_adapter,
)
from benchmark.skills.prompt_builder import build_skills_prompt_section
from src.benchmark_models import BenchmarkDatabase, BenchmarkInstance

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Skills-augmented prompt rendering
# ---------------------------------------------------------------------------

def render_prompt_parts_with_skills(
    instance: BenchmarkInstance,
    *,
    include_file_hints: bool = False,
    source_context: str = "",
    criteria_dir: str | None = None,
) -> tuple[str, str]:
    """Render prompt parts with skills analysis framework injected."""
    system_msg, user_msg = render_prompt_parts(
        instance,
        include_file_hints=include_file_hints,
        source_context=source_context,
    )
    skills_section = build_skills_prompt_section(instance, criteria_dir)

    # Inject skills section before the final instructions block.
    # The instructions are the last section added by render_prompt_parts,
    # starting with a newline followed by the instructions text.
    tp = instance.task_prompt
    instructions_marker = f"\n{tp.instructions}"
    if instructions_marker in user_msg:
        user_msg = user_msg.replace(
            instructions_marker,
            f"\n\n{skills_section}\n{instructions_marker}",
            1,
        )
    else:
        # Fallback: append before the end
        user_msg = f"{user_msg}\n\n{skills_section}"

    return system_msg, user_msg


def render_prompt_with_skills(
    instance: BenchmarkInstance,
    *,
    include_file_hints: bool = False,
    source_context: str = "",
    criteria_dir: str | None = None,
) -> str:
    """Render a flat prompt string with skills analysis framework injected."""
    prompt = render_prompt(
        instance,
        include_file_hints=include_file_hints,
        source_context=source_context,
    )
    skills_section = build_skills_prompt_section(instance, criteria_dir)

    tp = instance.task_prompt
    instructions_marker = f"\n{tp.instructions}"
    if instructions_marker in prompt:
        prompt = prompt.replace(
            instructions_marker,
            f"\n\n{skills_section}\n{instructions_marker}",
            1,
        )
    else:
        prompt = f"{prompt}\n\n{skills_section}"

    return prompt


# ---------------------------------------------------------------------------
# Skills-augmented instance evaluation
# ---------------------------------------------------------------------------

def evaluate_instance_with_skills(
    instance: BenchmarkInstance,
    adapter,
    judge_model: str = JUDGE_MODEL,
    *,
    include_source: bool = True,
    file_hint_mode: str = "description",
    max_source_files: int = 3,
    max_source_chars: int = 6000,
    criteria_dir: str | None = None,
) -> InstanceResult:
    """Evaluate a single instance with skills-augmented prompts."""
    is_litellm = _is_litellm_adapter(adapter)
    include_file_hints = file_hint_mode == "gold"
    source_context = ""

    if include_source:
        source_context = build_source_context(
            instance,
            file_hint_mode=file_hint_mode,
            max_files=max_source_files,
            max_chars=max_source_chars,
        )

    # Generate patch with skills-augmented prompt
    start = time.monotonic()
    try:
        if is_litellm:
            system_msg, user_msg = render_prompt_parts_with_skills(
                instance,
                include_file_hints=include_file_hints,
                source_context=source_context,
                criteria_dir=criteria_dir,
            )
            raw_output = adapter.generate_patch(user_msg, system_prompt=system_msg)
        else:
            prompt = render_prompt_with_skills(
                instance,
                include_file_hints=include_file_hints,
                source_context=source_context,
                criteria_dir=criteria_dir,
            )
            raw_output = adapter.generate_patch(prompt)
    except Exception as e:
        logger.warning("Adapter failed for %s: %s", instance.instance_id, e)
        raw_output = ""
    gen_time = time.monotonic() - start

    # Collect token/cost metadata
    prompt_tokens = 0
    completion_tokens = 0
    cost_usd = 0.0
    if is_litellm:
        meta = adapter.last_response_meta
        prompt_tokens = meta.get("prompt_tokens", 0)
        completion_tokens = meta.get("completion_tokens", 0)
        cost_usd = meta.get("cost_usd", 0.0)

    # Parse diff and judge
    model_patch = parse_diff_from_output(raw_output)
    analysis = judge_patch(instance, model_patch, judge_model=judge_model)
    score = analysis.judge_score
    passed = analysis.judge_verdict == "pass"

    return InstanceResult(
        instance_id=instance.instance_id,
        cve_id=instance.cve_id,
        difficulty_tier=instance.difficulty_tier.value,
        ecosystem=instance.ecosystem,
        model_patch=model_patch,
        generation_time_s=round(gen_time, 3),
        patch_analysis=analysis,
        score=score,
        passed=passed,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        cost_usd=cost_usd,
        judge_cost_usd=analysis.judge_cost_usd,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="VulnBench Skills-Augmented Evaluation"
    )
    parser.add_argument("--benchmark", type=str, required=True)
    parser.add_argument("--model", type=str, required=True)
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
    parser.add_argument(
        "--criteria-dir",
        type=str,
        default=None,
        help="Custom criteria YAML directory (default: benchmark/skills/criteria)",
    )
    parser.add_argument("--output", type=str, default="results/skills/eval_report.json")
    parser.add_argument("--limit", type=int, default=0)

    args = parser.parse_args()

    # Load benchmark
    bench_data = json.loads(Path(args.benchmark).read_text())
    benchmark = BenchmarkDatabase(**bench_data)
    instances = benchmark.instances
    if args.limit > 0:
        instances = instances[: args.limit]

    adapter = LiteLLMAdapter(
        model=args.model,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
    )

    logger.info(
        "Skills-augmented eval: model=%s, instances=%d, judge=%s",
        args.model, len(instances), args.judge_model,
    )

    results: list[InstanceResult] = []
    pbar = tqdm(instances, desc="Skills eval")
    for instance in pbar:
        result = evaluate_instance_with_skills(
            instance,
            adapter,
            judge_model=args.judge_model,
            include_source=args.include_source,
            file_hint_mode=args.file_hint_mode,
            max_source_files=args.max_source_files,
            max_source_chars=args.max_source_chars,
            criteria_dir=args.criteria_dir,
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

    # Add skills metadata
    report.metadata["skills_augmented"] = True
    report.metadata["criteria_dir"] = args.criteria_dir or str(
        Path("benchmark/skills/criteria")
    )

    # Write output
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report.model_dump(), indent=2))

    print_report_summary(report.aggregate)
    print(f"  Skills-augmented report written to: {out_path}")


if __name__ == "__main__":
    main()
