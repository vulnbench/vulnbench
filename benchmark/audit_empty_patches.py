"""Audit VulnBench result files for empty-patch generation failures.

This helps distinguish benchmark failures caused by model-generated patches from
failures caused by adapter exceptions or empty model responses. Older result
files cannot perfectly separate those cases because the previous harness did not
persist adapter errors per instance.
"""

from __future__ import annotations

import argparse
import glob
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class FileAudit:
    path: Path
    model: str
    total: int
    pass_rate: float | None
    empty: int = 0
    likely_adapter_error: int = 0
    ambiguous_empty: int = 0
    max_token_empty: int = 0
    recorded_generation_error: int = 0

    @property
    def empty_rate(self) -> float:
        return self.empty / self.total if self.total else 0.0


@dataclass
class ModelAudit:
    model: str
    files: int = 0
    total: int = 0
    empty: int = 0
    likely_adapter_error: int = 0
    ambiguous_empty: int = 0
    max_token_empty: int = 0
    recorded_generation_error: int = 0

    @property
    def empty_rate(self) -> float:
        return self.empty / self.total if self.total else 0.0


def audit_file(path: Path, max_tokens: int) -> FileAudit | None:
    try:
        data = json.loads(path.read_text())
    except Exception:
        return None

    results = data.get("results")
    if not isinstance(results, list) or not results:
        return None

    metadata = data.get("metadata", {})
    aggregate = data.get("aggregate", {})
    model = metadata.get("model") or metadata.get("adapter") or path.stem
    audit = FileAudit(
        path=path,
        model=model,
        total=len(results),
        pass_rate=aggregate.get("pass_rate"),
    )

    for result in results:
        patch = result.get("model_patch") or ""
        if result.get("generation_error"):
            audit.recorded_generation_error += 1

        if patch.strip():
            continue

        audit.empty += 1
        prompt_tokens = result.get("prompt_tokens") or 0
        completion_tokens = result.get("completion_tokens") or 0
        cost_usd = result.get("cost_usd") or 0.0

        if result.get("generation_error"):
            audit.likely_adapter_error += 1
        elif prompt_tokens == 0 and completion_tokens == 0 and cost_usd == 0:
            audit.likely_adapter_error += 1
        else:
            # On older result files, token-bearing empties may be true empty
            # responses, max-token exhaustion, or stale metadata after an adapter
            # exception. They need rerun telemetry to attribute precisely.
            audit.ambiguous_empty += 1

        if completion_tokens >= max_tokens:
            audit.max_token_empty += 1

    return audit


def _format_rate(value: float) -> str:
    return f"{value * 100:5.1f}%"


def print_file_audits(audits: list[FileAudit], limit: int) -> None:
    print("Top result files by empty model_patch rate")
    print("empty% empty adapter? ambiguous maxTok total pass  model                           file")
    for audit in audits[:limit]:
        pass_rate = "" if audit.pass_rate is None else f"{audit.pass_rate:.3f}"
        print(
            f"{_format_rate(audit.empty_rate)} "
            f"{audit.empty:5d} "
            f"{audit.likely_adapter_error:8d} "
            f"{audit.ambiguous_empty:9d} "
            f"{audit.max_token_empty:6d} "
            f"{audit.total:5d} "
            f"{pass_rate:>5} "
            f"{audit.model[:31]:31s} "
            f"{audit.path}"
        )


def print_model_audits(audits: list[ModelAudit], limit: int) -> None:
    print("\nAggregate by model")
    print("empty% empty adapter? ambiguous maxTok files total model")
    for audit in audits[:limit]:
        print(
            f"{_format_rate(audit.empty_rate)} "
            f"{audit.empty:5d} "
            f"{audit.likely_adapter_error:8d} "
            f"{audit.ambiguous_empty:9d} "
            f"{audit.max_token_empty:6d} "
            f"{audit.files:5d} "
            f"{audit.total:5d} "
            f"{audit.model}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit VulnBench empty-patch results")
    parser.add_argument(
        "paths",
        nargs="*",
        default=["results/*.json", "results/skills/*.json"],
        help="Result JSON paths or glob patterns",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=4096,
        help="Completion-token threshold for max-token empty responses",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=40,
        help="Rows to print for file and model summaries",
    )
    parser.add_argument(
        "--total",
        type=int,
        default=0,
        help="Only include files with this result count (0=all)",
    )
    parser.add_argument(
        "--exclude-best",
        action="store_true",
        help="Exclude best-of-N aggregate files",
    )
    parser.add_argument(
        "--exclude-skills",
        action="store_true",
        help="Exclude results/skills files",
    )
    args = parser.parse_args()

    paths: list[Path] = []
    for pattern in args.paths:
        matched = sorted(glob.glob(pattern))
        paths.extend(Path(p) for p in (matched or [pattern]))

    file_audits: list[FileAudit] = []
    for path in paths:
        if not path.is_file():
            continue
        if args.exclude_best and path.name.startswith("best"):
            continue
        if args.exclude_skills and "skills" in path.parts:
            continue

        audit = audit_file(path, max_tokens=args.max_tokens)
        if audit is None or audit.empty == 0:
            continue
        if args.total and audit.total != args.total:
            continue
        file_audits.append(audit)

    file_audits.sort(key=lambda a: (a.empty_rate, a.empty), reverse=True)
    print_file_audits(file_audits, args.limit)

    by_model: dict[str, ModelAudit] = {}
    for audit in file_audits:
        model_audit = by_model.setdefault(audit.model, ModelAudit(model=audit.model))
        model_audit.files += 1
        model_audit.total += audit.total
        model_audit.empty += audit.empty
        model_audit.likely_adapter_error += audit.likely_adapter_error
        model_audit.ambiguous_empty += audit.ambiguous_empty
        model_audit.max_token_empty += audit.max_token_empty
        model_audit.recorded_generation_error += audit.recorded_generation_error

    model_audits = sorted(
        by_model.values(),
        key=lambda a: (a.empty_rate, a.empty),
        reverse=True,
    )
    print_model_audits(model_audits, args.limit)

    if file_audits:
        print(
            "\nNote: for old result files, 'ambiguous' includes true empty responses, "
            "max-token exhaustion, and possible stale token metadata after adapter "
            "exceptions. New runs include generation_error and retry counters."
        )


if __name__ == "__main__":
    main()
