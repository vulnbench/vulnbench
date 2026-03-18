"""Pipeline stage for generating VulnBench benchmark instances."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from tqdm import tqdm

from .benchmark_generator import (
    classify_tier,
    compute_quality_score,
    fetch_fix_diff,
    generate_task_prompt,
    passes_size_filter,
    select_curated_subset,
)
from .benchmark_models import BenchmarkDatabase, BenchmarkInstance
from .models import CVERecord

logger = logging.getLogger(__name__)

BENCHMARK_DIR = Path("data/benchmark")
TASKS_DIR = BENCHMARK_DIR / "tasks"
CHECKPOINT_DIR = BENCHMARK_DIR / "checkpoints"
CHECKPOINT_INTERVAL = 25


def _is_benchmark_candidate(record: CVERecord) -> bool:
    """Check if a record has all fields required for benchmarking."""
    if not record.fix_commit or not record.fix_commit.sha:
        return False
    if not record.download_url:
        return False
    if not record.cwe_ids:
        return False
    if not record.cvss_score or record.cvss_score <= 0:
        return False
    if not record.github_repo_url:
        return False
    return True


def _extract_owner_repo(github_url: str) -> str | None:
    """Extract 'owner/repo' from a GitHub URL."""
    # Handle https://github.com/owner/repo[/...]
    url = github_url.rstrip("/")
    if "github.com/" not in url:
        return None
    parts = url.split("github.com/")[1].split("/")
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return None


def _load_benchmark_checkpoint() -> tuple[set[str], list[BenchmarkInstance]]:
    """Load benchmark generation checkpoint."""
    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    state_path = CHECKPOINT_DIR / "benchmark_state.json"
    instances_path = CHECKPOINT_DIR / "benchmark_instances.json"

    processed_ids: set[str] = set()
    instances: list[BenchmarkInstance] = []

    if state_path.exists():
        try:
            data = json.loads(state_path.read_text())
            processed_ids = set(data.get("processed_cve_ids", []))
        except Exception:
            pass

    if instances_path.exists():
        try:
            raw = json.loads(instances_path.read_text())
            instances = [BenchmarkInstance(**item) for item in raw]
        except Exception:
            pass

    return processed_ids, instances


def _save_benchmark_checkpoint(
    processed_ids: set[str],
    instances: list[BenchmarkInstance],
) -> None:
    """Save benchmark generation checkpoint."""
    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)

    state_path = CHECKPOINT_DIR / "benchmark_state.json"
    tmp = state_path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"processed_cve_ids": sorted(processed_ids)}))
    tmp.rename(state_path)

    instances_path = CHECKPOINT_DIR / "benchmark_instances.json"
    tmp = instances_path.with_suffix(".tmp")
    tmp.write_text(json.dumps([inst.model_dump() for inst in instances], indent=2))
    tmp.rename(instances_path)


def run_benchmark_stage(
    records: list[CVERecord],
    limit: int = 0,
    mini_size: int = 200,
    shutdown_flag=None,
) -> None:
    """Generate VulnBench benchmark from CVE records.

    Args:
        records: CVE records from the pipeline checkpoint.
        limit: Max candidates to process (0 = unlimited).
        mini_size: Number of instances for VulnBench-mini.
        shutdown_flag: Callable returning True if shutdown requested.
    """
    logger.info("=== Stage 6: Generating VulnBench benchmark ===")

    # Ensure output directories
    BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)
    TASKS_DIR.mkdir(parents=True, exist_ok=True)

    # Filter to candidates
    candidates = [r for r in records if _is_benchmark_candidate(r)]
    logger.info("Benchmark candidates: %d / %d records", len(candidates), len(records))

    if limit > 0:
        candidates = candidates[:limit]

    # Load checkpoint
    processed_ids, instances = _load_benchmark_checkpoint()
    logger.info("Resuming: %d already processed, %d instances built", len(processed_ids), len(instances))

    # Track stats
    skipped_fetch = 0
    skipped_size = 0
    created = 0

    pbar = tqdm(candidates, desc="Benchmark Generation")
    for i, record in enumerate(pbar):
        if shutdown_flag and shutdown_flag():
            logger.info("Shutdown during benchmark generation, saving checkpoint")
            _save_benchmark_checkpoint(processed_ids, instances)
            return

        if record.cve_id in processed_ids:
            continue

        owner_repo = _extract_owner_repo(record.github_repo_url or "")
        if not owner_repo or not record.fix_commit:
            processed_ids.add(record.cve_id)
            continue

        # Fetch the fix diff
        gold_patch = fetch_fix_diff(owner_repo, record.fix_commit.sha)
        if not gold_patch:
            skipped_fetch += 1
            processed_ids.add(record.cve_id)
            continue

        # Size filter
        if not passes_size_filter(gold_patch):
            skipped_size += 1
            processed_ids.add(record.cve_id)
            continue

        # Classify tier
        tier, primary_cwe = classify_tier(record.cwe_ids)

        # Generate prompt
        task_prompt = generate_task_prompt(record, gold_patch, tier, primary_cwe)

        # Build instance
        instance = BenchmarkInstance(
            instance_id=f"vulnbench-{record.cve_id}",
            cve_id=record.cve_id,
            ecosystem=record.ecosystem,
            package_name=record.package_name,
            severity=record.severity,
            cvss_score=record.cvss_score,
            cwe_ids=record.cwe_ids,
            primary_cwe=primary_cwe,
            difficulty_tier=tier,
            gold_patch=gold_patch,
            task_prompt=task_prompt,
            vulnerable_version=record.vulnerable_version or "",
            download_url=record.download_url or "",
            github_repo_url=record.github_repo_url or "",
        )

        # Compute quality
        instance.quality_score = compute_quality_score(instance)

        instances.append(instance)
        processed_ids.add(record.cve_id)
        created += 1

        pbar.set_postfix(created=created, skipped_fetch=skipped_fetch, skipped_size=skipped_size)

        # Checkpoint
        if created % CHECKPOINT_INTERVAL == 0:
            _save_benchmark_checkpoint(processed_ids, instances)

    pbar.close()
    _save_benchmark_checkpoint(processed_ids, instances)

    logger.info(
        "Benchmark generation complete: %d instances created "
        "(%d skipped fetch, %d skipped size filter)",
        len(instances), skipped_fetch, skipped_size,
    )

    # Select curated subset
    mini = select_curated_subset(instances, target=mini_size)
    logger.info("VulnBench-mini: %d instances selected", len(mini))

    # Log tier distribution
    tier_counts: dict[str, int] = {}
    for inst in instances:
        tier_counts[inst.difficulty_tier.value] = tier_counts.get(inst.difficulty_tier.value, 0) + 1
    logger.info("Tier distribution (full): %s", tier_counts)

    mini_tier_counts: dict[str, int] = {}
    for inst in mini:
        mini_tier_counts[inst.difficulty_tier.value] = mini_tier_counts.get(inst.difficulty_tier.value, 0) + 1
    logger.info("Tier distribution (mini): %s", mini_tier_counts)

    # Write output files
    _write_outputs(instances, mini)


def _write_outputs(
    instances: list[BenchmarkInstance],
    mini: list[BenchmarkInstance],
) -> None:
    """Write benchmark database files and individual task prompts."""
    now = datetime.now(timezone.utc).isoformat() + "Z"

    # Ecosystem stats
    eco_counts: dict[str, int] = {}
    for inst in instances:
        eco = inst.ecosystem or "unknown"
        eco_counts[eco] = eco_counts.get(eco, 0) + 1

    tier_counts: dict[str, int] = {}
    for inst in instances:
        tier_counts[inst.difficulty_tier.value] = tier_counts.get(inst.difficulty_tier.value, 0) + 1

    # Full benchmark
    full_db = BenchmarkDatabase(
        metadata={
            "name": "VulnBench",
            "version": "1.0.0",
            "generated_at": now,
            "total_instances": len(instances),
            "tier_distribution": tier_counts,
            "ecosystem_distribution": eco_counts,
        },
        instances=instances,
    )
    full_path = BENCHMARK_DIR / "vulnbench_full.json"
    _atomic_write(full_path, json.dumps(full_db.model_dump(), indent=2))
    logger.info("Written: %s (%d instances)", full_path, len(instances))

    # Mini benchmark
    mini_eco: dict[str, int] = {}
    for inst in mini:
        eco = inst.ecosystem or "unknown"
        mini_eco[eco] = mini_eco.get(eco, 0) + 1

    mini_tier: dict[str, int] = {}
    for inst in mini:
        mini_tier[inst.difficulty_tier.value] = mini_tier.get(inst.difficulty_tier.value, 0) + 1

    mini_db = BenchmarkDatabase(
        metadata={
            "name": "VulnBench-mini",
            "version": "1.0.0",
            "generated_at": now,
            "total_instances": len(mini),
            "tier_distribution": mini_tier,
            "ecosystem_distribution": mini_eco,
        },
        instances=mini,
    )
    mini_path = BENCHMARK_DIR / "vulnbench_mini.json"
    _atomic_write(mini_path, json.dumps(mini_db.model_dump(), indent=2))
    logger.info("Written: %s (%d instances)", mini_path, len(mini))

    # Individual task prompts (no gold patch)
    TASKS_DIR.mkdir(parents=True, exist_ok=True)
    for inst in instances:
        task_data = {
            "instance_id": inst.instance_id,
            "cve_id": inst.cve_id,
            "ecosystem": inst.ecosystem,
            "package_name": inst.package_name,
            "difficulty_tier": inst.difficulty_tier.value,
            "task_prompt": inst.task_prompt.model_dump(),
        }
        task_path = TASKS_DIR / f"{inst.instance_id}.json"
        task_path.write_text(json.dumps(task_data, indent=2))

    logger.info("Written %d individual task files to %s", len(instances), TASKS_DIR)


def _atomic_write(path: Path, content: str) -> None:
    """Write content atomically via temp file + rename."""
    tmp = path.with_suffix(".tmp")
    tmp.write_text(content)
    tmp.rename(path)
