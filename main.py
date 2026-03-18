#!/usr/bin/env python3
"""CVE Vulnerability Database Builder.

Scrapes GitHub Advisory Database for CVEs affecting open-source projects,
enriches with NVD CVSS data, resolves GitHub repos, and finds vulnerable versions.

Usage:
    python main.py                    # Full run (target: 10,000 CVEs)
    python main.py --limit 10         # Test with 10 records
    python main.py --resume           # Resume from checkpoint
    python main.py --stage version    # Re-run only the version stage
    python main.py --clear-checkpoint # Clear checkpoint and start fresh
"""

import argparse
import json
import logging
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path

from tqdm import tqdm

from src.benchmark_stage import run_benchmark_stage
from src.checkpoint import CheckpointManager
from src.ghsa import fetch_advisories
from src.models import CVEDatabase, CVERecord, PipelineState
from src.nvd import enrich_record
from src.repo_resolver import resolve_repo
from src.version_finder import find_vulnerable_version

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("data/pipeline.log", mode="a"),
    ],
)
logger = logging.getLogger(__name__)

# Graceful shutdown flag
_shutdown = False


def _handle_signal(signum, frame):
    global _shutdown
    logger.info("Shutdown requested (signal %d), finishing current batch...", signum)
    _shutdown = True


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


CHECKPOINT_INTERVAL = 50


def run_pipeline(limit: int = 0, resume: bool = True, stage: str = "", mini_size: int = 200) -> None:
    """Run the full CVE collection pipeline."""
    global _shutdown

    ckpt = CheckpointManager()
    state = PipelineState()
    records: list[CVERecord] = []

    # Resume from checkpoint if available
    if resume and ckpt.has_checkpoint():
        state = ckpt.load_state()
        records = ckpt.load_records()
        logger.info(
            "Resuming from checkpoint: stage=%s, records=%d",
            state.stage, len(records),
        )
    else:
        logger.info("Starting fresh pipeline run")

    # If --stage is specified, jump directly to that stage and reset its counter
    if stage:
        valid_stages = ("collect", "enrich", "resolve", "version", "validate", "benchmark")
        if stage not in valid_stages:
            logger.error("Invalid stage '%s'. Valid stages: %s", stage, ", ".join(valid_stages))
            return
        if not records:
            logger.error("Cannot use --stage without existing checkpoint data")
            return
        logger.info("Jumping to stage '%s' (resetting stage counter)", stage)
        state.stage = stage
        if stage == "version":
            # Clear vulnerable_version on all records so they get re-processed
            for r in records:
                r.vulnerable_version = None
                r.download_url = None
            state.versioned_count = 0
        elif stage == "enrich":
            state.enriched_count = 0
        elif stage == "resolve":
            state.resolved_count = 0
        elif stage == "validate":
            state.validated_count = 0
        elif stage == "benchmark":
            pass  # No counter to reset; benchmark has its own checkpointing

    # ── Stage 1: Collect ──────────────────────────────────────────────
    if state.stage == "collect":
        logger.info("=== Stage 1: Collecting GHSA advisories ===")
        new_records = fetch_advisories(
            date_start="2022-01-01",
            date_end="2026-12-31",
            limit=limit if limit > 0 else 0,
            skip_ecosystems=state.ecosystems_done,
        )

        # Merge with any existing records (from partial resume)
        existing_cves = {r.cve_id for r in records}
        for r in new_records:
            if r.cve_id not in existing_cves:
                records.append(r)
                existing_cves.add(r.cve_id)

        state.collected_count = len(records)
        state.stage = "enrich"
        ckpt.save(state, records)
        logger.info("Collection complete: %d records", len(records))

        if _shutdown:
            logger.info("Shutdown after collection, checkpoint saved")
            return

    # ── Stage 2: Enrich with NVD CVSS ─────────────────────────────────
    if state.stage == "enrich":
        logger.info("=== Stage 2: Enriching with NVD CVSS data ===")
        needs_enrichment = [
            r for r in records
            if not r.cvss_score or r.cvss_score == 0
        ]
        logger.info("Records needing CVSS enrichment: %d / %d",
                     len(needs_enrichment), len(records))

        enriched = state.enriched_count
        pbar = tqdm(needs_enrichment, desc="NVD Enrichment",
                    initial=enriched, total=len(needs_enrichment))

        for i, record in enumerate(needs_enrichment):
            if _shutdown:
                logger.info("Shutdown during enrichment, saving checkpoint")
                state.enriched_count = enriched
                ckpt.save(state, records)
                return

            if i < enriched:
                pbar.update(1)
                continue

            try:
                enrich_record(record)
            except Exception as e:
                logger.warning("NVD enrichment failed for %s: %s", record.cve_id, e)

            enriched += 1
            pbar.update(1)

            if enriched % CHECKPOINT_INTERVAL == 0:
                state.enriched_count = enriched
                ckpt.save(state, records)

        pbar.close()
        state.enriched_count = enriched
        state.stage = "resolve"
        ckpt.save(state, records)
        logger.info("Enrichment complete")

    # ── Stage 3: Resolve GitHub repos ─────────────────────────────────
    if state.stage == "resolve":
        logger.info("=== Stage 3: Resolving GitHub repositories ===")
        needs_resolution = [r for r in records if not r.github_repo_url]
        already_resolved = sum(1 for r in records if r.github_repo_url)
        logger.info(
            "Already have repo URL: %d, Need resolution: %d",
            already_resolved, len(needs_resolution),
        )

        resolved = state.resolved_count
        pbar = tqdm(needs_resolution, desc="Repo Resolution",
                    initial=resolved, total=len(needs_resolution))

        for i, record in enumerate(needs_resolution):
            if _shutdown:
                logger.info("Shutdown during repo resolution, saving checkpoint")
                state.resolved_count = resolved
                ckpt.save(state, records)
                return

            if i < resolved:
                pbar.update(1)
                continue

            try:
                url = resolve_repo(
                    record.package_name,
                    record.ecosystem,
                    record.references,
                    record.github_repo_url,
                )
                if url:
                    record.github_repo_url = url
            except Exception as e:
                logger.warning("Repo resolution failed for %s: %s", record.cve_id, e)

            resolved += 1
            pbar.update(1)

            if resolved % CHECKPOINT_INTERVAL == 0:
                state.resolved_count = resolved
                ckpt.save(state, records)

        pbar.close()
        state.resolved_count = resolved
        state.stage = "version"
        ckpt.save(state, records)

        resolved_total = sum(1 for r in records if r.github_repo_url)
        logger.info("Repo resolution complete: %d/%d have GitHub URLs",
                     resolved_total, len(records))

    # ── Stage 4: Find vulnerable versions ─────────────────────────────
    if state.stage == "version":
        logger.info("=== Stage 4: Finding vulnerable versions ===")
        needs_version = [
            r for r in records
            if r.github_repo_url and not r.vulnerable_version
        ]
        logger.info("Records needing version resolution: %d", len(needs_version))

        versioned = state.versioned_count
        pbar = tqdm(needs_version, desc="Version Finding",
                    initial=versioned, total=len(needs_version))

        for i, record in enumerate(needs_version):
            if _shutdown:
                logger.info("Shutdown during version finding, saving checkpoint")
                state.versioned_count = versioned
                ckpt.save(state, records)
                return

            if i < versioned:
                pbar.update(1)
                continue

            try:
                version_data = find_vulnerable_version(
                    record.github_repo_url,
                    record.vulnerable_version_range,
                    record.patched_version,
                    record.references,
                    package_name=record.package_name or None,
                    ecosystem=record.ecosystem or None,
                )
                if version_data.get("vulnerable_version"):
                    record.vulnerable_version = version_data["vulnerable_version"]
                if version_data.get("download_url"):
                    record.download_url = version_data["download_url"]
                if version_data.get("fix_commit"):
                    from src.models import FixCommit
                    record.fix_commit = FixCommit(**version_data["fix_commit"])
            except Exception as e:
                logger.warning("Version finding failed for %s: %s", record.cve_id, e)

            versioned += 1
            pbar.update(1)

            if versioned % CHECKPOINT_INTERVAL == 0:
                state.versioned_count = versioned
                ckpt.save(state, records)

        pbar.close()
        state.versioned_count = versioned
        state.stage = "validate"
        ckpt.save(state, records)
        logger.info("Version finding complete")

    # ── Stage 5: Validate and write output ────────────────────────────
    if state.stage == "validate":
        logger.info("=== Stage 5: Validating and writing output ===")
        valid_records = []
        rejected = 0

        for record in records:
            if _is_valid(record):
                valid_records.append(record)
            else:
                rejected += 1

        # Deduplicate by CVE ID (keep first occurrence)
        seen = set()
        deduped = []
        for r in valid_records:
            if r.cve_id not in seen:
                seen.add(r.cve_id)
                deduped.append(r)

        logger.info(
            "Validation: %d valid, %d rejected, %d after dedup",
            len(valid_records), rejected, len(deduped),
        )

        # Sort by published date (newest first)
        deduped.sort(key=lambda r: r.published_date or "", reverse=True)

        # Apply limit if set
        if limit > 0:
            deduped = deduped[:limit]

        # Write final database
        _write_database(deduped)

        state.validated_count = len(deduped)
        state.stage = "done"
        ckpt.save(state, records)

    # ── Stage 6: Benchmark generation ─────────────────────────────────
    if state.stage == "benchmark" or stage == "benchmark":
        run_benchmark_stage(
            records=records,
            limit=limit,
            mini_size=mini_size,
            shutdown_flag=lambda: _shutdown,
        )

    # ── Done ──────────────────────────────────────────────────────────
    logger.info("=== Pipeline complete ===")
    _print_summary(state, records)


def _is_valid(record: CVERecord) -> bool:
    """Check if a record has minimum required fields."""
    if not record.cve_id:
        return False
    if not record.github_repo_url:
        return False
    if not record.description and not record.title:
        return False
    return True


def _write_database(records: list[CVERecord]) -> None:
    """Write the final JSON database."""
    output_path = Path("data/cve_database.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    db = CVEDatabase(
        metadata={
            "version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
            "total_entries": len(records),
            "date_range": {"start": "2022-01-01", "end": "2026-12-31"},
            "sources": ["ghsa", "nvd"],
        },
        vulnerabilities=records,
    )

    # Atomic write
    tmp = output_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(db.model_dump(), indent=2))
    tmp.rename(output_path)

    logger.info("Database written to %s (%d entries)", output_path, len(records))


def _print_summary(state: PipelineState, records: list[CVERecord]) -> None:
    """Print pipeline summary statistics."""
    total = len(records)
    with_repo = sum(1 for r in records if r.github_repo_url)
    with_version = sum(1 for r in records if r.vulnerable_version)
    with_download = sum(1 for r in records if r.download_url)
    with_cvss = sum(1 for r in records if r.cvss_score and r.cvss_score > 0)

    ecosystems = {}
    for r in records:
        eco = r.ecosystem or "unknown"
        ecosystems[eco] = ecosystems.get(eco, 0) + 1

    print("\n" + "=" * 60)
    print("  CVE Vulnerability Database - Pipeline Summary")
    print("=" * 60)
    print(f"  Total records collected:   {total}")
    print(f"  With GitHub repo URL:      {with_repo} ({_pct(with_repo, total)})")
    print(f"  With vulnerable version:   {with_version} ({_pct(with_version, total)})")
    print(f"  With download URL:         {with_download} ({_pct(with_download, total)})")
    print(f"  With CVSS score:           {with_cvss} ({_pct(with_cvss, total)})")
    print(f"  Validated entries:         {state.validated_count}")
    print()
    print("  By ecosystem:")
    for eco, count in sorted(ecosystems.items(), key=lambda x: -x[1]):
        print(f"    {eco:15s} {count:6d}")
    print("=" * 60)


def _pct(n: int, total: int) -> str:
    if total == 0:
        return "0%"
    return f"{n * 100 // total}%"


def main():
    parser = argparse.ArgumentParser(description="CVE Vulnerability Database Builder")
    parser.add_argument("--limit", type=int, default=0,
                       help="Max number of CVEs to process (0=unlimited, default: 0)")
    parser.add_argument("--resume", action="store_true", default=True,
                       help="Resume from checkpoint (default: True)")
    parser.add_argument("--no-resume", action="store_true",
                       help="Start fresh, ignore checkpoint")
    parser.add_argument("--stage", type=str, default="",
                       help="Re-run a specific stage (collect, enrich, resolve, version, validate)")
    parser.add_argument("--clear-checkpoint", action="store_true",
                       help="Clear checkpoint and exit")
    parser.add_argument("--benchmark-mini-size", type=int, default=200,
                       help="Number of instances for VulnBench-mini (default: 200)")

    args = parser.parse_args()

    # Ensure data directory exists
    Path("data/checkpoints").mkdir(parents=True, exist_ok=True)

    if args.clear_checkpoint:
        CheckpointManager().clear()
        print("Checkpoint cleared.")
        return

    resume = not args.no_resume
    if args.stage:
        resume = True  # --stage requires checkpoint data
    run_pipeline(limit=args.limit, resume=resume, stage=args.stage, mini_size=args.benchmark_mini_size)


if __name__ == "__main__":
    main()
