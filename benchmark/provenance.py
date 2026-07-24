"""Provenance stamping for VulnBench reports.

Every published number should be traceable to the exact harness commit and
dataset bytes that produced it. These helpers are cheap and never raise —
missing git or files degrade to sentinel values rather than failing a run.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path


def harness_version() -> str:
    """Current git commit of the harness, with -dirty suffix if uncommitted."""
    try:
        root = Path(__file__).resolve().parent.parent
        sha = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        if not sha:
            return "unknown"
        dirty = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        return f"{sha}-dirty" if dirty else sha
    except Exception:
        return "unknown"


def dataset_sha256(path: str | Path) -> str:
    """SHA-256 of the benchmark dataset file (first 16 hex chars)."""
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()[:16]
    except OSError:
        return "unknown"


def provenance_metadata(benchmark_path: str | Path) -> dict:
    return {
        "harness_version": harness_version(),
        "dataset_sha256": dataset_sha256(benchmark_path),
    }
