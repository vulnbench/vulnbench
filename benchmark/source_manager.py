"""Source archive management for downloading and patching vulnerable code."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_CACHE_DIR = Path("data/benchmark/sources")


def _safe_extract_tar(tar: tarfile.TarFile, dest: Path) -> None:
    """Extract a tar archive without allowing path traversal.

    Python 3.12+ supports `extractall(filter="data")`, but the benchmark still
    needs to run on Python 3.9/3.10 in some environments. This helper preserves
    the traversal check on older interpreters by validating each member path
    before extraction.
    """
    dest_resolved = dest.resolve()
    safe_members = []

    for member in tar.getmembers():
        member_path = Path(member.name)
        if member_path.is_absolute() or ".." in member_path.parts:
            logger.warning("Skipping suspicious archive member: %s", member.name)
            continue

        target = (dest_resolved / member_path).resolve()
        if os.path.commonpath([str(dest_resolved), str(target)]) != str(dest_resolved):
            logger.warning("Skipping archive member outside destination: %s", member.name)
            continue

        safe_members.append(member)

    try:
        tar.extractall(path=dest, members=safe_members, filter="data")
    except TypeError:
        tar.extractall(path=dest, members=safe_members)


def download_source(
    url: str,
    instance_id: str,
    cache_dir: Path = DEFAULT_CACHE_DIR,
) -> Path | None:
    """Download and extract a source archive, cached by instance_id.

    Args:
        url: URL to the source archive (tar.gz).
        instance_id: Unique instance identifier for caching.
        cache_dir: Base directory for cached sources.

    Returns:
        Path to the extracted source directory, or None on failure.
    """
    dest = cache_dir / instance_id
    if dest.exists() and any(dest.iterdir()):
        logger.debug("Using cached source for %s", instance_id)
        return dest

    dest.mkdir(parents=True, exist_ok=True)

    try:
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        logger.debug("Downloading source for %s from %s", instance_id, url)
        urllib.request.urlretrieve(url, str(tmp_path))

        # Extract tar.gz
        with tarfile.open(tmp_path, "r:gz") as tar:
            _safe_extract_tar(tar, dest)

        tmp_path.unlink(missing_ok=True)

        # If archive extracted into a single subdirectory, use that
        children = list(dest.iterdir())
        if len(children) == 1 and children[0].is_dir():
            return children[0]

        return dest

    except Exception as e:
        logger.warning("Failed to download/extract source for %s: %s", instance_id, e)
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        return None


def apply_patch(
    source_dir: Path,
    patch_text: str,
    dry_run: bool = False,
) -> tuple[bool, str]:
    """Apply a unified diff patch to a source directory.

    Args:
        source_dir: Path to the source code directory.
        patch_text: Unified diff text to apply.
        dry_run: If True, only check if patch applies without modifying files.

    Returns:
        Tuple of (success, output_text).
    """
    cmd = ["patch", "-p1", "--batch"]
    if dry_run:
        cmd.append("--dry-run")

    try:
        result = subprocess.run(
            cmd,
            input=patch_text,
            capture_output=True,
            text=True,
            cwd=str(source_dir),
            timeout=30,
        )
        success = result.returncode == 0
        output = result.stdout + result.stderr
        return success, output.strip()

    except (subprocess.TimeoutExpired, OSError) as e:
        return False, str(e)
