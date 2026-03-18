"""Structured diff parsing and comparison utilities for VulnBench evaluation.

Provides hunk-level overlap, content similarity, and minimality scoring
to complement file-level and CWE-pattern metrics.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field


@dataclass
class Hunk:
    """A single hunk from a unified diff."""

    file_path: str = ""
    old_start: int = 0
    old_count: int = 0
    new_start: int = 0
    new_count: int = 0
    added_lines: list[str] = field(default_factory=list)
    removed_lines: list[str] = field(default_factory=list)
    context_lines: list[str] = field(default_factory=list)


_HUNK_HEADER_RE = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@"
)


def parse_hunks(diff_text: str) -> list[Hunk]:
    """Parse a unified diff into structured Hunk objects.

    Handles standard unified diff format with ``diff --git`` headers
    and ``@@`` hunk markers.
    """
    hunks: list[Hunk] = []
    current_file = ""
    current_hunk: Hunk | None = None

    for line in diff_text.splitlines():
        # File header: diff --git a/path b/path
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                current_file = parts[3].removeprefix("b/")
            continue

        # Also pick up file path from +++ header
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue
        if line.startswith("+++ ") and not line.startswith("+++ /dev/null"):
            current_file = line[4:].removeprefix("b/")
            continue

        # Skip --- header
        if line.startswith("--- "):
            continue

        # Hunk header
        m = _HUNK_HEADER_RE.match(line)
        if m:
            current_hunk = Hunk(
                file_path=current_file,
                old_start=int(m.group(1)),
                old_count=int(m.group(2)) if m.group(2) is not None else 1,
                new_start=int(m.group(3)),
                new_count=int(m.group(4)) if m.group(4) is not None else 1,
            )
            hunks.append(current_hunk)
            continue

        # Content lines within a hunk
        if current_hunk is None:
            continue

        if line.startswith("+"):
            current_hunk.added_lines.append(line[1:])
        elif line.startswith("-"):
            current_hunk.removed_lines.append(line[1:])
        elif line.startswith(" "):
            current_hunk.context_lines.append(line[1:])

    return hunks


def compute_hunk_overlap(
    gold_hunks: list[Hunk],
    model_hunks: list[Hunk],
) -> float:
    """Compute Jaccard overlap of modified line ranges between gold and model.

    Groups hunks by file, builds sets of old-file line numbers being modified,
    and computes Jaccard per file, then averages across all files.
    """

    def _line_set(hunks: list[Hunk]) -> dict[str, set[int]]:
        by_file: dict[str, set[int]] = {}
        for h in hunks:
            lines = set(range(h.old_start, h.old_start + h.old_count))
            by_file.setdefault(h.file_path, set()).update(lines)
        return by_file

    gold_by_file = _line_set(gold_hunks)
    model_by_file = _line_set(model_hunks)

    all_files = set(gold_by_file.keys()) | set(model_by_file.keys())
    if not all_files:
        return 0.0

    total = 0.0
    for f in all_files:
        g = gold_by_file.get(f, set())
        m = model_by_file.get(f, set())
        union = g | m
        if union:
            total += len(g & m) / len(union)
        # File missing from one side contributes 0.0

    return total / len(all_files)


def compute_diff_content_similarity(
    gold_diff: str,
    model_diff: str,
) -> float:
    """Compute similarity of actual changed lines between gold and model diffs.

    Uses ``difflib.SequenceMatcher`` on the normalized added+removed lines
    to measure how similar the patch content is, independent of context.
    """
    gold_hunks = parse_hunks(gold_diff)
    model_hunks = parse_hunks(model_diff)

    def _collect(hunks: list[Hunk]) -> list[str]:
        lines: list[str] = []
        for h in hunks:
            lines.extend(l.strip() for l in h.added_lines)
            lines.extend(l.strip() for l in h.removed_lines)
        return lines

    gold_lines = _collect(gold_hunks)
    model_lines = _collect(model_hunks)

    if not gold_lines and not model_lines:
        return 1.0
    if not gold_lines or not model_lines:
        return 0.0

    return difflib.SequenceMatcher(None, gold_lines, model_lines).ratio()


def compute_minimality_score(
    gold_diff: str,
    model_diff: str,
) -> float:
    """Score how minimal the model patch is relative to the gold patch.

    Returns ``min(1.0, gold_changes / model_changes)``.
    A model patch the same size or smaller than gold gets 1.0.
    A patch 2x gold size gets 0.5, 3x gets 0.33, etc.
    """
    gold_hunks = parse_hunks(gold_diff)
    model_hunks = parse_hunks(model_diff)

    gold_changes = sum(
        len(h.added_lines) + len(h.removed_lines) for h in gold_hunks
    )
    model_changes = sum(
        len(h.added_lines) + len(h.removed_lines) for h in model_hunks
    )

    if model_changes == 0:
        return 0.0
    if gold_changes == 0:
        return 0.0

    return min(1.0, gold_changes / model_changes)


def extract_removed_lines(diff_text: str) -> str:
    """Extract only removed lines (starting with '-') from a unified diff."""
    removed: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:])
    return "\n".join(removed)
