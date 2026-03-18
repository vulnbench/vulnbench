"""Core generation logic for VulnBench benchmark instances."""

from __future__ import annotations

import json
import logging
import re
import subprocess
from typing import Optional

from .benchmark_models import (
    BenchmarkInstance,
    DifficultyTier,
    FileChange,
    GoldPatch,
    TaskPrompt,
)
from .models import CVERecord
from .rate_limiter import benchmark_limiter

logger = logging.getLogger(__name__)

SCRUB_SECTION_HEADERS = {
    "patch",
    "patches",
    "references",
    "workarounds",
    "workaround",
    "recommended fix",
    "fix",
    "solution",
    "mitigation",
}

SCRUB_LINE_PATTERNS = [
    re.compile(r"https?://\S*(?:/commit/|\.patch\b)\S*", re.IGNORECASE),
    re.compile(r"\b(?:fixed|patched|addressed) in version\b", re.IGNORECASE),
    re.compile(r"\b(?:fixed|patched|addressed) in\b", re.IGNORECASE),
    re.compile(r"\bupgrade to\b", re.IGNORECASE),
]

COMMIT_HASH_RE = re.compile(r"\b[0-9a-f]{7,40}\b")
SCRUB_REPLACEMENTS = [
    (
        re.compile(r"\b(?:identifier|name) of the patch is\b.*?(?:\.|$)", re.IGNORECASE),
        "",
    ),
    (
        re.compile(r"\bit is recommended to apply a patch to fix this issue\.?", re.IGNORECASE),
        "",
    ),
    (
        re.compile(r"\b(?:the )?patch can be viewed and applied from the following link:.*?(?:\.|$)", re.IGNORECASE),
        "",
    ),
    (
        re.compile(r"\b(?:recommended|best|only) course of action is to apply the provided patch.*?(?:\.|$)", re.IGNORECASE),
        "",
    ),
]

# ── CWE-to-tier mapping ──────────────────────────────────────────────────

TIER_1_CWES = {"CWE-79", "CWE-89", "CWE-22"}  # XSS, SQLi, Path Traversal
TIER_2_CWES = {"CWE-862", "CWE-863", "CWE-352", "CWE-200"}  # Auth, CSRF, Info Disclosure
TIER_3_CWES = {"CWE-94", "CWE-400", "CWE-20"}  # Code Injection, Resource Exhaustion, Input Validation

# ── CWE guidance strings ─────────────────────────────────────────────────

CWE_GUIDANCE = {
    "CWE-79": (
        "Cross-Site Scripting (XSS). Typical fixes involve output encoding/escaping "
        "user-controlled data before rendering in HTML, JavaScript, or URL contexts."
    ),
    "CWE-89": (
        "SQL Injection. Typical fixes involve using parameterized queries or prepared "
        "statements instead of string concatenation for SQL construction."
    ),
    "CWE-22": (
        "Path Traversal. Typical fixes involve canonicalizing file paths and validating "
        "they remain within an expected base directory."
    ),
    "CWE-862": (
        "Missing Authorization. Typical fixes involve adding permission or role checks "
        "before allowing access to protected resources."
    ),
    "CWE-863": (
        "Incorrect Authorization. Typical fixes involve correcting permission logic to "
        "properly enforce access control boundaries."
    ),
    "CWE-352": (
        "Cross-Site Request Forgery (CSRF). Typical fixes involve adding and validating "
        "anti-CSRF tokens in state-changing requests."
    ),
    "CWE-200": (
        "Information Disclosure. Typical fixes involve removing sensitive data from "
        "responses, logs, or error messages."
    ),
    "CWE-94": (
        "Code Injection. Typical fixes involve removing or sandboxing dynamic code "
        "execution (eval, exec) and using safe alternatives."
    ),
    "CWE-400": (
        "Resource Exhaustion. Typical fixes involve adding size limits, timeouts, "
        "rate limiting, or resource caps to prevent denial of service."
    ),
    "CWE-20": (
        "Improper Input Validation. Typical fixes involve adding validation logic "
        "such as regex checks, type enforcement, and range bounds."
    ),
}


def fetch_fix_diff(owner_repo: str, commit_sha: str) -> Optional[GoldPatch]:
    """Fetch the diff for a fix commit via the GitHub CLI.

    Args:
        owner_repo: Repository in "owner/repo" format.
        commit_sha: The commit SHA to fetch.

    Returns:
        GoldPatch with parsed diff data, or None on failure.
    """
    benchmark_limiter.acquire()
    try:
        result = subprocess.run(
            ["gh", "api", f"/repos/{owner_repo}/commits/{commit_sha}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            logger.debug("gh api failed for %s@%s: %s", owner_repo, commit_sha, result.stderr.strip())
            return None

        data = json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
        logger.debug("Failed to fetch commit %s@%s: %s", owner_repo, commit_sha, e)
        return None

    files_changed: list[FileChange] = []
    total_add = 0
    total_del = 0

    for f in data.get("files", []):
        added = f.get("additions", 0)
        removed = f.get("deletions", 0)
        status = f.get("status", "modified")
        files_changed.append(FileChange(
            path=f.get("filename", ""),
            lines_added=added,
            lines_removed=removed,
            change_type=status,
        ))
        total_add += added
        total_del += removed

    # Build raw diff from file patches
    diff_parts = []
    for f in data.get("files", []):
        patch = f.get("patch")
        if patch:
            diff_parts.append(f"diff --git a/{f['filename']} b/{f['filename']}")
            diff_parts.append(patch)

    return GoldPatch(
        commit_sha=commit_sha,
        raw_diff="\n".join(diff_parts),
        files_changed=files_changed,
        total_additions=total_add,
        total_deletions=total_del,
    )


def passes_size_filter(gold_patch: GoldPatch) -> bool:
    """Check if a patch is within acceptable size bounds.

    Filters to 3-500 total lines changed across at most 10 files.
    """
    total_lines = gold_patch.total_additions + gold_patch.total_deletions
    if total_lines < 3 or total_lines > 500:
        return False
    if len(gold_patch.files_changed) > 10:
        return False
    return True


def classify_tier(cwe_ids: list[str]) -> tuple[DifficultyTier, str]:
    """Classify difficulty tier based on CWE IDs.

    Returns:
        Tuple of (tier, primary_cwe). Unmapped CWEs default to tier 2.
    """
    for cwe in cwe_ids:
        if cwe in TIER_1_CWES:
            return DifficultyTier.TIER_1, cwe
    for cwe in cwe_ids:
        if cwe in TIER_3_CWES:
            return DifficultyTier.TIER_3, cwe
    for cwe in cwe_ids:
        if cwe in TIER_2_CWES:
            return DifficultyTier.TIER_2, cwe
    # Default: tier 2 with first CWE
    primary = cwe_ids[0] if cwe_ids else ""
    return DifficultyTier.TIER_2, primary


def generate_task_prompt(
    record: CVERecord,
    gold_patch: GoldPatch,
    tier: DifficultyTier,
    primary_cwe: str,
) -> TaskPrompt:
    """Build the model prompt from CVE data (no gold patch content leaked).

    The prompt contains vulnerability description, CWE guidance, and hints
    about which files are affected — but never the actual fix.
    """
    guidance = CWE_GUIDANCE.get(primary_cwe, "")
    cwe_label = primary_cwe if primary_cwe else "Unknown"

    system_context = (
        "You are a security engineer tasked with fixing a vulnerability in an open-source project. "
        "Analyze the vulnerability description and produce a unified diff that fixes the issue. "
        "Your patch should be minimal, focused, and correct."
    )

    description = scrub_advisory_text(
        record.description or record.title or f"Vulnerability {record.cve_id}"
    )
    vuln_desc = (
        f"CVE: {record.cve_id}\n"
        f"Package: {record.package_name} ({record.ecosystem})\n"
        f"Severity: {record.severity}"
    )
    if record.cvss_score:
        vuln_desc += f" (CVSS {record.cvss_score})"
    vuln_desc += f"\n\nDescription:\n{description}"

    instructions = (
        "Produce a unified diff (patch) that fixes this vulnerability. "
        "The patch should:\n"
        "1. Address the root cause of the vulnerability\n"
        "2. Be minimal — only change what is necessary\n"
        "3. Not introduce new bugs or break existing functionality\n"
        "4. Follow the project's existing code style\n\n"
        "Output your fix as a unified diff enclosed in a code block."
    )

    return TaskPrompt(
        system_context=system_context,
        vulnerability_description=vuln_desc,
        cwe_category=cwe_label,
        cwe_guidance=guidance,
        affected_files_hint=[],
        instructions=instructions,
    )


def scrub_advisory_text(text: str) -> str:
    """Remove explicit patch/fix leakage from advisory text.

    This intentionally strips direct patch references, commit URLs/hashes,
    and sections that prescribe the exact remediation. The goal is not to
    preserve every advisory detail; it is to remove easy answer leakage while
    keeping the vulnerability description intact.
    """
    if not text:
        return ""

    scrubbed = _scrub_advisory_lines(text, strict=True)
    if len(scrubbed) < 80:
        scrubbed = _scrub_advisory_lines(text, strict=False)
    if len(scrubbed) < 80:
        scrubbed = _scrub_advisory_minimal(text)
    scrubbed = re.sub(r"\n{3,}", "\n\n", scrubbed)
    return scrubbed.strip()


def _scrub_advisory_lines(text: str, *, strict: bool) -> str:
    scrubbed_lines: list[str] = []
    skip_section = False

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        lowered = stripped.lower().rstrip(":")

        if stripped.startswith("### "):
            header = lowered[4:].strip()
            skip_section = header in SCRUB_SECTION_HEADERS
            if skip_section:
                continue

        if skip_section:
            continue

        cleaned = COMMIT_HASH_RE.sub("[redacted]", line)
        cleaned = re.sub(r"https?://\S+", "[redacted-url]", cleaned)
        for pattern, replacement in SCRUB_REPLACEMENTS:
            cleaned = pattern.sub(replacement, cleaned)
        cleaned = re.sub(
            r"\b(?:versions?|releases?)\s+(?:before|prior to)\s+[A-Za-z0-9._:-]+\b",
            "affected versions before [redacted-version]",
            cleaned,
            flags=re.IGNORECASE,
        )
        cleaned = re.sub(
            r"\b(?:fixed|patched|addressed)\s+in\s+[A-Za-z0-9._:-]+\b",
            "fixed in [redacted-version]",
            cleaned,
            flags=re.IGNORECASE,
        )
        if strict and any(p.search(cleaned) for p in SCRUB_LINE_PATTERNS):
            continue
        cleaned = cleaned.strip()
        if not cleaned:
            continue
        scrubbed_lines.append(cleaned)

    return "\n".join(scrubbed_lines)


def _scrub_advisory_minimal(text: str) -> str:
    cleaned = COMMIT_HASH_RE.sub("[redacted]", text)
    cleaned = re.sub(r"https?://\S+", "[redacted-url]", cleaned)
    for pattern, replacement in SCRUB_REPLACEMENTS:
        cleaned = pattern.sub(replacement, cleaned)
    cleaned = re.sub(
        r"\b(?:versions?|releases?)\s+(?:before|prior to)\s+[A-Za-z0-9._:-]+\b",
        "affected versions before [redacted-version]",
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(
        r"\b(?:fixed|patched|addressed)\s+in\s+[A-Za-z0-9._:-]+\b",
        "fixed in [redacted-version]",
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def compute_quality_score(instance: BenchmarkInstance) -> float:
    """Compute a 0.0-1.0 quality score for a benchmark instance.

    Factors:
    - Description quality (length/detail)
    - Ideal diff size (sweet spot: 10-100 lines)
    - Single CWE (cleaner signal)
    - Has CVSS score
    - Focused file count (fewer files = easier to evaluate)
    """
    score = 0.0

    # Description quality (0-0.25)
    desc_len = len(instance.task_prompt.vulnerability_description)
    if desc_len > 200:
        score += 0.25
    elif desc_len > 100:
        score += 0.15
    elif desc_len > 50:
        score += 0.08

    # Diff size sweet spot (0-0.25)
    total_lines = instance.gold_patch.total_additions + instance.gold_patch.total_deletions
    if 10 <= total_lines <= 100:
        score += 0.25
    elif 5 <= total_lines <= 200:
        score += 0.15
    else:
        score += 0.05

    # Single CWE (0-0.2)
    if len(instance.cwe_ids) == 1:
        score += 0.2
    elif len(instance.cwe_ids) == 2:
        score += 0.1

    # Has CVSS (0-0.15)
    if instance.cvss_score and instance.cvss_score > 0:
        score += 0.15

    # Focused file count (0-0.15)
    n_files = len(instance.gold_patch.files_changed)
    if n_files == 1:
        score += 0.15
    elif n_files <= 3:
        score += 0.1
    elif n_files <= 5:
        score += 0.05

    return round(min(score, 1.0), 3)


def select_curated_subset(
    instances: list[BenchmarkInstance],
    target: int = 200,
) -> list[BenchmarkInstance]:
    """Select a balanced, high-quality curated subset for VulnBench-mini.

    Strategy:
    - Equal thirds across difficulty tiers
    - Proportional ecosystem representation (min 2 per ecosystem)
    - Sorted by quality score (highest first)
    """
    per_tier = target // 3
    remainder = target - per_tier * 3

    # Group by tier
    by_tier: dict[DifficultyTier, list[BenchmarkInstance]] = {
        DifficultyTier.TIER_1: [],
        DifficultyTier.TIER_2: [],
        DifficultyTier.TIER_3: [],
    }
    for inst in instances:
        by_tier[inst.difficulty_tier].append(inst)

    # Sort each tier by quality
    for tier in by_tier:
        by_tier[tier].sort(key=lambda x: x.quality_score, reverse=True)

    selected: list[BenchmarkInstance] = []
    tier_order = [DifficultyTier.TIER_1, DifficultyTier.TIER_2, DifficultyTier.TIER_3]

    for i, tier in enumerate(tier_order):
        budget = per_tier + (1 if i < remainder else 0)
        pool = by_tier[tier]

        if not pool:
            continue

        # Within this tier, ensure ecosystem diversity
        tier_selected = _select_with_ecosystem_balance(pool, budget)
        selected.extend(tier_selected)

    # Mark selected instances
    selected_ids = {inst.instance_id for inst in selected}
    for inst in instances:
        inst.in_mini = inst.instance_id in selected_ids

    return selected


def _select_with_ecosystem_balance(
    pool: list[BenchmarkInstance],
    budget: int,
) -> list[BenchmarkInstance]:
    """Select from a pool with ecosystem diversity guarantees."""
    # Group by ecosystem
    by_eco: dict[str, list[BenchmarkInstance]] = {}
    for inst in pool:
        eco = inst.ecosystem or "unknown"
        by_eco.setdefault(eco, []).append(inst)

    selected: list[BenchmarkInstance] = []
    selected_ids: set[str] = set()

    # First pass: guarantee min 2 per ecosystem (if available)
    for eco in sorted(by_eco.keys()):
        for inst in by_eco[eco][:2]:
            if len(selected) < budget and inst.instance_id not in selected_ids:
                selected.append(inst)
                selected_ids.add(inst.instance_id)

    # Second pass: fill remaining budget by quality score
    if len(selected) < budget:
        remaining = [inst for inst in pool if inst.instance_id not in selected_ids]
        remaining.sort(key=lambda x: x.quality_score, reverse=True)
        for inst in remaining:
            if len(selected) >= budget:
                break
            selected.append(inst)
            selected_ids.add(inst.instance_id)

    return selected
