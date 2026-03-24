"""Build skills-augmented prompt sections from criteria YAML files.

Maps CWE IDs to vulnerability categories and injects structured
analysis methodology into the evaluation prompt.
"""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

import yaml

from src.benchmark_models import BenchmarkInstance

CRITERIA_DIR = Path(__file__).parent / "criteria"

# ---------------------------------------------------------------------------
# CWE → category mapping
# ---------------------------------------------------------------------------

CWE_TO_CATEGORY: dict[str, str] = {
    # Injection
    "CWE-79": "injection",
    "CWE-89": "injection",
    "CWE-94": "injection",
    "CWE-77": "injection",
    "CWE-78": "injection",
    "CWE-74": "injection",
    "CWE-1336": "injection",
    # Traversal / file access
    "CWE-22": "traversal",
    "CWE-23": "traversal",
    "CWE-73": "traversal",
    "CWE-36": "traversal",
    "CWE-59": "traversal",
    # Auth / access control
    "CWE-287": "auth_access",
    "CWE-862": "auth_access",
    "CWE-863": "auth_access",
    "CWE-285": "auth_access",
    "CWE-352": "auth_access",
    "CWE-384": "auth_access",
    "CWE-639": "auth_access",
    "CWE-306": "auth_access",
    # Resource exhaustion
    "CWE-400": "resource",
    "CWE-770": "resource",
    "CWE-674": "resource",
    "CWE-835": "resource",
    "CWE-1333": "resource",
    "CWE-405": "resource",
    "CWE-776": "resource",
    # Input validation / data handling
    "CWE-20": "input_validation",
    "CWE-1321": "input_validation",
    "CWE-502": "input_validation",
    "CWE-125": "input_validation",
    "CWE-476": "input_validation",
    "CWE-129": "input_validation",
    "CWE-190": "input_validation",
    # Information exposure / SSRF / redirects
    "CWE-200": "info_exposure",
    "CWE-532": "info_exposure",
    "CWE-601": "info_exposure",
    "CWE-918": "info_exposure",
    "CWE-209": "info_exposure",
    "CWE-538": "info_exposure",
}


@functools.lru_cache(maxsize=32)
def load_criteria(category: str, criteria_dir: str | None = None) -> dict[str, Any]:
    """Load and cache a criteria YAML file by category name."""
    base = Path(criteria_dir) if criteria_dir else CRITERIA_DIR
    path = base / f"{category}.yaml"
    if not path.exists():
        path = base / "general.yaml"
    return yaml.safe_load(path.read_text())


def resolve_criteria(
    instance: BenchmarkInstance,
    criteria_dir: str | None = None,
) -> dict[str, Any]:
    """Resolve the best-matching criteria for a benchmark instance."""
    for cwe in instance.cwe_ids:
        cat = CWE_TO_CATEGORY.get(cwe)
        if cat:
            return load_criteria(cat, criteria_dir)
    if instance.primary_cwe:
        cat = CWE_TO_CATEGORY.get(instance.primary_cwe)
        if cat:
            return load_criteria(cat, criteria_dir)
    return load_criteria("general", criteria_dir)


def build_skills_prompt_section(
    instance: BenchmarkInstance,
    criteria_dir: str | None = None,
) -> str:
    """Build a structured analysis framework section for the prompt.

    Returns a markdown-formatted text block to inject between the
    vulnerability description and the patch-generation instructions.
    """
    criteria = resolve_criteria(instance, criteria_dir)
    methodology = criteria.get("analysis_methodology", {})

    parts: list[str] = []
    parts.append("## Security Analysis Framework")
    parts.append(
        "Before generating your patch, work through this structured "
        "vulnerability analysis:"
    )

    if methodology.get("plan"):
        parts.append("\n### Step 1: Plan Your Approach")
        parts.append(methodology["plan"].strip())

    if methodology.get("analyze"):
        parts.append("\n### Step 2: Analyze the Vulnerability")
        parts.append(methodology["analyze"].strip())

    if methodology.get("verify"):
        parts.append("\n### Step 3: Verify Your Fix")
        parts.append(methodology["verify"].strip())

    # CWE-specific fix guidance
    fix_patterns = criteria.get("fix_patterns", {})
    primary_cwe = instance.primary_cwe or (instance.cwe_ids[0] if instance.cwe_ids else None)
    cwe_guidance = fix_patterns.get(primary_cwe, {}) if primary_cwe else {}

    if cwe_guidance:
        cwe_name = cwe_guidance.get("name", primary_cwe)
        parts.append(f"\n### Fix Guidance: {cwe_name} ({primary_cwe})")

        common = cwe_guidance.get("common_fixes", [])
        if common:
            parts.append("\nCommon correct approaches:")
            for fix in common:
                parts.append(f"  - {fix}")

        anti = cwe_guidance.get("anti_patterns", [])
        if anti:
            parts.append("\nKnown anti-patterns to AVOID:")
            for ap in anti:
                parts.append(f"  - {ap}")

    return "\n".join(parts)
