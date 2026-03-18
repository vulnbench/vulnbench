"""Find vulnerable versions from GitHub tags and version ranges."""

import json
import logging
import re
import subprocess
from typing import Optional

from packaging.version import Version, InvalidVersion

from .rate_limiter import gh_limiter

logger = logging.getLogger(__name__)


def find_vulnerable_version(
    github_repo_url: str,
    vulnerable_range: Optional[str],
    patched_version: Optional[str],
    references: Optional[list[str]] = None,
    package_name: Optional[str] = None,
    ecosystem: Optional[str] = None,
) -> dict:
    """Find the last vulnerable version and construct download URL.

    Args:
        github_repo_url: e.g. 'https://github.com/lodash/lodash'
        vulnerable_range: e.g. '< 4.17.21' or '>= 1.0.0, < 2.3.4'
        patched_version: e.g. '4.17.21'
        references: List of reference URLs (may contain commit links).

    Returns:
        Dict with keys: vulnerable_version, download_url, fix_commit (any may be None).
    """
    result = {
        "vulnerable_version": None,
        "download_url": None,
        "fix_commit": None,
    }

    if not github_repo_url:
        return result

    owner_repo = _extract_owner_repo(github_repo_url)
    if not owner_repo:
        return result

    # Handle Go pseudo-versions (e.g., 0.0.0-20260219090056-6a672503973b)
    if ecosystem and ecosystem.lower() == "go":
        go_result = _handle_go_pseudo_version(
            owner_repo, vulnerable_range, patched_version, references
        )
        if go_result:
            return go_result

    # Extract fix commit from references first (works even if repo is 404)
    if references:
        result["fix_commit"] = _extract_commit_from_refs(references, owner_repo)

    # Determine vulnerable version from range/patched info
    vuln_version = _extract_vuln_version_from_range(vulnerable_range, patched_version)

    # Try to get tags from the repo
    tags = _fetch_tags(owner_repo, package_name=package_name)

    # Filter tags for monorepo packages
    if tags and package_name:
        tags = _filter_monorepo_tags(tags, package_name)

    if tags:
        # Find exact vulnerable version tag
        target = _determine_vulnerable_version(tags, vulnerable_range, patched_version)
        if target:
            tag_name = target["tag"]
            result["vulnerable_version"] = target["version"]
            result["download_url"] = (
                f"https://github.com/{owner_repo}/archive/refs/tags/{tag_name}.tar.gz"
            )

        # Fix commit from tag match
        if not result["fix_commit"]:
            fix = _find_fix_commit(owner_repo, patched_version, tags)
            if fix:
                result["fix_commit"] = fix

    # Fallback: try GitHub Releases API if tags didn't yield a version
    if not result["vulnerable_version"]:
        releases = _fetch_releases(owner_repo)
        if releases:
            target = _determine_vulnerable_version(
                releases, vulnerable_range, patched_version
            )
            if target:
                tag_name = target["tag"]
                result["vulnerable_version"] = target["version"]
                result["download_url"] = (
                    f"https://github.com/{owner_repo}/archive/refs/tags/{tag_name}.tar.gz"
                )

    # If tags/releases didn't yield a version, use the range-extracted version
    if not result["vulnerable_version"] and vuln_version:
        result["vulnerable_version"] = vuln_version
        # Try common tag prefixes to construct a download URL
        for prefix in ["v", "", "release-"]:
            tag_guess = f"{prefix}{vuln_version}"
            result["download_url"] = (
                f"https://github.com/{owner_repo}/archive/refs/tags/{tag_guess}.tar.gz"
            )
            break  # Use "v" prefix as most common

    return result


def _extract_owner_repo(url: str) -> Optional[str]:
    """Extract 'owner/repo' from a GitHub URL."""
    match = re.match(r"https?://github\.com/([^/]+/[^/]+)", url)
    if match:
        return match.group(1).removesuffix(".git")
    return None


def _extract_commit_from_refs(references: list[str], owner_repo: str) -> Optional[dict]:
    """Extract fix commit info from reference URLs."""
    for ref in references:
        match = re.match(
            r"https?://github\.com/[^/]+/[^/]+/commit/([a-f0-9]{7,40})",
            ref,
        )
        if match:
            sha = match.group(1)
            return {"sha": sha, "url": ref}
    return None


def _extract_vuln_version_from_range(
    vulnerable_range: Optional[str],
    patched_version: Optional[str],
) -> Optional[str]:
    """Extract a concrete vulnerable version string from range/patched info.

    Returns the highest known vulnerable version string.
    """
    if vulnerable_range:
        # Pattern: "= X.Y.Z" (exact vulnerable version)
        match = re.match(r"^=\s+(\d[\d.]*\S*)$", vulnerable_range.strip())
        if match:
            return match.group(1)

        # Pattern: "<= X.Y.Z" — X.Y.Z is the vulnerable version
        match = re.search(r"<=\s+(\d[\d.]*\S*)", vulnerable_range)
        if match:
            return match.group(1)

        # Pattern: ">= A.B.C, < X.Y.Z" or "> A.B.C, < X.Y.Z" — lower bound
        match = re.search(r">=?\s+(\d[\d.]*[^\s,]*)\s*,\s*<", vulnerable_range)
        if match:
            lower = match.group(1)
            if lower != "0" and lower != "0.0.0":
                return lower

        # Pattern: "< X.Y.Z" — decrement version as heuristic
        match = re.search(r"<\s+(\d[\d.]*\S*)", vulnerable_range)
        if match:
            upper = match.group(1)
            decremented = _decrement_version(upper)
            if decremented:
                return decremented

        # Pattern: ">= X.Y.Z" (no upper bound) — lower bound is vulnerable
        match = re.match(r"^>=?\s+(\d[\d.]*\S*)$", vulnerable_range.strip())
        if match:
            ver = match.group(1)
            if ver != "0" and ver != "0.0.0":
                return ver

    # Fallback: if patched_version exists, try decrementing it
    if patched_version:
        decremented = _decrement_version(patched_version)
        if decremented:
            return decremented

    return None


def _decrement_version(version_str: str) -> Optional[str]:
    """Decrement a version string intelligently.

    Strategy: try decrementing the last component. If it's 0, try decrementing
    the next-to-last component instead. Also handles pre-release suffixes.

    E.g., '4.17.21' -> '4.17.20'
          '3.74.0'  -> '3.73.0'  (minor decrement when patch is 0)
          '2.0.0'   -> '1.0.0'   (major decrement when minor and patch are 0)
          '1.0.0-rc.10' -> '1.0.0-rc.9' (pre-release decrement)
    """
    # Try pre-release suffix decrement first: 1.0.0-rc.10 -> 1.0.0-rc.9
    pre_match = re.match(r"^(\d[\d.]*\S*?)(\d+)$", version_str)
    if pre_match and "-" in version_str:
        prefix = pre_match.group(1)
        num = int(pre_match.group(2))
        if num > 0:
            return prefix + str(num - 1)

    # Parse the numeric portion
    match = re.match(r"^(\d+(?:\.\d+)*)(.*)$", version_str)
    if not match:
        return None
    numeric_part = match.group(1)
    suffix = match.group(2)
    parts = numeric_part.split(".")

    # Handle single-component versions like "427" -> "426"
    if len(parts) == 1:
        val = int(parts[0])
        if val > 0:
            return str(val - 1) + suffix
        return None

    # Try decrementing from the last component upward
    int_parts = []
    for p in parts:
        try:
            int_parts.append(int(p))
        except ValueError:
            return None

    # Find the rightmost non-zero component and decrement it
    for i in range(len(int_parts) - 1, -1, -1):
        if int_parts[i] > 0:
            int_parts[i] -= 1
            # Zero out everything to the right
            for j in range(i + 1, len(int_parts)):
                int_parts[j] = 0
            return ".".join(str(p) for p in int_parts) + suffix

    return None


def _fetch_tags(
    owner_repo: str,
    package_name: Optional[str] = None,
) -> list[dict]:
    """Fetch tags from a GitHub repo, return list of {name, version, sha} dicts."""
    gh_limiter.acquire()
    try:
        result = subprocess.run(
            ["gh", "api", f"/repos/{owner_repo}/tags",
             "-X", "GET", "-f", "per_page=100",
             "--paginate", "--cache", "1h"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            logger.debug("Failed to fetch tags for %s (may not exist)", owner_repo)
            return []

        text = result.stdout.strip()
        if not text:
            return []

        try:
            raw_tags = json.loads(text)
        except json.JSONDecodeError:
            text = text.replace("][", ",")
            try:
                raw_tags = json.loads(text)
            except json.JSONDecodeError:
                logger.debug("Could not parse tags JSON for %s", owner_repo)
                return []

        if not isinstance(raw_tags, list):
            return []

        tags = []
        for t in raw_tags:
            if not isinstance(t, dict):
                continue
            name = t.get("name", "")
            version = _extract_version(name, package_name=package_name)
            if version:
                tags.append({
                    "tag": name,
                    "version": version,
                    "sha": t.get("commit", {}).get("sha", ""),
                })
        return tags

    except Exception as e:
        logger.debug("Tag fetch error for %s: %s", owner_repo, e)
        return []


def _extract_version(tag_name: str, package_name: Optional[str] = None) -> Optional[str]:
    """Extract a clean version string from a tag name.

    Handles common patterns:
    - v1.2.3, V1.2.3
    - release-1.2.3, version-1.2.3
    - @scope/package@1.2.3, gradio@4.44.1
    - ray-2.54.0, jenkins-2.551, keycloak-26.2.0
    - struts2-parent-2.3.14.1 (multi-word package prefix)
    - STRUTS_7_1_1 (uppercase underscore-separated)
    """
    cleaned = tag_name.strip()

    # Strip ecosystem-prefixed tags like "@scope/package@1.2.3" or "gradio@4.44.1"
    if "@" in cleaned:
        parts = cleaned.split("@")
        cleaned = parts[-1]

    # Strip common prefixes: v, release-, version-, ver-, rel-
    cleaned = re.sub(r"^[vV]\.?", "", cleaned)
    cleaned = re.sub(r"^(release|version|ver|rel)[-_]?", "", cleaned, flags=re.IGNORECASE)

    # If a specific package_name is provided, strip it as prefix
    if package_name:
        # Escape the package name for regex and allow - or _ separator
        escaped = re.escape(package_name)
        cleaned = re.sub(rf"^{escaped}[-_]?", "", cleaned, flags=re.IGNORECASE)

    # Handle UPPERCASE_UNDERSCORE tags like STRUTS_7_1_1 -> 7.1.1
    upper_match = re.match(r"^[A-Z][A-Z0-9_]*?_(\d+(?:_\d+)*)$", cleaned)
    if upper_match:
        cleaned = upper_match.group(1).replace("_", ".")
    else:
        # Generic package-name prefix stripping: anything-before-digits
        # e.g., "ray-2.54.0" -> "2.54.0", "jenkins-2.551" -> "2.551"
        # e.g., "struts2-parent-2.3.14.1" -> "2.3.14.1"
        prefix_match = re.match(r"^[a-zA-Z][a-zA-Z0-9]*(?:[-_][a-zA-Z][a-zA-Z0-9]*)*[-_](\d+(?:\.\d+)*.*)$", cleaned)
        if prefix_match:
            cleaned = prefix_match.group(1)

    # Validate it looks like a version (digits with optional dots and suffixes)
    if re.match(r"\d+(\.\d+)*", cleaned):
        return cleaned
    return None


def _parse_version(v: str) -> Optional[Version]:
    """Try to parse a version string."""
    try:
        return Version(v)
    except InvalidVersion:
        # Try cleaning it up
        cleaned = re.sub(r"[^0-9.]", "", v)
        if not cleaned:
            return None
        try:
            return Version(cleaned)
        except InvalidVersion:
            return None


def _determine_vulnerable_version(
    tags: list[dict],
    vulnerable_range: Optional[str],
    patched_version: Optional[str],
) -> Optional[dict]:
    """Find the last vulnerable version tag.

    Strategy:
    1. If patched_version is known, find the highest tag BELOW it.
    2. If only vulnerable_range is given, find the highest tag matching it.
    3. If range uses <=, find exact match for the upper bound.
    """
    if not tags:
        return None

    # Parse all tag versions
    parsed_tags = []
    for t in tags:
        pv = _parse_version(t["version"])
        if pv:
            parsed_tags.append({**t, "parsed": pv})

    if not parsed_tags:
        return None

    # Sort by version descending
    parsed_tags.sort(key=lambda x: x["parsed"], reverse=True)

    # Strategy 1: Find highest tag below patched version
    if patched_version:
        patched_pv = _parse_version(patched_version)
        if patched_pv:
            for t in parsed_tags:
                if t["parsed"] < patched_pv:
                    return t

    # Strategy 2: Handle "<= X.Y.Z" — find exact match
    if vulnerable_range:
        le_match = re.search(r"<=\s+(\d[\d.]*\S*)", vulnerable_range)
        if le_match:
            bound_ver = le_match.group(1)
            bound_pv = _parse_version(bound_ver)
            if bound_pv:
                for t in parsed_tags:
                    if t["parsed"] == bound_pv:
                        return t
                # If exact match not found, find highest below
                for t in parsed_tags:
                    if t["parsed"] <= bound_pv:
                        return t

    # Strategy 3: Handle "< X.Y.Z"
    if vulnerable_range:
        lt_match = re.search(r"<\s+(\d[\d.]*\S*)", vulnerable_range)
        if lt_match:
            bound_ver = lt_match.group(1)
            bound_pv = _parse_version(bound_ver)
            if bound_pv:
                for t in parsed_tags:
                    if t["parsed"] < bound_pv:
                        return t

    # Fallback: if patched version given but couldn't parse, use second tag
    if patched_version and parsed_tags:
        if len(parsed_tags) > 1:
            return parsed_tags[1]
        return parsed_tags[0]

    return None


def _fetch_releases(owner_repo: str) -> list[dict]:
    """Fetch releases from GitHub Releases API as fallback.

    Releases often have cleaner version names than tags
    (e.g., jenkins release name=2.551 vs tag=jenkins-2.551).
    """
    gh_limiter.acquire()
    try:
        result = subprocess.run(
            ["gh", "api", f"/repos/{owner_repo}/releases",
             "-X", "GET", "-f", "per_page=100",
             "--paginate", "--cache", "1h"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            return []

        text = result.stdout.strip()
        if not text:
            return []

        try:
            raw_releases = json.loads(text)
        except json.JSONDecodeError:
            text = text.replace("][", ",")
            try:
                raw_releases = json.loads(text)
            except json.JSONDecodeError:
                return []

        if not isinstance(raw_releases, list):
            return []

        releases = []
        for r in raw_releases:
            if not isinstance(r, dict):
                continue
            # Try release name first (often cleaner), then tag_name
            tag_name = r.get("tag_name", "")
            name = r.get("name", "") or tag_name
            version = _extract_version(name) or _extract_version(tag_name)
            if version and tag_name:
                releases.append({
                    "tag": tag_name,
                    "version": version,
                    "sha": "",
                })
        return releases

    except Exception as e:
        logger.debug("Release fetch error for %s: %s", owner_repo, e)
        return []


def _handle_go_pseudo_version(
    owner_repo: str,
    vulnerable_range: Optional[str],
    patched_version: Optional[str],
    references: Optional[list[str]],
) -> Optional[dict]:
    """Handle Go pseudo-versions like 0.0.0-20260219090056-6a672503973b.

    Go pseudo-versions encode a commit SHA in the last segment.
    Extract it and construct a commit-based download URL.
    """
    result = {
        "vulnerable_version": None,
        "download_url": None,
        "fix_commit": None,
    }

    # Extract fix commit from references first
    if references:
        result["fix_commit"] = _extract_commit_from_refs(references, owner_repo)

    # Check if the patched or vulnerable version is a Go pseudo-version
    pseudo_re = re.compile(
        r"v?0\.0\.0-\d{14}-([a-f0-9]{12})"
    )

    versions_to_check = []
    if patched_version:
        versions_to_check.append(patched_version)
    if vulnerable_range:
        # Extract version strings from the range
        for v in re.findall(r"[\d]+\.[\d]+\.[\d]+(?:-[\w.]+)*", vulnerable_range):
            versions_to_check.append(v)

    for v in versions_to_check:
        m = pseudo_re.match(v)
        if m:
            sha = m.group(1)
            result["vulnerable_version"] = v
            result["download_url"] = (
                f"https://github.com/{owner_repo}/archive/{sha}.tar.gz"
            )
            if not result["fix_commit"]:
                result["fix_commit"] = {
                    "sha": sha,
                    "url": f"https://github.com/{owner_repo}/commit/{sha}",
                }
            return result

    return None


def _filter_monorepo_tags(tags: list[dict], package_name: str) -> list[dict]:
    """Filter tags for monorepo packages.

    In monorepos, tags are often prefixed with the package name:
    - gradio@4.44.1 vs website@0.61.2
    - packages/foo/v1.2.3
    - foo-v1.2.3

    Returns tags that match the package, plus unscoped tags.
    """
    pkg_lower = package_name.lower()

    # Build patterns that indicate a tag belongs to this package
    scoped_tags = []
    unscoped_tags = []

    for t in tags:
        tag = t["tag"].lower()
        # Check if this tag is explicitly scoped to our package
        if (
            tag.startswith(f"{pkg_lower}@")
            or tag.startswith(f"{pkg_lower}-v")
            or tag.startswith(f"{pkg_lower}-")
            or tag.startswith(f"{pkg_lower}/")
        ):
            scoped_tags.append(t)
        # Check if tag has no package scope (plain version tags)
        elif re.match(r"^v?\d", tag):
            unscoped_tags.append(t)

    # If we found package-scoped tags, prefer those
    if scoped_tags:
        return scoped_tags

    # Otherwise fall back to unscoped tags (could be single-package repo)
    return unscoped_tags if unscoped_tags else tags


def _find_fix_commit(
    owner_repo: str,
    patched_version: Optional[str],
    tags: list[dict],
) -> Optional[dict]:
    """Try to find the fix commit from tags."""
    if not patched_version:
        return None

    for t in tags:
        if t["version"] == patched_version or t["tag"] == f"v{patched_version}":
            sha = t.get("sha", "")
            if sha:
                return {
                    "sha": sha,
                    "url": f"https://github.com/{owner_repo}/commit/{sha}",
                }
    return None
