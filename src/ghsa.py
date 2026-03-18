"""Fetch security advisories from the GitHub Advisory Database via gh CLI."""

import json
import logging
import subprocess
from typing import Optional

from .models import CVERecord
from .rate_limiter import gh_limiter

logger = logging.getLogger(__name__)

ECOSYSTEMS = [
    "npm", "pip", "maven", "go", "rust", "nuget",
    "rubygems", "composer", "erlang", "pub", "swift", "actions",
]


def _gh_api(endpoint: str, params: Optional[dict] = None, paginate: bool = False) -> list[dict]:
    """Call gh api and return parsed JSON."""
    cmd = ["gh", "api", endpoint, "-X", "GET", "--cache", "1h"]
    if paginate:
        cmd.append("--paginate")
    if params:
        for key, value in params.items():
            cmd.extend(["-f", f"{key}={value}"])

    gh_limiter.acquire()
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        logger.error("gh api error: %s", result.stderr[:500])
        return []

    text = result.stdout.strip()
    if not text:
        return []

    # --paginate may return concatenated JSON arrays, fix by wrapping
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Paginated output can be multiple JSON arrays concatenated
        # e.g. [{...}][{...}] — fix by joining
        text = text.replace("][", ",")
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            logger.error("Failed to parse gh api response")
            return []

    if isinstance(data, list):
        return data
    return [data]


def _parse_advisory(adv: dict) -> Optional[CVERecord]:
    """Convert a GHSA advisory dict to a CVERecord."""
    cve_id = adv.get("cve_id")
    if not cve_id:
        return None

    ghsa_id = adv.get("ghsa_id", "")
    title = adv.get("summary", "")
    description = adv.get("description", "")
    severity = adv.get("severity", "").lower()
    published = adv.get("published_at", "")
    source_code_url = adv.get("source_code_location")

    # CVSS score — prefer v3, fall back to v4
    cvss_score = None
    cvss_vector = None
    cvss_data = adv.get("cvss_severities", {})
    v3 = cvss_data.get("cvss_v3", {})
    v4 = cvss_data.get("cvss_v4", {})
    if v3 and v3.get("score") and v3["score"] > 0:
        cvss_score = v3["score"]
        cvss_vector = v3.get("vector_string")
    elif v4 and v4.get("score") and v4["score"] > 0:
        cvss_score = v4["score"]
        cvss_vector = v4.get("vector_string")

    # CWEs
    cwe_ids = [c["cwe_id"] for c in adv.get("cwes", []) if "cwe_id" in c]

    # References
    references = adv.get("references", [])

    # Vulnerability details (take first affected package)
    ecosystem = ""
    package_name = ""
    vuln_range = None
    patched = None
    vulns = adv.get("vulnerabilities", [])
    if vulns:
        v = vulns[0]
        pkg = v.get("package", {})
        ecosystem = pkg.get("ecosystem", "")
        package_name = pkg.get("name", "")
        vuln_range = v.get("vulnerable_version_range")
        patched = v.get("first_patched_version")

    return CVERecord(
        cve_id=cve_id,
        ghsa_id=ghsa_id,
        title=title,
        description=description,
        severity=severity,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        cwe_ids=cwe_ids,
        published_date=published,
        ecosystem=ecosystem,
        package_name=package_name,
        github_repo_url=source_code_url,
        vulnerable_version_range=vuln_range,
        patched_version=patched,
        references=references,
        source="ghsa",
    )


def fetch_advisories(
    ecosystems: Optional[list[str]] = None,
    date_start: str = "2022-01-01",
    date_end: str = "2026-12-31",
    severities: Optional[list[str]] = None,
    limit: int = 0,
    skip_ecosystems: Optional[list[str]] = None,
) -> list[CVERecord]:
    """Fetch GHSA advisories for the given ecosystems and date range.

    Args:
        ecosystems: List of ecosystems to query. Defaults to all.
        date_start: Start date (inclusive) in YYYY-MM-DD format.
        date_end: End date (inclusive) in YYYY-MM-DD format.
        severities: Severity levels to include. Defaults to medium,high,critical.
        limit: Max total records to return (0 = unlimited).
        skip_ecosystems: Ecosystems already completed (for resume).

    Returns:
        List of CVERecord objects.
    """
    if ecosystems is None:
        ecosystems = ECOSYSTEMS
    if severities is None:
        severities = ["medium", "high", "critical"]
    if skip_ecosystems is None:
        skip_ecosystems = []

    records: list[CVERecord] = []
    seen_cves: set[str] = set()

    for eco in ecosystems:
        if eco in skip_ecosystems:
            logger.info("Skipping ecosystem %s (already done)", eco)
            continue

        logger.info("Fetching advisories for ecosystem: %s", eco)

        for sev in severities:
            params = {
                "type": "reviewed",
                "ecosystem": eco,
                "severity": sev,
                "published": f"{date_start}..{date_end}",
                "per_page": "100",
            }

            advisories = _gh_api("/advisories", params=params, paginate=True)
            logger.info("  %s/%s: got %d advisories", eco, sev, len(advisories))

            for adv in advisories:
                record = _parse_advisory(adv)
                if record and record.cve_id not in seen_cves:
                    seen_cves.add(record.cve_id)
                    records.append(record)

                    if limit > 0 and len(records) >= limit:
                        logger.info("Reached limit of %d records", limit)
                        return records

    logger.info("Total advisories collected: %d", len(records))
    return records
