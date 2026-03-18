"""NVD public API client for CVSS score enrichment."""

import logging
from typing import Optional

import requests

from .rate_limiter import nvd_limiter

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cvss(cve_id: str) -> dict:
    """Fetch CVSS data from NVD for a single CVE.

    Returns:
        Dict with keys: cvss_score, cvss_vector, cwe_ids (may be empty).
    """
    nvd_limiter.acquire()

    try:
        resp = requests.get(
            NVD_API_URL,
            params={"cveId": cve_id},
            headers={"User-Agent": "CVE-VulnRepo/1.0"},
            timeout=30,
        )

        if resp.status_code == 403:
            logger.warning("NVD rate limited on %s, returning empty", cve_id)
            return {}

        if resp.status_code != 200:
            logger.warning("NVD returned %d for %s", resp.status_code, cve_id)
            return {}

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {}

        cve_data = vulns[0].get("cve", {})
        return _extract_cvss(cve_data)

    except requests.RequestException as e:
        logger.warning("NVD request failed for %s: %s", cve_id, e)
        return {}


def _extract_cvss(cve_data: dict) -> dict:
    """Extract CVSS score, vector, and CWEs from NVD CVE data."""
    result: dict = {}

    # Try CVSS v3.1 first, then v3.0
    metrics = cve_data.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30"):
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss = metric_list[0].get("cvssData", {})
            score = cvss.get("baseScore")
            vector = cvss.get("vectorString")
            if score:
                result["cvss_score"] = score
                result["cvss_vector"] = vector
                break

    # CWEs
    weaknesses = cve_data.get("weaknesses", [])
    cwe_ids = []
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-") and val != "CWE-noinfo":
                cwe_ids.append(val)
    if cwe_ids:
        result["cwe_ids"] = cwe_ids

    return result


def enrich_record(record, force: bool = False) -> bool:
    """Enrich a CVERecord with NVD CVSS data if missing.

    Args:
        record: CVERecord to enrich.
        force: If True, fetch even if score already exists.

    Returns:
        True if record was updated.
    """
    if not force and record.cvss_score and record.cvss_score > 0:
        return False

    data = fetch_cvss(record.cve_id)
    if not data:
        return False

    updated = False
    if "cvss_score" in data and (not record.cvss_score or record.cvss_score == 0):
        record.cvss_score = data["cvss_score"]
        record.cvss_vector = data.get("cvss_vector")
        updated = True

    if "cwe_ids" in data and not record.cwe_ids:
        record.cwe_ids = data["cwe_ids"]
        updated = True

    return updated
