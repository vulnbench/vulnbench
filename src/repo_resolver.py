"""Resolve package names to GitHub repository URLs via package registries."""

import json
import logging
import re
import subprocess
from typing import Optional

import requests

from .rate_limiter import gh_limiter, registry_limiter

logger = logging.getLogger(__name__)


def resolve_repo(package_name: str, ecosystem: str, references: list[str],
                 existing_url: Optional[str] = None) -> Optional[str]:
    """Resolve a package to its GitHub repo URL.

    Tries in order:
    1. Use existing source_code_location from GHSA if valid
    2. Extract from reference URLs
    3. Look up in package registry
    4. Search GitHub

    Returns:
        GitHub repo URL like 'https://github.com/owner/repo', or None.
    """
    # 1. Validate existing URL
    if existing_url and _is_github_repo_url(existing_url):
        return _normalize_github_url(existing_url)

    # 2. Extract from references
    for ref in references:
        if _is_github_repo_url(ref):
            url = _normalize_github_url(ref)
            if url:
                return url

    # 3. Registry lookup
    url = _lookup_registry(package_name, ecosystem)
    if url:
        return url

    # 4. GitHub search fallback
    url = _search_github(package_name, ecosystem)
    if url:
        return url

    return None


def _is_github_repo_url(url: str) -> bool:
    """Check if a URL points to a GitHub repository."""
    return bool(re.match(r"https?://github\.com/[^/]+/[^/]+", url or ""))


def _normalize_github_url(url: str) -> Optional[str]:
    """Normalize a GitHub URL to https://github.com/owner/repo."""
    match = re.match(r"https?://github\.com/([^/]+)/([^/]+)", url)
    if not match:
        return None
    owner, repo = match.group(1), match.group(2)
    # Strip .git suffix
    repo = repo.removesuffix(".git")
    # Strip trailing path components (commits, issues, etc.)
    return f"https://github.com/{owner}/{repo}"


def _lookup_registry(package_name: str, ecosystem: str) -> Optional[str]:
    """Look up package in its ecosystem registry to find GitHub URL."""
    registry_limiter.acquire()

    try:
        if ecosystem == "npm":
            return _lookup_npm(package_name)
        elif ecosystem == "pip":
            return _lookup_pypi(package_name)
        elif ecosystem == "go":
            return _lookup_go(package_name)
        elif ecosystem == "rubygems":
            return _lookup_rubygems(package_name)
        elif ecosystem == "rust":
            return _lookup_crates(package_name)
        elif ecosystem == "composer":
            return _lookup_packagist(package_name)
        elif ecosystem == "maven":
            return _lookup_maven(package_name)
        elif ecosystem == "nuget":
            return _lookup_nuget(package_name)
    except Exception as e:
        logger.debug("Registry lookup failed for %s/%s: %s", ecosystem, package_name, e)

    return None


def _lookup_npm(name: str) -> Optional[str]:
    resp = requests.get(f"https://registry.npmjs.org/{name}", timeout=15)
    if resp.status_code != 200:
        return None
    data = resp.json()
    repo = data.get("repository", {})
    if isinstance(repo, dict):
        url = repo.get("url", "")
    elif isinstance(repo, str):
        url = repo
    else:
        return None
    return _normalize_github_url(url)


def _lookup_pypi(name: str) -> Optional[str]:
    resp = requests.get(f"https://pypi.org/pypi/{name}/json", timeout=15)
    if resp.status_code != 200:
        return None
    info = resp.json().get("info", {})
    # Check project_urls first
    project_urls = info.get("project_urls") or {}
    for key in ("Source", "Source Code", "Repository", "Homepage", "Code", "GitHub"):
        url = project_urls.get(key, "")
        if _is_github_repo_url(url):
            return _normalize_github_url(url)
    # Fall back to home_page
    hp = info.get("home_page", "")
    if _is_github_repo_url(hp):
        return _normalize_github_url(hp)
    return None


def _lookup_go(name: str) -> Optional[str]:
    # Go modules starting with github.com/ are direct repos
    if name.startswith("github.com/"):
        parts = name.split("/")
        if len(parts) >= 3:
            return f"https://github.com/{parts[1]}/{parts[2]}"
    # Try pkg.go.dev
    resp = requests.get(f"https://pkg.go.dev/{name}?tab=overview", timeout=15,
                       headers={"Accept": "text/html"})
    if resp.status_code == 200:
        match = re.search(r'href="(https://github\.com/[^/]+/[^/"]+)"', resp.text)
        if match:
            return _normalize_github_url(match.group(1))
    return None


def _lookup_rubygems(name: str) -> Optional[str]:
    resp = requests.get(f"https://rubygems.org/api/v1/gems/{name}.json", timeout=15)
    if resp.status_code != 200:
        return None
    data = resp.json()
    for key in ("source_code_uri", "homepage_uri"):
        url = data.get(key, "")
        if _is_github_repo_url(url):
            return _normalize_github_url(url)
    return None


def _lookup_crates(name: str) -> Optional[str]:
    resp = requests.get(f"https://crates.io/api/v1/crates/{name}",
                       timeout=15, headers={"User-Agent": "CVE-VulnRepo/1.0"})
    if resp.status_code != 200:
        return None
    crate = resp.json().get("crate", {})
    url = crate.get("repository", "")
    if _is_github_repo_url(url):
        return _normalize_github_url(url)
    return None


def _lookup_packagist(name: str) -> Optional[str]:
    resp = requests.get(f"https://repo.packagist.org/p2/{name}.json", timeout=15)
    if resp.status_code != 200:
        return None
    data = resp.json()
    packages = data.get("packages", {}).get(name, [])
    if packages:
        source = packages[0].get("source", {})
        url = source.get("url", "")
        if _is_github_repo_url(url):
            return _normalize_github_url(url)
    return None


def _lookup_maven(name: str) -> Optional[str]:
    # Maven package name format: group:artifact or group/artifact
    parts = re.split(r"[:/]", name)
    if len(parts) < 2:
        return None
    group, artifact = parts[0], parts[1]
    group_path = group.replace(".", "/")
    # Try Maven Central search API
    resp = requests.get(
        "https://search.maven.org/solrsearch/select",
        params={"q": f"g:{group} AND a:{artifact}", "rows": 1, "wt": "json"},
        timeout=15,
    )
    if resp.status_code != 200:
        return None
    docs = resp.json().get("response", {}).get("docs", [])
    if not docs:
        return None
    # Maven Central doesn't directly have repo URLs; check SCM via POM
    # For now, try common patterns
    scm_url = None
    for pattern in [
        f"https://github.com/{group}/{artifact}",
        f"https://github.com/{group.split('.')[-1]}/{artifact}",
    ]:
        try:
            r = requests.head(pattern, timeout=10, allow_redirects=True)
            if r.status_code == 200:
                scm_url = pattern
                break
        except requests.RequestException:
            continue
    return scm_url


def _lookup_nuget(name: str) -> Optional[str]:
    resp = requests.get(
        f"https://api.nuget.org/v3/registration5-gz-semver2/{name.lower()}/index.json",
        timeout=15,
    )
    if resp.status_code != 200:
        return None
    data = resp.json()
    items = data.get("items", [])
    if not items:
        return None
    # Get the latest catalog entry
    pages = items[-1].get("items", [])
    if pages:
        entry = pages[-1].get("catalogEntry", {})
        url = entry.get("projectUrl", "")
        if _is_github_repo_url(url):
            return _normalize_github_url(url)
    return None


def _search_github(package_name: str, ecosystem: str) -> Optional[str]:
    """Search GitHub for the package repository as a last resort."""
    gh_limiter.acquire()
    query = f"{package_name} {ecosystem}"
    try:
        result = subprocess.run(
            ["gh", "api", "/search/repositories", "-f", f"q={query}", "-f", "per_page=3"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return None
        data = json.loads(result.stdout)
        items = data.get("items", [])
        if items:
            # Return the top result
            return items[0].get("html_url")
    except Exception as e:
        logger.debug("GitHub search failed for %s: %s", package_name, e)
    return None
