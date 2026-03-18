"""Data models for CVE vulnerability records and pipeline state."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class FixCommit(BaseModel):
    sha: str
    url: str
    message: Optional[str] = None


class CVERecord(BaseModel):
    """A single CVE vulnerability entry in the database."""

    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$")
    ghsa_id: Optional[str] = None
    title: str = ""
    description: str = ""
    severity: str = ""  # low, medium, high, critical
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    cwe_ids: list[str] = Field(default_factory=list)
    published_date: Optional[str] = None
    ecosystem: str = ""
    package_name: str = ""
    github_repo_url: Optional[str] = None
    vulnerable_version: Optional[str] = None
    vulnerable_version_range: Optional[str] = None
    patched_version: Optional[str] = None
    download_url: Optional[str] = None
    fix_commit: Optional[FixCommit] = None
    references: list[str] = Field(default_factory=list)
    source: str = "ghsa"


class CVEDatabase(BaseModel):
    """The full output database."""

    metadata: dict = Field(default_factory=dict)
    vulnerabilities: list[CVERecord] = Field(default_factory=list)


class PipelineState(BaseModel):
    """Checkpoint state for the pipeline."""

    stage: str = "collect"
    ecosystems_done: list[str] = Field(default_factory=list)
    collected_count: int = 0
    enriched_count: int = 0
    resolved_count: int = 0
    versioned_count: int = 0
    validated_count: int = 0
    failed_cves: list[str] = Field(default_factory=list)
    last_updated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
