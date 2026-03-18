"""Data models for VulnBench benchmark instances and metadata."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class DifficultyTier(str, Enum):
    """Difficulty classification based on CWE vulnerability type."""

    TIER_1 = "tier_1"  # Pattern-matching fixes (XSS, SQLi, path traversal)
    TIER_2 = "tier_2"  # Logic fixes (auth, CSRF, info disclosure)
    TIER_3 = "tier_3"  # Deep reasoning (code injection, resource exhaustion, input validation)


class FileChange(BaseModel):
    """A single file changed in a fix commit."""

    path: str
    lines_added: int = 0
    lines_removed: int = 0
    change_type: str = "modified"  # added, removed, modified, renamed


class GoldPatch(BaseModel):
    """The ground-truth fix extracted from a commit."""

    commit_sha: str
    raw_diff: str
    files_changed: list[FileChange] = Field(default_factory=list)
    total_additions: int = 0
    total_deletions: int = 0


class TaskPrompt(BaseModel):
    """The prompt given to models (contains NO gold patch information)."""

    system_context: str = ""
    vulnerability_description: str = ""
    cwe_category: str = ""
    cwe_guidance: str = ""
    affected_files_hint: list[str] = Field(default_factory=list)
    source_context: str = ""
    source_context_files: list[str] = Field(default_factory=list)
    instructions: str = ""


class BenchmarkInstance(BaseModel):
    """A single benchmark task instance."""

    instance_id: str  # Format: vulnbench-{cve_id}
    cve_id: str
    ecosystem: str = ""
    package_name: str = ""
    severity: str = ""
    cvss_score: Optional[float] = None
    cwe_ids: list[str] = Field(default_factory=list)
    primary_cwe: str = ""
    difficulty_tier: DifficultyTier = DifficultyTier.TIER_2
    gold_patch: GoldPatch
    task_prompt: TaskPrompt
    vulnerable_version: str = ""
    download_url: str = ""
    github_repo_url: str = ""
    quality_score: float = 0.0
    in_mini: bool = False


class BenchmarkDatabase(BaseModel):
    """The full benchmark output."""

    metadata: dict = Field(default_factory=dict)
    instances: list[BenchmarkInstance] = Field(default_factory=list)
