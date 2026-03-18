"""Data models for VulnBench evaluation results."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class PatchAnalysis(BaseModel):
    """Analysis of a model-generated patch by the LLM judge."""

    judge_score: float = 0.0  # 0.0-1.0 from judge
    judge_reasoning: str = ""  # Judge's explanation
    judge_verdict: str = ""  # "pass" or "fail"


class InstanceResult(BaseModel):
    """Evaluation result for a single benchmark instance."""

    instance_id: str
    cve_id: str
    difficulty_tier: str = ""
    ecosystem: str = ""
    model_patch: str = ""
    generation_time_s: float = 0.0
    patch_analysis: PatchAnalysis = Field(default_factory=PatchAnalysis)
    score: float = 0.0  # 0.0-1.0
    passed: bool = False  # score >= 0.5
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    judge_cost_usd: float = 0.0


class AggregateMetrics(BaseModel):
    """Aggregate metrics across all evaluated instances."""

    total_instances: int = 0
    total_passed: int = 0
    pass_rate: float = 0.0
    mean_score: float = 0.0
    pass_rate_by_tier: dict[str, float] = Field(default_factory=dict)
    pass_rate_by_ecosystem: dict[str, float] = Field(default_factory=dict)
    mean_generation_time_s: float = 0.0
    total_cost_usd: float = 0.0
    total_judge_cost_usd: float = 0.0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0


class EvalReport(BaseModel):
    """Complete evaluation report."""

    metadata: dict = Field(default_factory=dict)
    aggregate: AggregateMetrics = Field(default_factory=AggregateMetrics)
    results: list[InstanceResult] = Field(default_factory=list)
