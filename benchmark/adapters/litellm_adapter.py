"""LiteLLM-powered model adapter for VulnBench evaluation.

Supports 100+ LLM providers via a unified interface:
    - anthropic/claude-sonnet-4-20250514
    - openai/gpt-4o
    - ollama/llama3
    - And many more: https://docs.litellm.ai/docs/providers
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import litellm

logger = logging.getLogger(__name__)


@dataclass
class LiteLLMAdapter:
    """Model adapter using LiteLLM for unified LLM access.

    Args:
        model: LiteLLM model identifier (e.g. "anthropic/claude-sonnet-4-20250514").
        temperature: Sampling temperature. 0.0 for deterministic output.
        max_tokens: Maximum tokens in the response.
        num_retries: Number of retries on transient failures (429/5xx).
    """

    model: str
    temperature: float = 0.0
    max_tokens: int = 4096
    num_retries: int = 2
    _last_response_meta: dict = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        logger.info(
            "LiteLLMAdapter initialized: model=%s temperature=%s max_tokens=%d",
            self.model,
            self.temperature,
            self.max_tokens,
        )

    def generate_patch(self, prompt: str, system_prompt: str = "") -> str:
        """Generate a patch given a vulnerability description prompt.

        Args:
            prompt: The user-facing task prompt.
            system_prompt: Optional system message for role-setting context.

        Returns:
            The model's text response (diff parsing handled by the harness).
        """
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = litellm.completion(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            num_retries=self.num_retries,
        )

        # Extract response text
        text = response.choices[0].message.content or ""

        # Capture metadata for cost/token tracking
        self._last_response_meta = {
            "prompt_tokens": getattr(response.usage, "prompt_tokens", 0) or 0,
            "completion_tokens": getattr(response.usage, "completion_tokens", 0) or 0,
            "cost_usd": response._hidden_params.get("response_cost", 0.0) or 0.0,
            "model": response.model or self.model,
        }

        logger.info(
            "LiteLLM response: tokens=%d+%d cost=$%.4f",
            self._last_response_meta["prompt_tokens"],
            self._last_response_meta["completion_tokens"],
            self._last_response_meta["cost_usd"],
        )

        return text

    @property
    def last_response_meta(self) -> dict:
        """Metadata from the most recent generate_patch call."""
        return dict(self._last_response_meta)
