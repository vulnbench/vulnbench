"""LiteLLM-powered model adapter for VulnBench evaluation.

Supports 100+ LLM providers via a unified interface:
    - anthropic/claude-sonnet-4-20250514
    - openai/gpt-4o
    - ollama/llama3
    - And many more: https://docs.litellm.ai/docs/providers
"""

from __future__ import annotations

import logging
import multiprocessing
import queue
import random
import re
import signal
import threading
import time
from dataclasses import dataclass, field
import traceback

import litellm

logger = logging.getLogger(__name__)


# Per-model configuration is intentionally not supported: every model must run
# under the identical policy or leaderboard rows stop being comparable. Models
# whose hidden reasoning exhausts the completion budget are handled by the
# uniform escalation in generate_patch (larger budget, then reasoning excluded).
DEFAULT_REASONING_MAX_TOKENS_BY_MODEL: dict[str, int] = {}

DEFAULT_REASONING_DISABLED_BY_MODEL: set[str] = set()

_PATCH_LIKE_PATTERNS = (
    re.compile(r"diff --git\s+a/"),
    re.compile(r"```(?:diff|patch)\b", re.I),
    re.compile(r"(?m)^---\s+\S+.*\n\+\+\+\s+\S+"),
)


@dataclass
class _CompletionTokenDetails:
    reasoning_tokens: int = 0


@dataclass
class _CompletionUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    completion_tokens_details: _CompletionTokenDetails = field(
        default_factory=_CompletionTokenDetails
    )


@dataclass
class _CompletionMessage:
    content: str = ""
    reasoning_content: str = ""


@dataclass
class _CompletionChoice:
    finish_reason: str = ""
    message: _CompletionMessage = field(default_factory=_CompletionMessage)


@dataclass
class _CompletionResponse:
    choices: list[_CompletionChoice]
    usage: _CompletionUsage = field(default_factory=_CompletionUsage)
    _hidden_params: dict = field(default_factory=dict)
    model: str = ""


def _serialize_completion_response(response: object) -> _CompletionResponse:
    usage = getattr(response, "usage", None)
    completion_details = getattr(usage, "completion_tokens_details", None)
    hidden_params = getattr(response, "_hidden_params", {}) or {}
    choices = []
    for choice in getattr(response, "choices", []) or []:
        message = getattr(choice, "message", None)
        choices.append(
            _CompletionChoice(
                finish_reason=getattr(choice, "finish_reason", "") or "",
                message=_CompletionMessage(
                    content=getattr(message, "content", "") or "",
                    reasoning_content=getattr(message, "reasoning_content", "") or "",
                ),
            )
        )

    return _CompletionResponse(
        choices=choices,
        usage=_CompletionUsage(
            prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
            completion_tokens_details=_CompletionTokenDetails(
                reasoning_tokens=getattr(
                    completion_details, "reasoning_tokens", 0
                )
                or 0,
            ),
        ),
        _hidden_params={"response_cost": hidden_params.get("response_cost", 0.0) or 0.0},
        model=getattr(response, "model", "") or "",
    )


def _litellm_completion_worker(kwargs: dict, result_queue: object) -> None:
    try:
        response = litellm.completion(**kwargs)
        result_queue.put(("ok", _serialize_completion_response(response)))
    except BaseException as exc:
        result_queue.put(
            (
                "error",
                type(exc).__name__,
                str(exc),
                traceback.format_exc(),
            )
        )


def _multiprocessing_context() -> multiprocessing.context.BaseContext:
    if "spawn" in multiprocessing.get_all_start_methods():
        return multiprocessing.get_context("spawn")
    return multiprocessing.get_context()


def default_reasoning_max_tokens_for_model(model: str) -> int | None:
    return DEFAULT_REASONING_MAX_TOKENS_BY_MODEL.get(model)


def default_reasoning_disabled_for_model(model: str) -> bool:
    return model in DEFAULT_REASONING_DISABLED_BY_MODEL


def _looks_like_patch(text: str) -> bool:
    return any(pattern.search(text) for pattern in _PATCH_LIKE_PATTERNS)


@dataclass
class LiteLLMAdapter:
    """Model adapter using LiteLLM for unified LLM access.

    Args:
        model: LiteLLM model identifier (e.g. "anthropic/claude-sonnet-4-20250514").
        temperature: Sampling temperature. 0.0 for deterministic output.
        max_tokens: Maximum tokens in the response.
        num_retries: Number of retries on transient failures (429/5xx).
        timeout: Per-request timeout in seconds.
        max_attempts: Number of full completion attempts for adapter-level retries.
        retry_backoff_base_s: Initial exponential backoff delay in seconds.
        retry_backoff_max_s: Maximum exponential backoff delay in seconds.
        retry_backoff_jitter_s: Random jitter added to each retry sleep.
        retry_empty_responses: Retry responses whose content is empty or whitespace.
        reasoning_effort: Optional provider reasoning effort parameter.
        reasoning_max_tokens: Optional OpenRouter reasoning token budget.
        reasoning_exclude: Ask OpenRouter to exclude reasoning tokens from responses.
        process_timeout: Run each LiteLLM completion in a child process and
            enforce timeout from the parent process.
    """

    model: str
    temperature: float = 0.0
    max_tokens: int = 16384
    escalated_max_tokens: int = 32768
    num_retries: int = 2
    timeout: float = 300.0
    max_attempts: int = 3
    retry_backoff_base_s: float = 2.0
    retry_backoff_max_s: float = 60.0
    retry_backoff_jitter_s: float = 0.5
    retry_empty_responses: bool = True
    reasoning_effort: str | None = None
    reasoning_max_tokens: int | None = None
    reasoning_exclude: bool = False
    reasoning_enabled: bool | None = None
    process_timeout: bool = False
    _last_response_meta: dict = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if self.retry_backoff_base_s < 0:
            raise ValueError("retry_backoff_base_s must be >= 0")
        if self.retry_backoff_max_s < 0:
            raise ValueError("retry_backoff_max_s must be >= 0")
        if self.retry_backoff_jitter_s < 0:
            raise ValueError("retry_backoff_jitter_s must be >= 0")
        if self.reasoning_max_tokens is not None and self.reasoning_max_tokens < 0:
            raise ValueError("reasoning_max_tokens must be >= 0")
        if self.reasoning_effort and self.reasoning_max_tokens is not None:
            raise ValueError(
                "reasoning_effort and reasoning_max_tokens cannot both be set"
            )
        if self.reasoning_effort is None and self.reasoning_max_tokens is None:
            self.reasoning_max_tokens = default_reasoning_max_tokens_for_model(
                self.model
            )
        if (
            self.reasoning_enabled is None
            and self.reasoning_effort is None
            and self.reasoning_max_tokens is None
            and default_reasoning_disabled_for_model(self.model)
        ):
            self.reasoning_enabled = False
            self.reasoning_exclude = True

        logger.info(
            (
                "LiteLLMAdapter initialized: model=%s temperature=%s "
                "max_tokens=%d max_attempts=%d reasoning_effort=%s "
                "reasoning_max_tokens=%s reasoning_exclude=%s "
                "reasoning_enabled=%s process_timeout=%s"
            ),
            self.model,
            self.temperature,
            self.max_tokens,
            self.max_attempts,
            self.reasoning_effort,
            self.reasoning_max_tokens,
            self.reasoning_exclude,
            self.reasoning_enabled,
            self.process_timeout,
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

        self._last_response_meta = {}
        attempt_metas: list[dict] = []
        empty_response_attempts = 0
        exception_attempts = 0
        budget_escalations = 0
        last_error: Exception | None = None
        # Uniform escalation ladder for every model: normal budget, then a
        # larger budget, then the larger budget with provider reasoning
        # excluded. Prevents hidden reasoning from consuming the entire
        # completion budget and scoring as an empty patch.
        attempt_max_tokens = self.max_tokens
        attempt_exclude_reasoning = self.reasoning_exclude

        for attempt in range(1, self.max_attempts + 1):
            try:
                response = self._complete(
                    messages,
                    max_tokens_override=attempt_max_tokens,
                    exclude_reasoning_override=attempt_exclude_reasoning,
                )
                text, used_reasoning_content = self._response_text(response)
                attempt_meta = self._response_meta(response)
                attempt_meta["attempt"] = attempt
                attempt_meta["used_reasoning_content"] = used_reasoning_content
                attempt_meta["max_tokens"] = attempt_max_tokens
                attempt_meta["budget_exhausted"] = self._budget_exhausted(
                    attempt_meta, attempt_max_tokens
                )
                attempt_metas.append(attempt_meta)
                logger.info(
                    (
                        "LiteLLM attempt %d/%d meta: finish_reason=%s "
                        "content_chars=%d reasoning_content_chars=%d "
                        "used_reasoning_content=%s"
                    ),
                    attempt,
                    self.max_attempts,
                    attempt_meta.get("finish_reason", ""),
                    attempt_meta.get("content_chars", 0),
                    attempt_meta.get("reasoning_content_chars", 0),
                    attempt_meta.get("used_reasoning_content", False),
                )

                if text.strip() or not self.retry_empty_responses:
                    self._last_response_meta = self._aggregate_response_meta(
                        attempt_metas,
                        attempts=attempt,
                        empty_response_attempts=empty_response_attempts,
                        exception_attempts=exception_attempts,
                        budget_escalations=budget_escalations,
                    )
                    self._log_response_meta()
                    return text

                empty_response_attempts += 1
                retry_reason = "empty response"
                if attempt_meta["budget_exhausted"]:
                    if attempt_max_tokens < self.escalated_max_tokens:
                        attempt_max_tokens = self.escalated_max_tokens
                        budget_escalations += 1
                        retry_reason = (
                            "empty response with exhausted budget; "
                            f"escalating max_tokens to {attempt_max_tokens}"
                        )
                    elif not attempt_exclude_reasoning:
                        attempt_exclude_reasoning = True
                        budget_escalations += 1
                        retry_reason = (
                            "empty response with exhausted escalated budget; "
                            "excluding provider reasoning"
                        )
                self._last_response_meta = self._aggregate_response_meta(
                    attempt_metas,
                    attempts=attempt,
                    empty_response_attempts=empty_response_attempts,
                    exception_attempts=exception_attempts,
                    budget_escalations=budget_escalations,
                    last_error="empty response",
                )
                if attempt == self.max_attempts:
                    logger.warning(
                        "LiteLLM returned an empty response after %d attempt(s)",
                        attempt,
                    )
                    self._log_response_meta()
                    return text

                self._sleep_before_retry(attempt, retry_reason)
            except Exception as exc:
                last_error = exc
                exception_attempts += 1
                self._last_response_meta = self._aggregate_response_meta(
                    attempt_metas,
                    attempts=attempt,
                    empty_response_attempts=empty_response_attempts,
                    exception_attempts=exception_attempts,
                    budget_escalations=budget_escalations,
                    last_error=f"{type(exc).__name__}: {exc}",
                )
                if attempt == self.max_attempts:
                    logger.warning(
                        "LiteLLM failed after %d attempt(s): %s",
                        attempt,
                        exc,
                    )
                    raise

                self._sleep_before_retry(attempt, f"{type(exc).__name__}: {exc}")

        if last_error is not None:
            raise last_error
        return ""

    def _budget_exhausted(self, attempt_meta: dict, max_tokens: int) -> bool:
        if attempt_meta.get("finish_reason") == "length":
            return True
        completion = attempt_meta.get("completion_tokens", 0) or 0
        return bool(max_tokens) and completion >= int(0.98 * max_tokens)

    def _complete(
        self,
        messages: list[dict],
        max_tokens_override: int | None = None,
        exclude_reasoning_override: bool | None = None,
    ) -> object:
        exclude_reasoning = (
            self.reasoning_exclude
            if exclude_reasoning_override is None
            else exclude_reasoning_override
        )
        kwargs = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": max_tokens_override or self.max_tokens,
            "num_retries": self.num_retries,
            "timeout": self.timeout,
        }
        openrouter_model = self.model.startswith("openrouter/")
        reasoning: dict = {}
        if self.reasoning_effort:
            reasoning["effort"] = self.reasoning_effort
        if self.reasoning_max_tokens is not None:
            reasoning["max_tokens"] = self.reasoning_max_tokens
        if self.reasoning_enabled is not None:
            reasoning["enabled"] = self.reasoning_enabled
        if exclude_reasoning:
            reasoning["exclude"] = True

        if self.reasoning_effort and not openrouter_model:
            kwargs["reasoning_effort"] = self.reasoning_effort
        if reasoning and (openrouter_model or self.reasoning_max_tokens is not None or exclude_reasoning):
            kwargs["extra_body"] = {"reasoning": reasoning}
            if self.reasoning_enabled is False:
                kwargs["extra_body"]["include_reasoning"] = False

        logger.debug(
            (
                "LiteLLM request options: model=%s max_tokens=%d "
                "reasoning_effort=%s extra_body=%s"
            ),
            self.model,
            self.max_tokens,
            self.reasoning_effort,
            kwargs.get("extra_body"),
        )
        return self._complete_with_hard_timeout(kwargs)

    def _complete_with_hard_timeout(self, kwargs: dict) -> object:
        """Call LiteLLM with a process-level timeout for blocking socket reads."""
        # Global override: long suites can wedge the OS multiprocessing
        # subsystem (child/semaphore leaks) until new spawns hang. In-process
        # mode avoids child spawning entirely, relying on the SIGALRM path
        # below plus LiteLLM's own timeout kwarg.
        import os as _os
        if self.process_timeout and not _os.environ.get("VULNBENCH_INPROCESS_LLM"):
            return self._complete_with_process_timeout(kwargs)

        if self.timeout <= 0 or threading.current_thread() is not threading.main_thread():
            return litellm.completion(**kwargs)

        previous_handler = signal.getsignal(signal.SIGALRM)
        previous_timer = signal.getitimer(signal.ITIMER_REAL)
        start = time.monotonic()

        def _raise_timeout(signum: int, frame: object) -> None:
            raise TimeoutError(
                f"LiteLLM completion hard timeout after {self.timeout:.1f}s"
            )

        signal.signal(signal.SIGALRM, _raise_timeout)
        signal.setitimer(signal.ITIMER_REAL, self.timeout)
        try:
            return litellm.completion(**kwargs)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)
            previous_remaining, previous_interval = previous_timer
            if previous_remaining > 0:
                elapsed = time.monotonic() - start
                signal.setitimer(
                    signal.ITIMER_REAL,
                    max(0.001, previous_remaining - elapsed),
                    previous_interval,
                )

    def _complete_with_process_timeout(self, kwargs: dict) -> object:
        if self.timeout <= 0:
            return litellm.completion(**kwargs)

        ctx = _multiprocessing_context()
        result_queue = ctx.Queue(maxsize=1)
        proc = ctx.Process(
            target=_litellm_completion_worker,
            args=(kwargs, result_queue),
            daemon=True,
        )
        proc.start()
        proc.join(self.timeout)
        if proc.is_alive():
            proc.terminate()
            proc.join(5)
            if proc.is_alive():
                proc.kill()
                proc.join()
            raise TimeoutError(
                f"LiteLLM completion process timeout after {self.timeout:.1f}s"
            )

        try:
            status, *payload = result_queue.get_nowait()
        except queue.Empty as exc:
            raise RuntimeError(
                f"LiteLLM completion process exited without a result "
                f"(exitcode={proc.exitcode})"
            ) from exc

        if status == "ok":
            return payload[0]

        exc_type, message, child_traceback = payload
        raise RuntimeError(
            "LiteLLM completion failed in child process: "
            f"{exc_type}: {message}\n{child_traceback}"
        )

    def _response_meta(self, response: object) -> dict:
        usage = getattr(response, "usage", None)
        hidden_params = getattr(response, "_hidden_params", {}) or {}
        choice = response.choices[0] if getattr(response, "choices", None) else None
        message = getattr(choice, "message", None) if choice is not None else None
        content = getattr(message, "content", "") or ""
        reasoning_content = getattr(message, "reasoning_content", "") or ""
        completion_details = getattr(usage, "completion_tokens_details", None)
        return {
            "prompt_tokens": getattr(usage, "prompt_tokens", 0) or 0,
            "completion_tokens": getattr(usage, "completion_tokens", 0) or 0,
            "reasoning_tokens": getattr(completion_details, "reasoning_tokens", 0) or 0,
            "cost_usd": hidden_params.get("response_cost", 0.0) or 0.0,
            "model": getattr(response, "model", None) or self.model,
            "provider": getattr(response, "provider", "")
            or hidden_params.get("custom_llm_provider", "")
            or "",
            "finish_reason": getattr(choice, "finish_reason", "") or "",
            "content_chars": len(content),
            "reasoning_content_chars": len(reasoning_content),
        }

    def _response_text(self, response: object) -> tuple[str, bool]:
        choice = response.choices[0] if getattr(response, "choices", None) else None
        message = getattr(choice, "message", None) if choice is not None else None
        content = getattr(message, "content", "") or ""
        if content.strip():
            return content, False

        reasoning_content = getattr(message, "reasoning_content", "") or ""
        if reasoning_content.strip() and _looks_like_patch(reasoning_content):
            logger.warning(
                "LiteLLM returned patch-like reasoning_content with empty content; "
                "using reasoning_content as raw output"
            )
            return reasoning_content, True

        return content, False

    def _aggregate_response_meta(
        self,
        attempt_metas: list[dict],
        *,
        attempts: int,
        empty_response_attempts: int,
        exception_attempts: int,
        budget_escalations: int = 0,
        last_error: str = "",
    ) -> dict:
        model = attempt_metas[-1]["model"] if attempt_metas else self.model
        return {
            "budget_escalations": budget_escalations,
            "final_max_tokens": attempt_metas[-1].get("max_tokens", self.max_tokens)
            if attempt_metas
            else self.max_tokens,
            "budget_exhausted": attempt_metas[-1].get("budget_exhausted", False)
            if attempt_metas
            else False,
            "provider": attempt_metas[-1].get("provider", "") if attempt_metas else "",
            "prompt_tokens": sum(m.get("prompt_tokens", 0) for m in attempt_metas),
            "completion_tokens": sum(m.get("completion_tokens", 0) for m in attempt_metas),
            "reasoning_tokens": sum(m.get("reasoning_tokens", 0) for m in attempt_metas),
            "cost_usd": sum(m.get("cost_usd", 0.0) for m in attempt_metas),
            "model": model,
            "attempts": attempts,
            "empty_response_attempts": empty_response_attempts,
            "exception_attempts": exception_attempts,
            "last_error": last_error,
            "reasoning_effort": self.reasoning_effort or "",
            "reasoning_max_tokens": self.reasoning_max_tokens or 0,
            "reasoning_exclude": self.reasoning_exclude,
            "reasoning_enabled": self.reasoning_enabled,
            "process_timeout": self.process_timeout,
            "finish_reason": attempt_metas[-1].get("finish_reason", "") if attempt_metas else "",
            "content_chars": sum(m.get("content_chars", 0) for m in attempt_metas),
            "reasoning_content_chars": sum(
                m.get("reasoning_content_chars", 0) for m in attempt_metas
            ),
            "used_reasoning_content": any(
                m.get("used_reasoning_content", False) for m in attempt_metas
            ),
        }

    def _sleep_before_retry(self, attempt: int, reason: str) -> None:
        delay = self._retry_delay_s(attempt)
        logger.warning(
            "LiteLLM attempt %d/%d failed (%s); retrying in %.2fs",
            attempt,
            self.max_attempts,
            reason,
            delay,
        )
        if delay > 0:
            time.sleep(delay)

    def _retry_delay_s(self, attempt: int) -> float:
        base_delay = self.retry_backoff_base_s * (2 ** max(attempt - 1, 0))
        delay = min(base_delay, self.retry_backoff_max_s)
        if self.retry_backoff_jitter_s:
            delay += random.uniform(0, self.retry_backoff_jitter_s)
        return delay

    def _log_response_meta(self) -> None:
        logger.info(
            (
                "LiteLLM response: attempts=%d empty=%d exceptions=%d "
                "tokens=%d+%d reasoning=%d cost=$%.4f finish_reason=%s "
                "content_chars=%d reasoning_content_chars=%d "
                "used_reasoning_content=%s"
            ),
            self._last_response_meta.get("attempts", 0),
            self._last_response_meta.get("empty_response_attempts", 0),
            self._last_response_meta.get("exception_attempts", 0),
            self._last_response_meta.get("prompt_tokens", 0),
            self._last_response_meta.get("completion_tokens", 0),
            self._last_response_meta.get("reasoning_tokens", 0),
            self._last_response_meta.get("cost_usd", 0.0),
            self._last_response_meta.get("finish_reason", ""),
            self._last_response_meta.get("content_chars", 0),
            self._last_response_meta.get("reasoning_content_chars", 0),
            self._last_response_meta.get("used_reasoning_content", False),
        )

    @property
    def last_response_meta(self) -> dict:
        """Metadata from the most recent generate_patch call."""
        return dict(self._last_response_meta)
