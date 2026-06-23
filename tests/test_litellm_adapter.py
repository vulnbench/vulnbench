from __future__ import annotations

import multiprocessing
import time
from types import SimpleNamespace
from unittest.mock import patch
import unittest

from benchmark.adapters.litellm_adapter import LiteLLMAdapter


def _response(
    text: str,
    *,
    reasoning_content: str = "",
    finish_reason: str = "stop",
    prompt_tokens: int = 10,
    completion_tokens: int = 20,
    reasoning_tokens: int = 0,
    cost_usd: float = 0.1,
    model: str = "provider/model",
):
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                finish_reason=finish_reason,
                message=SimpleNamespace(
                    content=text,
                    reasoning_content=reasoning_content,
                ),
            )
        ],
        usage=SimpleNamespace(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            completion_tokens_details=SimpleNamespace(
                reasoning_tokens=reasoning_tokens,
            ),
        ),
        _hidden_params={"response_cost": cost_usd},
        model=model,
    )


class LiteLLMAdapterRetryTests(unittest.TestCase):
    def test_retries_empty_response_and_accumulates_meta(self) -> None:
        adapter = LiteLLMAdapter(
            model="provider/model",
            max_attempts=2,
            retry_backoff_base_s=0,
            retry_backoff_jitter_s=0,
        )

        with patch(
            "benchmark.adapters.litellm_adapter.litellm.completion",
            side_effect=[
                _response("", prompt_tokens=3, completion_tokens=5, cost_usd=0.02),
                _response(
                    "diff --git a/a.py b/a.py\n",
                    prompt_tokens=7,
                    completion_tokens=11,
                    reasoning_tokens=4,
                    cost_usd=0.04,
                ),
            ],
        ) as completion:
            output = adapter.generate_patch("fix this")

        self.assertEqual(output, "diff --git a/a.py b/a.py\n")
        self.assertEqual(completion.call_count, 2)
        meta = adapter.last_response_meta
        self.assertEqual(meta["attempts"], 2)
        self.assertEqual(meta["empty_response_attempts"], 1)
        self.assertEqual(meta["exception_attempts"], 0)
        self.assertEqual(meta["prompt_tokens"], 10)
        self.assertEqual(meta["completion_tokens"], 16)
        self.assertEqual(meta["reasoning_tokens"], 4)
        self.assertAlmostEqual(meta["cost_usd"], 0.06)

    def test_retries_exception_and_passes_reasoning_effort(self) -> None:
        adapter = LiteLLMAdapter(
            model="provider/model",
            max_attempts=2,
            retry_backoff_base_s=0,
            retry_backoff_jitter_s=0,
            reasoning_effort="high",
        )

        with patch(
            "benchmark.adapters.litellm_adapter.litellm.completion",
            side_effect=[
                RuntimeError("temporary provider failure"),
                _response("diff --git a/a.py b/a.py\n"),
            ],
        ) as completion:
            output = adapter.generate_patch("fix this")

        self.assertEqual(output, "diff --git a/a.py b/a.py\n")
        self.assertEqual(completion.call_count, 2)
        for call in completion.call_args_list:
            self.assertEqual(call.kwargs["reasoning_effort"], "high")
        meta = adapter.last_response_meta
        self.assertEqual(meta["attempts"], 2)
        self.assertEqual(meta["exception_attempts"], 1)
        self.assertEqual(meta["reasoning_effort"], "high")

    def test_openrouter_reasoning_effort_uses_reasoning_extra_body(self) -> None:
        adapter = LiteLLMAdapter(
            model="openrouter/provider/model",
            max_attempts=1,
            retry_backoff_base_s=0,
            retry_backoff_jitter_s=0,
            reasoning_effort="low",
        )

        with patch(
            "benchmark.adapters.litellm_adapter.litellm.completion",
            return_value=_response("diff --git a/a.py b/a.py\n"),
        ) as completion:
            adapter.generate_patch("fix this")

        call = completion.call_args
        self.assertNotIn("reasoning_effort", call.kwargs)
        self.assertEqual(
            call.kwargs["extra_body"],
            {"reasoning": {"effort": "low"}},
        )

    def test_rejects_effort_and_reasoning_max_tokens_together(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot both be set"):
            LiteLLMAdapter(
                model="openrouter/provider/model",
                reasoning_effort="low",
                reasoning_max_tokens=512,
            )

    def test_openrouter_glm52_disables_default_reasoning(self) -> None:
        adapter = LiteLLMAdapter(
            model="openrouter/z-ai/glm-5.2",
            max_attempts=1,
            retry_backoff_base_s=0,
            retry_backoff_jitter_s=0,
        )

        with patch(
            "benchmark.adapters.litellm_adapter.litellm.completion",
            return_value=_response("diff --git a/a.py b/a.py\n"),
        ) as completion:
            adapter.generate_patch("fix this")

        self.assertEqual(
            completion.call_args.kwargs["extra_body"],
            {
                "reasoning": {"enabled": False, "exclude": True},
                "include_reasoning": False,
            },
        )
        self.assertEqual(adapter.last_response_meta["reasoning_max_tokens"], 0)
        self.assertEqual(adapter.last_response_meta["reasoning_enabled"], False)
        self.assertEqual(adapter.last_response_meta["reasoning_exclude"], True)

    def test_reasoning_content_patch_fallback(self) -> None:
        adapter = LiteLLMAdapter(
            model="openrouter/z-ai/glm-5.2",
            max_attempts=1,
            retry_backoff_base_s=0,
            retry_backoff_jitter_s=0,
        )
        patch_text = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"

        with patch(
            "benchmark.adapters.litellm_adapter.litellm.completion",
            return_value=_response(
                "",
                reasoning_content=patch_text,
                finish_reason="length",
                reasoning_tokens=100,
            ),
        ):
            output = adapter.generate_patch("fix this")

        self.assertEqual(output, patch_text)
        self.assertEqual(adapter.last_response_meta["empty_response_attempts"], 0)
        self.assertTrue(adapter.last_response_meta["used_reasoning_content"])

    def test_raises_after_retry_limit(self) -> None:
        adapter = LiteLLMAdapter(
            model="provider/model",
            max_attempts=2,
            retry_backoff_base_s=0,
            retry_backoff_jitter_s=0,
        )

        with patch(
            "benchmark.adapters.litellm_adapter.litellm.completion",
            side_effect=RuntimeError("provider down"),
        ) as completion:
            with self.assertRaisesRegex(RuntimeError, "provider down"):
                adapter.generate_patch("fix this")

        self.assertEqual(completion.call_count, 2)
        meta = adapter.last_response_meta
        self.assertEqual(meta["attempts"], 2)
        self.assertEqual(meta["exception_attempts"], 2)
        self.assertIn("provider down", meta["last_error"])

    def test_hard_timeout_interrupts_blocking_completion(self) -> None:
        adapter = LiteLLMAdapter(
            model="provider/model",
            max_attempts=1,
            retry_backoff_base_s=0,
            retry_backoff_jitter_s=0,
            timeout=0.05,
        )

        def slow_completion(**kwargs):
            time.sleep(1)
            return _response("diff --git a/a.py b/a.py\n")

        start = time.monotonic()
        with patch(
            "benchmark.adapters.litellm_adapter.litellm.completion",
            side_effect=slow_completion,
        ):
            with self.assertRaisesRegex(TimeoutError, "hard timeout"):
                adapter.generate_patch("fix this")

        self.assertLess(time.monotonic() - start, 0.5)
        meta = adapter.last_response_meta
        self.assertEqual(meta["attempts"], 1)
        self.assertEqual(meta["exception_attempts"], 1)
        self.assertIn("hard timeout", meta["last_error"])

    @unittest.skipUnless(
        "fork" in multiprocessing.get_all_start_methods(),
        "process timeout test requires fork start method",
    )
    def test_process_timeout_interrupts_blocking_completion(self) -> None:
        adapter = LiteLLMAdapter(
            model="provider/model",
            max_attempts=1,
            retry_backoff_base_s=0,
            retry_backoff_jitter_s=0,
            timeout=0.05,
            process_timeout=True,
        )

        def slow_completion(**kwargs):
            time.sleep(1)
            return _response("diff --git a/a.py b/a.py\n")

        start = time.monotonic()
        with patch(
            "benchmark.adapters.litellm_adapter._multiprocessing_context",
            return_value=multiprocessing.get_context("fork"),
        ):
            with patch(
                "benchmark.adapters.litellm_adapter.litellm.completion",
                side_effect=slow_completion,
            ):
                with self.assertRaisesRegex(TimeoutError, "process timeout"):
                    adapter.generate_patch("fix this")

        self.assertLess(time.monotonic() - start, 0.5)
        meta = adapter.last_response_meta
        self.assertEqual(meta["attempts"], 1)
        self.assertEqual(meta["exception_attempts"], 1)
        self.assertIn("process timeout", meta["last_error"])


if __name__ == "__main__":
    unittest.main()
