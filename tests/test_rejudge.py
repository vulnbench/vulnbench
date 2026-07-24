"""Tests for benchmark.rejudge (no network calls; judge is stubbed)."""

import unittest
from unittest import mock

from benchmark.eval_models import InstanceResult, PatchAnalysis
from benchmark.rejudge import rejudge_result


def _analysis(score: float, verdict: str) -> PatchAnalysis:
    return PatchAnalysis(
        judge_model="stub-judge",
        judge_score=score,
        judge_verdict=verdict,
        raw_judge_verdict=verdict,
        judge_cost_usd=0.01,
    )


class TestRejudgeResult(unittest.TestCase):
    def _result(self, **overrides) -> InstanceResult:
        base = dict(
            instance_id="vulnbench-CVE-2024-0001",
            cve_id="CVE-2024-0001",
            model_patch="diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b",
            score=0.0,
            passed=False,
            cost_usd=0.5,
            prompt_tokens=100,
            completion_tokens=200,
        )
        base.update(overrides)
        return InstanceResult(**base)

    def test_rejudge_updates_scoring_and_keeps_generation_fields(self):
        result = self._result()
        with mock.patch(
            "benchmark.rejudge.judge_patch_with_models",
            return_value=(_analysis(0.8, "pass"), {"stub-judge": _analysis(0.8, "pass")}),
        ) as judge:
            updated = rejudge_result(result, instance=mock.Mock(), judge_models=["stub-judge"])

        judge.assert_called_once()
        self.assertTrue(updated.passed)
        self.assertEqual(updated.score, 0.8)
        self.assertEqual(updated.judge_cost_usd, 0.01)
        # Generation-side fields must be preserved untouched
        self.assertEqual(updated.cost_usd, 0.5)
        self.assertEqual(updated.prompt_tokens, 100)
        self.assertEqual(updated.completion_tokens, 200)
        self.assertEqual(updated.model_patch, result.model_patch)
        # Original result is not mutated
        self.assertFalse(result.passed)

    def test_adapter_error_results_are_not_sent_to_judge(self):
        result = self._result(generation_error="TimeoutError: boom", model_patch="")
        with mock.patch("benchmark.rejudge.judge_patch_with_models") as judge:
            updated = rejudge_result(result, instance=mock.Mock(), judge_models=["stub-judge"])

        judge.assert_not_called()
        self.assertFalse(updated.passed)
        self.assertEqual(updated.score, 0.0)
        self.assertEqual(updated.patch_analysis.raw_judge_verdict, "adapter_error")


if __name__ == "__main__":
    unittest.main()
