from __future__ import annotations

import multiprocessing
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from benchmark.eval_models import PatchAnalysis
from benchmark.run_eval import combine_judge_analyses, judge_patch


def _instance() -> SimpleNamespace:
    return SimpleNamespace(
        instance_id="test-instance",
        cve_id="CVE-2099-0001",
        cwe_ids=["CWE-79"],
        ecosystem="npm",
        package_name="pkg",
        severity="high",
        task_prompt=SimpleNamespace(
            vulnerability_description="Fix reflected input handling.",
            affected_files_hint=["src/app.js"],
        ),
        gold_patch=SimpleNamespace(raw_diff="diff --git a/src/app.js b/src/app.js\n"),
    )


def _slow_completion(**kwargs):
    time.sleep(1)
    return SimpleNamespace()


class MultiJudgeConsensusTests(unittest.TestCase):
    def test_majority_vote_with_median_score(self) -> None:
        consensus = combine_judge_analyses(
            {
                "judge-a": PatchAnalysis(
                    judge_model="judge-a",
                    judge_score=0.9,
                    judge_verdict="pass",
                    judge_cost_usd=0.1,
                ),
                "judge-b": PatchAnalysis(
                    judge_model="judge-b",
                    judge_score=0.7,
                    judge_verdict="pass",
                    judge_cost_usd=0.2,
                ),
                "judge-c": PatchAnalysis(
                    judge_model="judge-c",
                    judge_score=0.2,
                    judge_verdict="fail",
                    judge_cost_usd=0.3,
                ),
            }
        )

        self.assertEqual(consensus.judge_model, "consensus")
        self.assertEqual(consensus.judge_verdict, "pass")
        self.assertEqual(consensus.judge_score, 0.7)
        self.assertEqual(consensus.raw_judge_verdict, "pass:2,fail:1")
        self.assertFalse(consensus.judge_consistent)
        self.assertAlmostEqual(consensus.judge_cost_usd, 0.6)

    def test_judge_errors_abstain_from_consensus_vote(self) -> None:
        consensus = combine_judge_analyses(
            {
                "judge-a": PatchAnalysis(
                    judge_model="judge-a",
                    judge_score=0.8,
                    judge_verdict="pass",
                    judge_cost_usd=0.1,
                ),
                "judge-b": PatchAnalysis(
                    judge_model="judge-b",
                    judge_score=0.6,
                    judge_verdict="pass",
                    judge_cost_usd=0.2,
                ),
                "judge-c": PatchAnalysis(
                    judge_model="judge-c",
                    judge_score=0.0,
                    judge_verdict="fail",
                    raw_judge_verdict="judge_error",
                    judge_cost_usd=0.3,
                ),
            }
        )

        self.assertEqual(consensus.judge_verdict, "pass")
        self.assertEqual(consensus.judge_score, 0.7)
        self.assertEqual(consensus.raw_judge_verdict, "pass:2,fail:0,abstain:1")
        self.assertAlmostEqual(consensus.judge_cost_usd, 0.6)

    def test_two_judge_disagreement_is_conservative_fail(self) -> None:
        consensus = combine_judge_analyses(
            {
                "judge-a": PatchAnalysis(
                    judge_model="judge-a",
                    judge_score=0.8,
                    judge_verdict="pass",
                ),
                "judge-b": PatchAnalysis(
                    judge_model="judge-b",
                    judge_score=0.2,
                    judge_verdict="fail",
                ),
            }
        )

        self.assertEqual(consensus.judge_verdict, "fail")
        self.assertEqual(consensus.judge_score, 0.5)
        self.assertEqual(consensus.raw_judge_verdict, "pass:1,fail:1")
        self.assertFalse(consensus.judge_consistent)

    @unittest.skipUnless(
        "fork" in multiprocessing.get_all_start_methods(),
        "process timeout test requires fork start method",
    )
    def test_judge_process_timeout_returns_judge_error(self) -> None:
        with patch(
            "benchmark.run_eval._judge_multiprocessing_context",
            return_value=multiprocessing.get_context("fork"),
        ):
            with patch("benchmark.run_eval.LITELLM_TIMEOUT_SECONDS", 0.05):
                with patch("benchmark.run_eval.JUDGE_MAX_ATTEMPTS", 1):
                    with patch(
                        "benchmark.run_eval.litellm.completion",
                        side_effect=_slow_completion,
                    ):
                        start = time.monotonic()
                        analysis = judge_patch(
                            _instance(),
                            "diff --git a/src/app.js b/src/app.js\n",
                            judge_model="openrouter/judge/model",
                        )

        self.assertLess(time.monotonic() - start, 0.5)
        self.assertEqual(analysis.raw_judge_verdict, "judge_error")
        self.assertEqual(analysis.judge_verdict, "fail")
        self.assertIn("process timeout", analysis.judge_reasoning)


if __name__ == "__main__":
    unittest.main()
