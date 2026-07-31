"""Tests for benchmark.stats."""

import math
import unittest

from benchmark.stats import (
    mean_and_sample_std,
    multi_run_pass_summary,
    paired_bootstrap_diff,
    pass_rate_by,
    rank_tie_groups,
    wilson_interval,
)


class TestWilsonInterval(unittest.TestCase):
    def test_zero_n(self):
        self.assertEqual(wilson_interval(0, 0), (0.0, 0.0))

    def test_bounds_stay_in_unit_interval(self):
        low, high = wilson_interval(0, 200)
        self.assertEqual(low, 0.0)
        self.assertGreater(high, 0.0)
        low, high = wilson_interval(200, 200)
        self.assertEqual(high, 1.0)
        self.assertLess(low, 1.0)

    def test_known_value(self):
        # 30/200 = 15%; Wilson 95% interval ≈ (10.7%, 20.6%)
        low, high = wilson_interval(30, 200)
        self.assertAlmostEqual(low, 0.107, places=2)
        self.assertAlmostEqual(high, 0.206, places=2)

    def test_out_of_range_raises(self):
        with self.assertRaises(ValueError):
            wilson_interval(5, 4)


class TestMeanStd(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(mean_and_sample_std([]), (0.0, 0.0))

    def test_single(self):
        self.assertEqual(mean_and_sample_std([0.5]), (0.5, 0.0))

    def test_sample_std(self):
        mean, std = mean_and_sample_std([0.1, 0.2, 0.3])
        self.assertAlmostEqual(mean, 0.2)
        self.assertAlmostEqual(std, 0.1)


class TestMultiRunSummary(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(multi_run_pass_summary([])["runs"], 0)

    def test_common_instance_alignment(self):
        run1 = {"a": True, "b": False, "c": True}
        run2 = {"a": True, "b": True}  # missing c
        summary = multi_run_pass_summary([run1, run2])
        self.assertEqual(summary["common_instances"], 2)
        self.assertEqual(summary["dropped_instances"], 1)
        # over {a, b}: run1 = 1/2, run2 = 2/2
        self.assertEqual(summary["per_run_pass_rates"], [0.5, 1.0])
        self.assertAlmostEqual(summary["mean_pass_rate"], 0.75)
        self.assertEqual(summary["pass_at_k"], 1.0)  # a or b passes somewhere
        self.assertEqual(summary["all_runs_pass_rate"], 0.5)  # only a passes in both

    def test_pooled_interval_uses_all_trials(self):
        run = {f"i{k}": k < 3 for k in range(10)}
        summary = multi_run_pass_summary([run, run, run])
        low, high = summary["pooled_wilson_95"]
        self.assertLess(low, 0.3)
        self.assertGreater(high, 0.3)


class TestPairedBootstrap(unittest.TestCase):
    def test_no_overlap(self):
        result = paired_bootstrap_diff({"a": True}, {"b": True})
        self.assertEqual(result["n"], 0)
        self.assertEqual(result["p_value"], 1.0)

    def test_identical_models_not_significant(self):
        passed = {f"i{k}": k % 4 == 0 for k in range(100)}
        result = paired_bootstrap_diff(passed, dict(passed), iterations=500, seed=1)
        self.assertEqual(result["diff"], 0.0)
        self.assertGreater(result["p_value"], 0.9)

    def test_large_gap_significant(self):
        strong = {f"i{k}": k < 60 for k in range(100)}
        weak = {f"i{k}": k < 10 for k in range(100)}
        result = paired_bootstrap_diff(strong, weak, iterations=500, seed=1)
        self.assertAlmostEqual(result["diff"], 0.5)
        self.assertLess(result["p_value"], 0.01)

    def test_deterministic_under_seed(self):
        a = {f"i{k}": k % 3 == 0 for k in range(50)}
        b = {f"i{k}": k % 5 == 0 for k in range(50)}
        r1 = paired_bootstrap_diff(a, b, iterations=300, seed=7)
        r2 = paired_bootstrap_diff(a, b, iterations=300, seed=7)
        self.assertEqual(r1, r2)


class TestRankTieGroups(unittest.TestCase):
    def test_tied_and_separated_groups(self):
        strong = {f"i{k}": k < 60 for k in range(100)}
        strong_twin = {f"i{k}": k < 58 for k in range(100)}
        weak = {f"i{k}": k < 5 for k in range(100)}
        rows = rank_tie_groups(
            [("strong", strong), ("twin", strong_twin), ("weak", weak)],
            iterations=400,
            seed=3,
        )
        self.assertEqual(rows[0]["tie_group"], rows[1]["tie_group"])
        self.assertNotEqual(rows[0]["tie_group"], rows[2]["tie_group"])


class TestPassRateBy(unittest.TestCase):
    def test_buckets_and_intervals(self):
        results = [
            {"instance_id": "1", "difficulty_tier": "tier_1", "passed": True},
            {"instance_id": "2", "difficulty_tier": "tier_1", "passed": False},
            {"instance_id": "3", "difficulty_tier": "tier_2", "passed": False},
            {"instance_id": "4", "difficulty_tier": "", "passed": True},
        ]
        by_tier = pass_rate_by(results, "difficulty_tier")
        self.assertEqual(by_tier["tier_1"]["pass_rate"], 0.5)
        self.assertEqual(by_tier["tier_2"]["passed"], 0)
        self.assertIn("unknown", by_tier)
        low, high = by_tier["tier_1"]["wilson_95"]
        self.assertTrue(0 <= low <= 0.5 <= high <= 1)


if __name__ == "__main__":
    unittest.main()
