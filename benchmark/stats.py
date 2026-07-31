"""Statistical utilities for VulnBench reporting.

Pure-stdlib implementations (no numpy/scipy) so they run anywhere the
harness runs. All randomized procedures take an explicit seed so published
numbers are reproducible.
"""

from __future__ import annotations

import math
import random
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

Z_95 = 1.959963984540054  # two-sided 95%


def wilson_interval(
    successes: int,
    n: int,
    z: float = Z_95,
) -> Tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Preferred over the normal approximation for the small proportions
    typical of VulnBench pass rates (it never leaves [0, 1] and behaves
    sensibly when successes is 0 or n).
    """
    if n <= 0:
        return (0.0, 0.0)
    if not 0 <= successes <= n:
        raise ValueError(f"successes={successes} out of range for n={n}")

    p = successes / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, center - margin), min(1.0, center + margin))


def mean_and_sample_std(values: Sequence[float]) -> Tuple[float, float]:
    """Mean and sample standard deviation (ddof=1; 0.0 when n < 2)."""
    n = len(values)
    if n == 0:
        return (0.0, 0.0)
    mean = sum(values) / n
    if n < 2:
        return (mean, 0.0)
    var = sum((v - mean) ** 2 for v in values) / (n - 1)
    return (mean, math.sqrt(var))


def multi_run_pass_summary(
    runs: Sequence[Dict[str, bool]],
) -> dict:
    """Summarize pass results across repeated runs of the same model.

    Each run maps instance_id -> passed. Only instances present in every
    run are used, so partially-complete runs cannot skew the comparison;
    the number of dropped instances is reported.

    Returns per-run rates, the mean rate with a Wilson interval on pooled
    trials, and pass@k / all-pass rates over the common instances.
    """
    if not runs:
        return {
            "runs": 0,
            "common_instances": 0,
            "dropped_instances": 0,
            "per_run_pass_rates": [],
            "mean_pass_rate": 0.0,
            "pass_rate_std": 0.0,
            "pooled_wilson_95": (0.0, 0.0),
            "pass_at_k": 0.0,
            "all_runs_pass_rate": 0.0,
        }

    common = set(runs[0])
    union = set(runs[0])
    for run in runs[1:]:
        common &= set(run)
        union |= set(run)
    ordered = sorted(common)

    per_run = []
    for run in runs:
        n = len(ordered)
        per_run.append(sum(1 for i in ordered if run[i]) / n if n else 0.0)

    mean_rate, std = mean_and_sample_std(per_run)
    pooled_successes = sum(1 for run in runs for i in ordered if run[i])
    pooled_n = len(runs) * len(ordered)

    any_pass = sum(1 for i in ordered if any(run[i] for run in runs))
    all_pass = sum(1 for i in ordered if all(run[i] for run in runs))
    n = len(ordered)

    return {
        "runs": len(runs),
        "common_instances": n,
        "dropped_instances": len(union) - n,
        "per_run_pass_rates": [round(r, 4) for r in per_run],
        "mean_pass_rate": round(mean_rate, 4),
        "pass_rate_std": round(std, 4),
        "pooled_wilson_95": tuple(
            round(v, 4) for v in wilson_interval(pooled_successes, pooled_n)
        ),
        "pass_at_k": round(any_pass / n, 4) if n else 0.0,
        "all_runs_pass_rate": round(all_pass / n, 4) if n else 0.0,
    }


def paired_bootstrap_diff(
    a: Dict[str, bool],
    b: Dict[str, bool],
    iterations: int = 10_000,
    seed: int = 0,
) -> dict:
    """Paired bootstrap over instances for the pass-rate difference a - b.

    Resamples instance ids with replacement, preserving the pairing between
    the two models on each instance. Returns the observed difference, a 95%
    percentile interval, and a two-sided p-value for the null of no
    difference (fraction of resamples on the other side of zero, doubled).
    """
    ids = sorted(set(a) & set(b))
    n = len(ids)
    if n == 0:
        return {"n": 0, "diff": 0.0, "ci_95": (0.0, 0.0), "p_value": 1.0}

    a_vec = [1 if a[i] else 0 for i in ids]
    b_vec = [1 if b[i] else 0 for i in ids]
    observed = (sum(a_vec) - sum(b_vec)) / n

    rng = random.Random(seed)
    diffs = []
    for _ in range(iterations):
        total = 0
        for _ in range(n):
            j = rng.randrange(n)
            total += a_vec[j] - b_vec[j]
        diffs.append(total / n)
    diffs.sort()

    lo = diffs[int(0.025 * iterations)]
    hi = diffs[min(iterations - 1, int(0.975 * iterations))]

    if observed >= 0:
        tail = sum(1 for d in diffs if d <= 0) / iterations
    else:
        tail = sum(1 for d in diffs if d >= 0) / iterations
    p_value = min(1.0, 2 * tail)

    return {
        "n": n,
        "diff": round(observed, 4),
        "ci_95": (round(lo, 4), round(hi, 4)),
        "p_value": round(p_value, 4),
    }


def rank_tie_groups(
    models: List[Tuple[str, Dict[str, bool]]],
    alpha: float = 0.05,
    iterations: int = 2_000,
    seed: int = 0,
) -> List[dict]:
    """Assign leaderboard rows to statistical tie groups.

    ``models`` is ordered best-first; each entry pairs a model name with its
    instance_id -> passed map. Walking down the ranking, a model starts a new
    tie group only when the paired bootstrap distinguishes it (p < alpha)
    from the FIRST member of the current group. Rows in the same group are
    statistically indistinguishable from the group leader and should share a
    rank marker in published tables.
    """
    groups: List[dict] = []
    out: List[dict] = []
    for name, passed in models:
        if groups and (
            paired_bootstrap_diff(
                groups[-1]["leader_passed"], passed, iterations=iterations, seed=seed
            )["p_value"]
            >= alpha
        ):
            group = groups[-1]
        else:
            group = {"index": len(groups) + 1, "leader": name, "leader_passed": passed}
            groups.append(group)
        out.append({"model": name, "tie_group": group["index"], "group_leader": group["leader"]})
    return out


def extract_passed_map(results: Iterable[dict]) -> Dict[str, bool]:
    """instance_id -> passed from a report's ``results`` list."""
    return {r["instance_id"]: bool(r.get("passed", False)) for r in results}


def pass_rate_by(
    results: Iterable[dict],
    key: str,
    min_n: int = 1,
    getter=None,
) -> Dict[str, dict]:
    """Pass rate broken down by a per-instance field, with Wilson intervals."""
    buckets: Dict[str, List[bool]] = {}
    for r in results:
        value = getter(r) if getter else r.get(key)
        if value in (None, ""):
            value = "unknown"
        buckets.setdefault(str(value), []).append(bool(r.get("passed", False)))

    out: Dict[str, dict] = {}
    for value, flags in sorted(buckets.items()):
        n = len(flags)
        if n < min_n:
            continue
        passed = sum(flags)
        low, high = wilson_interval(passed, n)
        out[value] = {
            "n": n,
            "passed": passed,
            "pass_rate": round(passed / n, 4),
            "wilson_95": (round(low, 4), round(high, 4)),
        }
    return out
