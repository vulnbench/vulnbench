"""Generate the VulnBench V2 report from curated best-of-3 results."""

from __future__ import annotations

import html
import json
import re
import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
DOCS = ROOT / "docs"
MODEL_SUITE = ROOT / "benchmark" / "model_suites.sh"


ORG_CLASS = {
    "openai": "openai",
    "anthropic": "anthropic",
    "google": "google",
    "z-ai": "zhipu",
    "moonshotai": "moonshot",
    "x-ai": "xai",
    "deepseek": "deepseek",
    "minimax": "minimax",
    "stepfun": "stepfun",
    "nvidia": "google",
    "mistralai": "minimax",
    "qwen": "zhipu",
}

ORG_LABEL = {
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "google": "Google",
    "z-ai": "Z.AI",
    "moonshotai": "Moonshot AI",
    "x-ai": "xAI",
    "deepseek": "DeepSeek",
    "minimax": "MiniMax",
    "stepfun": "StepFun",
    "nvidia": "NVIDIA",
    "mistralai": "Mistral AI",
    "qwen": "Qwen",
}

DISPLAY_NAMES = {
    "openai/gpt-5.5": "GPT-5.5",
    "openai/gpt-5.4-mini": "GPT-5.4 Mini",
    "openai/gpt-5.3-codex": "GPT-5.3 Codex",
    "anthropic/claude-fable-5": "Claude Fable 5",
    "anthropic/claude-opus-4.8": "Claude Opus 4.8",
    "anthropic/claude-sonnet-4.6": "Claude Sonnet 4.6",
    "anthropic/claude-haiku-4.5": "Claude Haiku 4.5",
    "google/gemini-3.5-flash": "Gemini 3.5 Flash",
    "google/gemini-3.1-pro-preview": "Gemini 3.1 Pro",
    "x-ai/grok-build-0.1": "Grok Build 0.1",
    "x-ai/grok-4.3": "Grok 4.3",
    "deepseek/deepseek-v4-pro": "DeepSeek V4 Pro",
    "deepseek/deepseek-v4-flash": "DeepSeek V4 Flash",
    "moonshotai/kimi-k2.6": "Kimi K2.6",
    "minimax/minimax-m3": "MiniMax M3",
    "qwen/qwen3.7-max": "Qwen 3.7 Max",
    "qwen/qwen3.7-plus": "Qwen 3.7 Plus",
    "z-ai/glm-5.2": "GLM 5.2",
    "z-ai/glm-5.1": "GLM 5.1",
    "stepfun/step-3.7-flash": "Step 3.7 Flash",
    "nvidia/nemotron-3-ultra-550b-a55b": "Nemotron 3 Ultra 550B",
    "mistralai/mistral-medium-3-5": "Mistral Medium 3.5",
}


@dataclass
class Row:
    model: str
    display: str
    org: str
    org_class: str
    pass_rate: float
    mean_score: float
    passed: int
    total: int
    cost: float
    avg_time: float
    best_run: int | None
    runs: list[dict]
    source: str | None = None


def load_latest_models() -> list[str]:
    text = MODEL_SUITE.read_text()
    match = re.search(r"VULNBENCH_LATEST_MODELS=\(\n(?P<body>.*?)\n\)", text, re.S)
    if not match:
        raise RuntimeError("Could not find VULNBENCH_LATEST_MODELS")
    return [
        line.strip()
        for line in match.group("body").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def model_key(model: str) -> str:
    return model.removeprefix("openrouter/")


def safe_full(model: str) -> str:
    return model.replace("/", "_").replace(":", "_")


def safe_short(model: str) -> str:
    return model_key(model).replace("/", "_").replace(":", "_")


def combine_completed_best3(model: str) -> None:
    reports = []
    for run in range(1, 4):
        path = RESULTS / f"run{run}_{safe_full(model)}.json"
        if not path.exists():
            return
        data = json.loads(path.read_text())
        if data.get("aggregate", {}).get("total_instances") != 200:
            return
        reports.append((run, data))

    best_run, best = max(
        reports,
        key=lambda item: (
            item[1]["aggregate"]["pass_rate"],
            item[1]["aggregate"]["mean_score"],
        ),
    )
    best.setdefault("metadata", {})
    best["metadata"]["best_of_n"] = 3
    best["metadata"]["best_run"] = best_run
    best["metadata"]["all_runs"] = [
        {
            "run": run,
            "pass_rate": data["aggregate"]["pass_rate"],
            "mean_score": data["aggregate"]["mean_score"],
            "total_cost_usd": data["aggregate"].get("total_cost_usd", 0),
        }
        for run, data in reports
    ]
    (RESULTS / f"best3_{safe_short(model)}.json").write_text(json.dumps(best, indent=2))


def load_row(model: str) -> Row | None:
    path = RESULTS / f"best3_{safe_short(model)}.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    agg = data["aggregate"]
    if agg.get("total_instances") != 200:
        return None
    key = model_key(model)
    org_key = key.split("/", 1)[0]
    return Row(
        model=model,
        display=DISPLAY_NAMES.get(key, key.split("/", 1)[-1]),
        org=ORG_LABEL.get(org_key, org_key),
        org_class=ORG_CLASS.get(org_key, "xai"),
        pass_rate=agg["pass_rate"],
        mean_score=agg["mean_score"],
        passed=agg["total_passed"],
        total=agg["total_instances"],
        cost=agg.get("total_cost_usd", 0),
        avg_time=agg.get("mean_generation_time_s", 0),
        best_run=data.get("metadata", {}).get("best_run"),
        runs=data.get("metadata", {}).get("all_runs", []),
    )


def source_label(row: dict) -> str:
    decision = row.get("decision")
    source = row.get("source")
    if decision == "add_new_fixed_harness" or source == "fixed_harness_new_model":
        return "new fixed harness"
    if source == "fixed_harness":
        return "fixed harness"
    if source == "prior_baseline":
        return "prior baseline"
    return str(source or "unknown")


def load_merged_rows(results_dir: Path) -> tuple[list[Row], dict]:
    manifest_path = results_dir / "merged_leaderboard.json"
    manifest = json.loads(manifest_path.read_text())
    rows = []
    for item in manifest["rows"]:
        key = model_key(item["model"])
        org_key = key.split("/", 1)[0]
        rows.append(
            Row(
                model=item["model"],
                display=item.get("display") or DISPLAY_NAMES.get(key, key.split("/", 1)[-1]),
                org=item.get("org") or ORG_LABEL.get(org_key, org_key),
                org_class=ORG_CLASS.get(org_key, "xai"),
                pass_rate=item["pass_rate"],
                mean_score=item["mean_score"],
                passed=item["total_passed"],
                total=item["total_instances"],
                cost=item.get("total_cost_usd", 0) + item.get("total_judge_cost_usd", 0),
                avg_time=item.get("mean_generation_time_s", 0),
                best_run=item.get("best_run"),
                runs=[],
                source=source_label(item),
            )
        )
    rows.sort(key=lambda r: (r.pass_rate, r.mean_score), reverse=True)
    return rows, manifest


def pending_models(models: list[str]) -> list[str]:
    pending = []
    for model in models:
        if (RESULTS / f"best3_{safe_short(model)}.json").exists():
            continue
        pending.append(model_key(model))
    return pending


def percent(value: float) -> str:
    return f"{value * 100:.1f}%"


def money(value: float) -> str:
    return f"${value:.2f}"


def leaderboard_html(rows: list[Row]) -> str:
    max_rate = max((row.pass_rate for row in rows), default=1)
    out = []
    for idx, row in enumerate(rows, 1):
        first = idx == 1
        width = 100 * row.pass_rate / max_rate if max_rate else 0
        out.append(
            f'<tr class="{"gs-vb-leaderboard__first-row" if first else ""}">'
            f'<td class="gs-vb-leaderboard__rank {"gs-vb-leaderboard__rank--first" if first else ""}">{idx}</td>'
            f"<td><div class=\"gs-vb-leaderboard__model {'gs-vb-leaderboard__model--first' if first else ''}\">{html.escape(row.display)}</div>"
            f'<div class="gs-vb-leaderboard__org gs-vb-leaderboard__org--{row.org_class}">{html.escape(row.org)}</div></td>'
            f'<td><div class="gs-vb-leaderboard__bar-wrap"><span class="gs-vb-leaderboard__rate">{percent(row.pass_rate)}</span>'
            f'<div class="gs-vb-leaderboard__bar"><div class="gs-vb-leaderboard__bar-fill {"gs-vb-leaderboard__bar-fill--first" if first else ""}" style="width:{width:.1f}%"></div></div></div></td>'
            f'<td class="gs-vb-leaderboard__meta">{row.mean_score:.3f}</td>'
            f'<td class="gs-vb-leaderboard__meta">{row.passed}/{row.total}</td>'
            f'<td class="gs-vb-leaderboard__meta">{row.avg_time:.1f}s</td>'
            f'<td class="gs-vb-leaderboard__meta">{money(row.cost)}</td>'
            "</tr>"
        )
    return "\n".join(out)


def markdown_table(rows: list[Row]) -> str:
    show_source = any(row.source for row in rows)
    if show_source:
        lines = [
            "| Rank | Model | Org | Source | Pass Rate | Mean Score | Passed | Best Run | Cost |",
            "|:----:|-------|-----|--------|:---------:|:----------:|:------:|:--------:|-----:|",
        ]
    else:
        lines = [
            "| Rank | Model | Org | Pass Rate | Mean Score | Passed | Best Run | Cost |",
            "|:----:|-------|-----|:---------:|:----------:|:------:|:--------:|-----:|",
        ]
    for idx, row in enumerate(rows, 1):
        if show_source:
            lines.append(
                f"| {idx} | {row.display} | {row.org} | {row.source or '-'} | {percent(row.pass_rate)} | "
                f"{row.mean_score:.3f} | {row.passed}/{row.total} | {row.best_run or '-'} | {money(row.cost)} |"
            )
        else:
            lines.append(
                f"| {idx} | {row.display} | {row.org} | {percent(row.pass_rate)} | "
                f"{row.mean_score:.3f} | {row.passed}/{row.total} | {row.best_run or '-'} | {money(row.cost)} |"
            )
    return "\n".join(lines)


def render_page(rows: list[Row], pending: list[str], manifest: dict | None = None) -> str:
    top = rows[0]
    median = sorted(row.pass_rate for row in rows)[len(rows) // 2]
    top_two_gap = top.pass_rate - rows[1].pass_rate if len(rows) > 1 else 0
    top_score = max(rows, key=lambda row: row.mean_score)
    complete_count = len(rows)
    pending_note = ""
    if pending:
        pending_note = (
            f"<p class=\"gs-section-desc\">Pending completion: "
            f"{html.escape(', '.join(pending))}. This page will update from checkpointed results.</p>"
        )
    if manifest:
        runner_up = rows[1] if len(rows) > 1 else top
        hero_eyebrow = "Blind vulnerability find and fix benchmark"
        hero_title = "VulnBench V2 Benchmark"
        hero_desc = "VulnBench evaluates AI coding models on real CVEs. Models receive the vulnerability description and source context, must find and patch the flaw without seeing the reference fix, and are scored on whether the patch fixes the root cause safely."
        findings_title = "What We Learned"
        findings_desc = f"The top model solved {top.passed}/200 real vulnerability repair tasks, while the median model solved {round(median * top.total)}/200. The results show clear progress from the strongest systems, but blind CVE repair remains difficult across the field."
        result_title = "VulnBench-200 Model Leaderboard"
        result_desc = "Pass rates show how often each model produced a patch judged to fix the vulnerable behavior without seeing the reference fix."
        method_title = "Blind Vulnerability Repair Evaluation"
        method_desc = "Each model receives a real vulnerability description and relevant source context, then must produce a focused patch. The benchmark measures whether that patch addresses the root cause without unsafe side effects."
        step3_title = "Three Attempts"
        step3_desc = "Each model gets three independent attempts per task; the leaderboard reflects the strongest observed run for that model."
        judge_desc = "Candidate patches are reviewed against the intended security fix for root cause coverage, scope, and safety. A split two-judge vote passes when either judge accepts the patch."
        cta_title = "Reproduce The Benchmark"
        cta_desc = "The repository includes the curated CVE set, model outputs, judge decisions, and report generation scripts used to produce this leaderboard."
        terminal_command = "./run_curated_200_best3.sh"
        footer_scope = "Blind Vulnerability Repair Benchmark"
        finding_cards = f"""<div class="gs-vb-finding"><div class="gs-vb-finding__value">{percent(top.pass_rate)}</div><div class="gs-vb-finding__label">Best Pass Rate</div><p class="gs-vb-finding__desc">{html.escape(top.display)} leads the leaderboard with {top.passed}/200 accepted patches and a {top.mean_score:.3f} mean judge score.</p></div><div class="gs-vb-finding"><div class="gs-vb-finding__value">{runner_up.passed}/200</div><div class="gs-vb-finding__label">Runner Up</div><p class="gs-vb-finding__desc">{html.escape(runner_up.display)} ranks second at {percent(runner_up.pass_rate)}, showing a {top_two_gap * 100:.1f}-point gap from the leader.</p></div><div class="gs-vb-finding"><div class="gs-vb-finding__value">{percent(median)}</div><div class="gs-vb-finding__label">Median Pass Rate</div><p class="gs-vb-finding__desc">The median model still fixes only a small share of real CVEs, even with source context and multiple attempts.</p></div><div class="gs-vb-finding"><div class="gs-vb-finding__value">{top_score.mean_score:.3f}</div><div class="gs-vb-finding__label">Top Mean Score</div><p class="gs-vb-finding__desc">{html.escape(top_score.display)} has the highest mean judge score, reflecting stronger partial-credit patch quality.</p></div><div class="gs-vb-finding"><div class="gs-vb-finding__value">{complete_count}</div><div class="gs-vb-finding__label">Models Tested</div><p class="gs-vb-finding__desc">The leaderboard compares frontier, coding-specialized, and open-weight model families on the same vulnerability repair workload.</p></div><div class="gs-vb-finding"><div class="gs-vb-finding__value">{top.total - top.passed}/200</div><div class="gs-vb-finding__label">Remaining Gap</div><p class="gs-vb-finding__desc">Even the leading model leaves most tasks without an accepted fix, underscoring how hard blind security patching remains.</p></div>"""
    else:
        hero_eyebrow = "VulnBench V2"
        hero_title = "Latest LLMs Against<br>Real Vulnerabilities"
        hero_desc = "We retested the latest frontier and specialist coding models on the curated VulnBench-200 subset using best-of-3 variance reduction, source context, description-only file hints, and the same judge workflow as the original report."
        findings_title = "What Changed In V2"
        findings_desc = "The same report structure is preserved: curated 200-instance leaderboard first, methodology and dataset context below, and no mixing with partial full-benchmark runs."
        result_title = "VulnBench-200 V2 Leaderboard"
        result_desc = "Curated 200-instance subset with best-of-3 runs, source context, description-only file hints, and Claude Opus 4.8 as judge."
        method_title = "Same Harness, New Models"
        method_desc = "V2 keeps the published report's evaluation shape and visual language while swapping in the refreshed OpenRouter model suite and checkpointed reruns."
        step3_title = "Best Of 3"
        step3_desc = "Each model gets three independent runs; the reported row is selected by pass rate and then mean score."
        judge_desc = "Claude Opus 4.8 compares candidate patches against reference fixes for root cause, safety, and scope."
        cta_title = "Reproduce The V2 Run"
        cta_desc = "The run artifacts are stored in results as best-of-3 JSON reports and individual run files."
        terminal_command = "./run_curated_200_best3.sh"
        footer_scope = "Best-of-3 Curated 200"
        finding_cards = f"""<div class="gs-vb-finding"><div class="gs-vb-finding__value">{percent(top.pass_rate)}</div><div class="gs-vb-finding__label">Best Pass Rate</div><p class="gs-vb-finding__desc">{html.escape(top.display)} leads the V2 curated retest with {top.passed}/200 passing patches and a {top.mean_score:.3f} mean judge score.</p></div><div class="gs-vb-finding"><div class="gs-vb-finding__value">{rows[1].passed}/200</div><div class="gs-vb-finding__label">Runner Up</div><p class="gs-vb-finding__desc">{html.escape(rows[1].display)} is second at {percent(rows[1].pass_rate)}, a {top_two_gap * 100:.1f}-point gap from the leader.</p></div><div class="gs-vb-finding"><div class="gs-vb-finding__value">{percent(median)}</div><div class="gs-vb-finding__label">Median Pass Rate</div><p class="gs-vb-finding__desc">The median latest-suite model still fixes only a small share of real CVEs, even with source context and three attempts.</p></div><div class="gs-vb-finding"><div class="gs-vb-finding__value">{top_score.mean_score:.3f}</div><div class="gs-vb-finding__label">Top Mean Score</div><p class="gs-vb-finding__desc">{html.escape(top_score.display)} has the highest mean judge score in this table.</p></div><div class="gs-vb-finding"><div class="gs-vb-finding__value">Best-of-3</div><div class="gs-vb-finding__label">Variance Reduced</div><p class="gs-vb-finding__desc">Each leaderboard row keeps the best of three independent runs by pass rate, using mean score as the tiebreaker.</p></div><div class="gs-vb-finding"><div class="gs-vb-finding__value">No Full Mix</div><div class="gs-vb-finding__label">Curated Only</div><p class="gs-vb-finding__desc">The V2 report intentionally uses the curated 200-instance benchmark only, matching the user's requested scope.</p></div>"""

    return f"""<!DOCTYPE html><html lang="en"> <head><meta charset="utf-8"><link rel="icon" type="image/svg+xml" href="./favicon.svg"><meta name="viewport" content="width=device-width"><meta name="description" content="VulnBench V2: latest frontier model retest on 200 real CVEs using best-of-3 evaluation."><link rel="preconnect" href="https://cdn.fonts.net" crossorigin><link href="https://cdn.jsdelivr.net/npm/geist@1.3.1/dist/fonts/geist-sans/style.min.css" rel="stylesheet"><link href="https://cdn.jsdelivr.net/npm/geist@1.3.1/dist/fonts/geist-mono/style.min.css" rel="stylesheet"><title>VulnBench V2 — Latest Model Retest</title><link rel="stylesheet" href="./_astro/index.DCZr0Mhq.css"></head> <body>
<header class="gs-nav"><div class="gs-nav__inner"><a href="/" class="gs-nav__pill" style="font-family:var(--gs-font-mono);font-size:12px;letter-spacing:.1em;color:#000;text-decoration:none">GHOST</a><nav class="gs-nav__links"><a href="#findings" class="gs-nav__link">[F] Findings</a><a href="#leaderboard" class="gs-nav__link">[L] Curated 200</a><a href="#methodology" class="gs-nav__link">[M] Methodology</a><a href="#dataset" class="gs-nav__link">[D] Dataset</a></nav><a href="/" class="gs-nav__link gs-nav__login">[V1] Original</a><button class="gs-nav__hamburger" id="gs-nav-toggle" aria-label="Toggle menu"><span></span><span></span><span></span></button></div><div class="gs-nav__mobile" id="gs-nav-mobile"><a href="#findings" class="gs-nav__link">[F] Findings</a><a href="#leaderboard" class="gs-nav__link">[L] Curated 200</a><a href="#methodology" class="gs-nav__link">[M] Methodology</a><a href="#dataset" class="gs-nav__link">[D] Dataset</a><a href="/" class="gs-nav__link">[V1] Original</a></div></header>
<section class="gs-vb-hero"><div class="gs-vb-hero__shader" id="gs-vb-hero-shader"></div><div class="gs-vb-hero__inner"><div class="gs-vb-hero__content"><div class="gs-vb-hero__eyebrow"><span>{hero_eyebrow}</span><span class="gs-vb-hero__eyebrow-sep">/</span><span>Ghost Security</span></div><h1 class="gs-vb-hero__title">{hero_title}</h1><p class="gs-vb-hero__desc">{hero_desc}</p></div></div></section>
<div class="gs-vb-stats"><div class="gs-vb-stats__inner"><div class="gs-vb-stats__item"><div class="gs-vb-stats__value">{complete_count}</div><div class="gs-vb-stats__label">Models Final</div></div><div class="gs-vb-stats__item"><div class="gs-vb-stats__value">200</div><div class="gs-vb-stats__label">Curated CVEs</div></div><div class="gs-vb-stats__item"><div class="gs-vb-stats__value">3x</div><div class="gs-vb-stats__label">Runs Per Model</div></div><div class="gs-vb-stats__item"><div class="gs-vb-stats__value">55</div><div class="gs-vb-stats__label">CWE Types</div></div><div class="gs-vb-stats__item"><div class="gs-vb-stats__value">7</div><div class="gs-vb-stats__label">Ecosystems</div></div></div></div>
<section class="gs-vb-findings" id="findings"><div class="gs-vb-findings__inner"><div class="gs-section-eyebrow">Key Findings</div><h2 class="gs-section-title">{findings_title}</h2><p class="gs-section-desc">{findings_desc}</p><div class="gs-vb-findings__grid">{finding_cards}</div></div></section>
<section class="gs-vb-leaderboard" id="leaderboard"><div class="gs-vb-leaderboard__inner"><div class="gs-vb-leaderboard__header"><div class="gs-section-eyebrow">Results</div><h2 class="gs-section-title">{result_title}</h2><p class="gs-section-desc">{result_desc}</p>{pending_note}</div><div class="gs-vb-leaderboard__wrap"><table><thead><tr><th style="width:48px">#</th><th>Model</th><th>Pass Rate</th><th>Score</th><th>Passed</th><th>Avg Time</th><th>Cost</th></tr></thead><tbody>{leaderboard_html(rows)}</tbody></table></div></div></section>
<section class="gs-vb-method" id="methodology"><div class="gs-vb-method__inner"><div class="gs-vb-method__grid"><div class="gs-vb-method__left"><div class="gs-section-eyebrow">Methodology</div><h2 class="gs-section-title">{method_title}</h2><p class="gs-section-desc">{method_desc}</p></div><div class="gs-vb-method__timeline"><div class="gs-vb-method__line"></div><div class="gs-vb-method__step"><div class="gs-vb-method__num">1</div><div class="gs-vb-method__step-body"><div class="gs-vb-method__step-title">Real CVEs</div><p class="gs-vb-method__step-desc">All models run against the same 200 vulnerability repair tasks drawn from real repositories and disclosed CVEs.</p></div></div><div class="gs-vb-method__step"><div class="gs-vb-method__num">2</div><div class="gs-vb-method__step-body"><div class="gs-vb-method__step-title">Source + Hints</div><p class="gs-vb-method__step-desc">Prompts include vulnerable source snippets and vulnerability-derived localization hints, but not the reference fix.</p></div></div><div class="gs-vb-method__step"><div class="gs-vb-method__num">3</div><div class="gs-vb-method__step-body"><div class="gs-vb-method__step-title">{step3_title}</div><p class="gs-vb-method__step-desc">{step3_desc}</p></div></div><div class="gs-vb-method__step"><div class="gs-vb-method__num">4</div><div class="gs-vb-method__step-body"><div class="gs-vb-method__step-title">Patch Judging</div><p class="gs-vb-method__step-desc">{judge_desc}</p></div></div></div></div></div></section>
<section class="gs-vb-dataset" id="dataset"><div class="gs-vb-dataset__inner"><div class="gs-section-eyebrow">Dataset</div><h2 class="gs-section-title">Benchmark Dataset</h2><p class="gs-section-desc">The benchmark uses 200 curated CVEs from 200 repositories, balanced across three difficulty tiers and spanning 55 CWE types.</p><div class="gs-vb-dataset__mini-stats"><div class="gs-vb-dataset__mini-stat"><div class="gs-vb-dataset__mini-val">200</div><div class="gs-vb-dataset__mini-label">CVE Tasks</div></div><div class="gs-vb-dataset__mini-stat"><div class="gs-vb-dataset__mini-val">200</div><div class="gs-vb-dataset__mini-label">Repositories</div></div><div class="gs-vb-dataset__mini-stat"><div class="gs-vb-dataset__mini-val">55</div><div class="gs-vb-dataset__mini-label">CWE Types</div></div><div class="gs-vb-dataset__mini-stat"><div class="gs-vb-dataset__mini-val">7</div><div class="gs-vb-dataset__mini-label">Ecosystems</div></div><div class="gs-vb-dataset__mini-stat"><div class="gs-vb-dataset__mini-val">36</div><div class="gs-vb-dataset__mini-label">Mean Lines</div></div><div class="gs-vb-dataset__mini-stat"><div class="gs-vb-dataset__mini-val">1.9</div><div class="gs-vb-dataset__mini-label">Mean Files</div></div></div></div></section>
<section class="gs-vb-cta"><div class="gs-vb-cta__shader" id="gs-vb-cta-shader"></div><div class="gs-vb-cta__inner"><div class="gs-vb-cta__left"><h2 class="gs-vb-cta__title">{cta_title}</h2><p class="gs-vb-cta__desc">{cta_desc}</p></div><div class="gs-vb-cta__right"><pre class="gs-vb-cta__terminal">$ {terminal_command}

  Subset     VulnBench-200
  Runs       best-of-3
  Judge      see row metadata
  Hints      description-only

  Leader     {top.display}
  Pass Rate  {percent(top.pass_rate)}
  Passed     {top.passed}/200</pre></div></div></section>
<footer class="gs-vb-footer"><div class="gs-vb-footer__inner"><div class="gs-vb-footer__bar"><div class="gs-vb-footer__links"><span>VulnBench V2</span><span class="sep">/</span><span>Ghost Security</span><span class="sep">/</span><span>{footer_scope}</span></div><div class="gs-vb-footer__note">Generated {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")} from benchmark result artifacts</div></div></div></footer><script type="module" src="./_astro/index.CKBdZHn6.js"></script></body></html>"""


def render_markdown(rows: list[Row], pending: list[str], manifest: dict | None = None) -> str:
    top = rows[0]
    pending_text = "None" if not pending else ", ".join(pending)
    if manifest:
        return f"""# VulnBench-200 Merged Harness-Fix Report

Merged leaderboard preserving the prior curated-200 best-of-3 baseline and replacing only rows with clear material improvement from the fixed adapter retry/empty-response harness.

## Summary

- Rows included: {len(rows)}
- Updated from fixed harness: {manifest.get("updated_count", 0)}
- Added new fixed-harness rows: {manifest.get("added_count", 0)}
- Carried forward from prior baseline: {manifest.get("kept_count", 0)}
- Leader: {top.display} at {percent(top.pass_rate)} ({top.passed}/200)
- Median pass rate: {percent(sorted(row.pass_rate for row in rows)[len(rows) // 2])}

## Merge Rule

- A prior row is replaced only when the fixed-harness row improves mean score by at least 0.02 and pass count by at least 1.
- New models with no prior 200-instance baseline are added as fixed-harness rows.
- Regressions and ambiguous changes are kept from the prior baseline, even if one metric improved.
- Fixed-harness rows used adapter exception retries, empty-response retries, and two judges: Claude Opus 4.8 plus GPT-5.5.
- Under the current consensus rule, a split two-judge vote passes when either judge votes pass.

## Leaderboard

{markdown_table(rows)}
"""

    return f"""# VulnBench V2 Report

Curated VulnBench-200 retest using best-of-3 runs, source context, description-only file hints, and Claude Opus 4.8 as judge.

## Summary

- Final models included: {len(rows)}
- Pending models: {pending_text}
- Leader: {top.display} at {percent(top.pass_rate)} ({top.passed}/200)
- Median pass rate: {percent(sorted(row.pass_rate for row in rows)[len(rows) // 2])}

## Leaderboard

{markdown_table(rows)}

## Notes

- Full 1,650-instance reruns were stopped and are not mixed into this report.
- Rows are selected by best run out of three using pass rate, then mean score as tiebreaker.
- Costs include generation and judge costs as recorded in each result artifact.
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=RESULTS,
        help="Directory containing result artifacts. If merged_leaderboard.json is present, it is used as the source of truth.",
    )
    args = parser.parse_args()

    results_dir = args.results_dir
    manifest = None
    if (results_dir / "merged_leaderboard.json").exists():
        rows, manifest = load_merged_rows(results_dir)
        pending = []
    else:
        if results_dir != RESULTS:
            raise SystemExit(f"{results_dir} does not contain merged_leaderboard.json")
        models = load_latest_models()
        for model in models:
            combine_completed_best3(model)

        rows = [row for model in models if (row := load_row(model))]
        rows.sort(key=lambda r: (r.pass_rate, r.mean_score), reverse=True)
        pending = pending_models(models)

    if not rows:
        raise SystemExit("No completed best3 results found")

    rendered_page = render_page(rows, pending, manifest)
    (DOCS / "v2.html").write_text(rendered_page)
    if manifest:
        (DOCS / "index.html").write_text(rendered_page)
    (RESULTS / "vulnbench_200_v2_report.md").write_text(render_markdown(rows, pending, manifest))
    print(f"wrote {DOCS / 'v2.html'}")
    if manifest:
        print(f"wrote {DOCS / 'index.html'}")
    print(f"wrote {RESULTS / 'vulnbench_200_v2_report.md'}")
    print(f"complete={len(rows)} pending={len(pending)}")


if __name__ == "__main__":
    main()
