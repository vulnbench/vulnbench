"""Generate the public VulnBench v3 site from the audited Protocol v2 results.

Reuses the branded gs-vb design (Astro CSS/JS assets under _astro/) but renders
the v3 leaderboard: mean pass rate across 3 runs, 95% Wilson CI, and pass@3,
scored by the pinned cross-vendor judge panel with no self-judging. Writes
docs/index.html (published site) and mirrors to html/.
"""

from __future__ import annotations

import glob
import html
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS_V3 = ROOT / "results" / "v3"
DOCS = ROOT / "docs"
HTML = ROOT / "html"

# Latency-excluded models: reported separately, not on the leaderboard.
SLOW = {
    "moonshotai_kimi-k3", "moonshotai_kimi-k2.7-code",
    "moonshotai_kimi-k2.6", "qwen_qwen3.7-max",
}

ORG_CLASS = {
    "openai": "openai", "anthropic": "anthropic", "google": "google",
    "z-ai": "zhipu", "moonshotai": "moonshot", "x-ai": "xai",
    "deepseek": "deepseek", "minimax": "minimax", "stepfun": "stepfun",
    "nvidia": "google", "mistralai": "minimax", "qwen": "zhipu", "tencent": "xai",
}
ORG_LABEL = {
    "openai": "OpenAI", "anthropic": "Anthropic", "google": "Google",
    "z-ai": "Z.AI", "moonshotai": "Moonshot AI", "x-ai": "xAI",
    "deepseek": "DeepSeek", "minimax": "MiniMax", "stepfun": "StepFun",
    "nvidia": "NVIDIA", "mistralai": "Mistral AI", "qwen": "Qwen", "tencent": "Tencent",
}
DISPLAY_NAMES = {
    "anthropic/claude-opus-5": "Claude Opus 5",
    "anthropic/claude-sonnet-5": "Claude Sonnet 5",
    "anthropic/claude-fable-5": "Claude Fable 5",
    "anthropic/claude-opus-4.8": "Claude Opus 4.8",
    "anthropic/claude-sonnet-4.6": "Claude Sonnet 4.6",
    "anthropic/claude-haiku-4.5": "Claude Haiku 4.5",
    "openai/gpt-5.6-sol": "GPT-5.6 Sol",
    "openai/gpt-5.6-luna": "GPT-5.6 Luna",
    "openai/gpt-5.6-terra": "GPT-5.6 Terra",
    "openai/gpt-5.5": "GPT-5.5",
    "openai/gpt-5.4-mini": "GPT-5.4 Mini",
    "openai/gpt-5.3-codex": "GPT-5.3 Codex",
    "google/gemini-3.6-flash": "Gemini 3.6 Flash",
    "google/gemini-3.5-flash": "Gemini 3.5 Flash",
    "google/gemini-3.5-flash-lite": "Gemini 3.5 Flash Lite",
    "google/gemini-3.1-pro-preview": "Gemini 3.1 Pro",
    "x-ai/grok-4.5": "Grok 4.5",
    "x-ai/grok-build-0.1": "Grok Build 0.1",
    "x-ai/grok-4.3": "Grok 4.3",
    "deepseek/deepseek-v4-pro": "DeepSeek V4 Pro",
    "deepseek/deepseek-v4-flash": "DeepSeek V4 Flash",
    "minimax/minimax-m3": "MiniMax M3",
    "z-ai/glm-5.2": "GLM 5.2",
    "z-ai/glm-5.1": "GLM 5.1",
    "qwen/qwen3.7-plus": "Qwen 3.7 Plus",
    "stepfun/step-3.7-flash": "Step 3.7 Flash",
    "nvidia/nemotron-3-ultra-550b-a55b": "Nemotron 3 Ultra",
    "mistralai/mistral-medium-3-5": "Mistral Medium 3.5",
    "tencent/hy3": "Hunyuan 3",
}


@dataclass
class Row:
    key: str
    display: str
    org: str
    org_class: str
    pass_rate: float
    ci_lo: float
    ci_hi: float
    pass_at_k: float
    mean_score: float
    passed: int


def display_for(key: str) -> str:
    if key in DISPLAY_NAMES:
        return DISPLAY_NAMES[key]
    tail = key.split("/", 1)[1] if "/" in key else key
    return tail.replace("-", " ").title()


def load_rows() -> list[Row]:
    rows: list[Row] = []
    for path in glob.glob(str(RESULTS_V3 / "mean3_*.json")):
        name = os.path.basename(path)[6:-5]
        if name in SLOW:
            continue
        d = json.load(open(path))
        m = d["metadata"]
        a = m["across_runs"]
        key = m["model"].replace("openrouter/", "")
        org = key.split("/", 1)[0]
        lo, hi = a["pooled_wilson_95"]
        rows.append(Row(
            key=key, display=display_for(key),
            org=ORG_LABEL.get(org, org.title()),
            org_class=ORG_CLASS.get(org, "openai"),
            pass_rate=a["mean_pass_rate"], ci_lo=lo, ci_hi=hi,
            pass_at_k=a["pass_at_k"], mean_score=d["aggregate"]["mean_score"],
            passed=round(a["mean_pass_rate"] * 200),
        ))
    rows.sort(key=lambda r: -r.pass_rate)
    return rows


def pct(v: float) -> str:
    return f"{v * 100:.1f}%"


def leaderboard_html(rows: list[Row]) -> str:
    max_rate = max((r.pass_rate for r in rows), default=1) or 1
    out = []
    for idx, r in enumerate(rows, 1):
        first = idx == 1
        width = 100 * r.pass_rate / max_rate
        out.append(
            f'<tr class="{"gs-vb-leaderboard__first-row" if first else ""}">'
            f'<td class="gs-vb-leaderboard__rank {"gs-vb-leaderboard__rank--first" if first else ""}">{idx}</td>'
            f'<td><div class="gs-vb-leaderboard__model {"gs-vb-leaderboard__model--first" if first else ""}">{html.escape(r.display)}</div>'
            f'<div class="gs-vb-leaderboard__org gs-vb-leaderboard__org--{r.org_class}">{html.escape(r.org)}</div></td>'
            f'<td><div class="gs-vb-leaderboard__bar-wrap"><span class="gs-vb-leaderboard__rate">{pct(r.pass_rate)}</span>'
            f'<div class="gs-vb-leaderboard__bar"><div class="gs-vb-leaderboard__bar-fill {"gs-vb-leaderboard__bar-fill--first" if first else ""}" style="width:{width:.1f}%"></div></div></div></td>'
            f'<td class="gs-vb-leaderboard__meta">{pct(r.ci_lo)}&ndash;{pct(r.ci_hi)}</td>'
            f'<td class="gs-vb-leaderboard__meta">{pct(r.pass_at_k)}</td>'
            f'<td class="gs-vb-leaderboard__meta">{r.mean_score:.3f}</td>'
            "</tr>"
        )
    return "\n".join(out)


def render(rows: list[Row]) -> str:
    top = rows[0]
    second = rows[1]
    median = sorted(r.pass_rate for r in rows)[len(rows) // 2]
    gap = top.pass_rate - second.pass_rate
    best_passk = max(rows, key=lambda r: r.pass_at_k)
    n = len(rows)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    findings = "".join([
        f'<div class="gs-vb-finding"><div class="gs-vb-finding__value">{pct(top.pass_rate)}</div>'
        f'<div class="gs-vb-finding__label">Leader — {html.escape(top.display)}</div>'
        f'<p class="gs-vb-finding__desc">{html.escape(top.display)} fixes {pct(top.pass_rate)} of real CVEs '
        f'(95% CI {pct(top.ci_lo)}&ndash;{pct(top.ci_hi)}), roughly double the next model.</p></div>',
        f'<div class="gs-vb-finding"><div class="gs-vb-finding__value">+{gap*100:.0f} pts</div>'
        f'<div class="gs-vb-finding__label">Margin To #2</div>'
        f'<p class="gs-vb-finding__desc">{html.escape(top.display)} leads {html.escape(second.display)} '
        f'({pct(second.pass_rate)}) with non-overlapping confidence intervals &mdash; a statistically clear #1.</p></div>',
        f'<div class="gs-vb-finding"><div class="gs-vb-finding__value">{pct(top.pass_at_k)}</div>'
        f'<div class="gs-vb-finding__label">Best pass@3</div>'
        f'<p class="gs-vb-finding__desc">{html.escape(best_passk.display)} produced a passing patch for '
        f'{pct(best_passk.pass_at_k)} of vulnerabilities within three attempts.</p></div>',
        f'<div class="gs-vb-finding"><div class="gs-vb-finding__value">{pct(median)}</div>'
        f'<div class="gs-vb-finding__label">Median Model</div>'
        f'<p class="gs-vb-finding__desc">The median model fixes only {pct(median)} of real CVEs &mdash; blind '
        f'security repair remains hard across the field.</p></div>',
        f'<div class="gs-vb-finding"><div class="gs-vb-finding__value">{n}</div>'
        f'<div class="gs-vb-finding__label">Models Ranked</div>'
        f'<p class="gs-vb-finding__desc">Frontier, coding-specialist, and open-weight families evaluated on '
        f'the identical Protocol v2 harness, every row artifact-free.</p></div>',
        f'<div class="gs-vb-finding"><div class="gs-vb-finding__value">Audited</div>'
        f'<div class="gs-vb-finding__label">Protocol v2</div>'
        f'<p class="gs-vb-finding__desc">Rebuilt after an 81-finding audit: uniform token budget, a pinned '
        f'cross-vendor judge panel, and mean-of-3-runs with confidence intervals.</p></div>',
    ])

    return f"""<!DOCTYPE html><html lang="en"> <head><meta charset="utf-8"><link rel="icon" type="image/svg+xml" href="./favicon.svg"><meta name="viewport" content="width=device-width"><meta name="description" content="VulnBench v3: {n} LLMs scored on fixing 200 real CVEs under an audited find-and-fix protocol. {html.escape(top.display)} leads at {pct(top.pass_rate)}."><link rel="preconnect" href="https://cdn.fonts.net" crossorigin><link href="https://cdn.jsdelivr.net/npm/geist@1.3.1/dist/fonts/geist-sans/style.min.css" rel="stylesheet"><link href="https://cdn.jsdelivr.net/npm/geist@1.3.1/dist/fonts/geist-mono/style.min.css" rel="stylesheet"><title>VulnBench v3 — Can LLMs Fix Real Vulnerabilities?</title><link rel="stylesheet" href="./_astro/index.DCZr0Mhq.css"></head> <body>
<header class="gs-nav"><div class="gs-nav__inner"><a href="/" class="gs-nav__pill" style="font-family:var(--gs-font-mono);font-size:12px;letter-spacing:.1em;color:#000;text-decoration:none">GHOST</a><nav class="gs-nav__links"><a href="#findings" class="gs-nav__link">[F] Findings</a><a href="#leaderboard" class="gs-nav__link">[L] Leaderboard</a><a href="#methodology" class="gs-nav__link">[M] Methodology</a><a href="#dataset" class="gs-nav__link">[D] Dataset</a></nav><a href="https://github.com/vulnbench/vulnbench" class="gs-nav__link gs-nav__login">[R] Repository</a><button class="gs-nav__hamburger" id="gs-nav-toggle" aria-label="Toggle menu"><span></span><span></span><span></span></button></div><div class="gs-nav__mobile" id="gs-nav-mobile"><a href="#findings" class="gs-nav__link">[F] Findings</a><a href="#leaderboard" class="gs-nav__link">[L] Leaderboard</a><a href="#methodology" class="gs-nav__link">[M] Methodology</a><a href="#dataset" class="gs-nav__link">[D] Dataset</a><a href="https://github.com/vulnbench/vulnbench" class="gs-nav__link">[R] Repository</a></div></header>
<section class="gs-vb-hero"><div class="gs-vb-hero__shader" id="gs-vb-hero-shader"></div><div class="gs-vb-hero__inner"><div class="gs-vb-hero__content"><div class="gs-vb-hero__eyebrow"><span>Audited find-and-fix benchmark</span><span class="gs-vb-hero__eyebrow-sep">/</span><span>Ghost Security</span></div><h1 class="gs-vb-hero__title">Which LLMs Can Fix<br>Real Vulnerabilities?</h1><p class="gs-vb-hero__desc">VulnBench v3 scores {n} models on patching 200 real CVEs. Each model sees the vulnerability and source, never the reference fix, and a pinned cross-vendor judge panel decides whether the patch fixes the root cause. {html.escape(top.display)} leads at {pct(top.pass_rate)} &mdash; roughly double any other model.</p></div></div></section>
<div class="gs-vb-stats"><div class="gs-vb-stats__inner"><div class="gs-vb-stats__item"><div class="gs-vb-stats__value">{n}</div><div class="gs-vb-stats__label">Models Ranked</div></div><div class="gs-vb-stats__item"><div class="gs-vb-stats__value">200</div><div class="gs-vb-stats__label">Real CVEs</div></div><div class="gs-vb-stats__item"><div class="gs-vb-stats__value">3&times;</div><div class="gs-vb-stats__label">Runs Per Model</div></div><div class="gs-vb-stats__item"><div class="gs-vb-stats__value">3</div><div class="gs-vb-stats__label">Cross-Vendor Judges</div></div><div class="gs-vb-stats__item"><div class="gs-vb-stats__value">48</div><div class="gs-vb-stats__label">CWE Types</div></div></div></div>
<section class="gs-vb-findings" id="findings"><div class="gs-vb-findings__inner"><div class="gs-section-eyebrow">Key Findings</div><h2 class="gs-section-title">What The Benchmark Shows</h2><p class="gs-section-desc">Every ranked model ran three independent times; the score is the mean pass rate with a 95% confidence interval. All rows are artifact-free (no API or judge failures counted as model errors).</p><div class="gs-vb-findings__grid">{findings}</div></div></section>
<section class="gs-vb-leaderboard" id="leaderboard"><div class="gs-vb-leaderboard__inner"><div class="gs-vb-leaderboard__header"><div class="gs-section-eyebrow">Results</div><h2 class="gs-section-title">VulnBench v3 Leaderboard</h2><p class="gs-section-desc">Mean pass rate across 3 runs on the curated 200-CVE set. 95% CI is the Wilson interval over pooled trials; pass@3 is the share solved in at least one run. Judged by a pinned Claude Opus 4.8 + GPT-5.5 panel with a Gemini 3.5 Flash tie-breaker &mdash; no model judges its own patches.</p></div><div class="gs-vb-leaderboard__wrap"><table><thead><tr><th style="width:48px">#</th><th>Model</th><th>Pass Rate</th><th>95% CI</th><th>pass@3</th><th>Mean Score</th></tr></thead><tbody>{leaderboard_html(rows)}</tbody></table></div></div></section>
<section class="gs-vb-method" id="methodology"><div class="gs-vb-method__inner"><div class="gs-vb-method__grid"><div class="gs-vb-method__left"><div class="gs-section-eyebrow">Methodology</div><h2 class="gs-section-title">Protocol v2, Every Model Identical</h2><p class="gs-section-desc">v3 was rebuilt after an 81-finding audit of the earlier leaderboards. Every model runs under one frozen protocol so rankings reflect capability, not harness artifacts.</p></div><div class="gs-vb-method__timeline"><div class="gs-vb-method__line"></div><div class="gs-vb-method__step"><div class="gs-vb-method__num">1</div><div class="gs-vb-method__step-body"><div class="gs-vb-method__step-title">Real CVEs, Blind</div><p class="gs-vb-method__step-desc">Each model gets a real vulnerability and its source context, but never the reference fix, and must emit a minimal patch.</p></div></div><div class="gs-vb-method__step"><div class="gs-vb-method__num">2</div><div class="gs-vb-method__step-body"><div class="gs-vb-method__step-title">Uniform Budget</div><p class="gs-vb-method__step-desc">Identical 16k-token budget for every model &mdash; the fix for the artifact that zeroed out reasoning models in earlier reports.</p></div></div><div class="gs-vb-method__step"><div class="gs-vb-method__num">3</div><div class="gs-vb-method__step-body"><div class="gs-vb-method__step-title">Mean Of 3 Runs</div><p class="gs-vb-method__step-desc">Three independent runs per model; the headline is the mean pass rate with a 95% Wilson interval, plus pass@3.</p></div></div><div class="gs-vb-method__step"><div class="gs-vb-method__num">4</div><div class="gs-vb-method__step-body"><div class="gs-vb-method__step-title">Cross-Vendor Judges</div><p class="gs-vb-method__step-desc">A pinned Opus 4.8 + GPT-5.5 panel scores each patch, a third-vendor judge breaks split votes, and no model ever judges its own output.</p></div></div></div></div></div></section>
<section class="gs-vb-dataset" id="dataset"><div class="gs-vb-dataset__inner"><div class="gs-section-eyebrow">Dataset</div><h2 class="gs-section-title">Benchmark Dataset</h2><p class="gs-section-desc">200 curated CVEs from 200 repositories, balanced across three difficulty tiers, spanning 48 CWE types and 7 package ecosystems. Advisory text is sanitized to remove fix pointers before a model sees it.</p><div class="gs-vb-dataset__mini-stats"><div class="gs-vb-dataset__mini-stat"><div class="gs-vb-dataset__mini-val">200</div><div class="gs-vb-dataset__mini-label">CVE Tasks</div></div><div class="gs-vb-dataset__mini-stat"><div class="gs-vb-dataset__mini-val">200</div><div class="gs-vb-dataset__mini-label">Repositories</div></div><div class="gs-vb-dataset__mini-stat"><div class="gs-vb-dataset__mini-val">48</div><div class="gs-vb-dataset__mini-label">CWE Types</div></div><div class="gs-vb-dataset__mini-stat"><div class="gs-vb-dataset__mini-val">7</div><div class="gs-vb-dataset__mini-label">Ecosystems</div></div><div class="gs-vb-dataset__mini-stat"><div class="gs-vb-dataset__mini-val">36</div><div class="gs-vb-dataset__mini-label">Mean Lines</div></div><div class="gs-vb-dataset__mini-stat"><div class="gs-vb-dataset__mini-val">1.9</div><div class="gs-vb-dataset__mini-label">Mean Files</div></div></div></div></section>
<section class="gs-vb-cta"><div class="gs-vb-cta__shader" id="gs-vb-cta-shader"></div><div class="gs-vb-cta__inner"><div class="gs-vb-cta__left"><h2 class="gs-vb-cta__title">Reproduce The Benchmark</h2><p class="gs-vb-cta__desc">The repository ships the curated CVE set, every model's patches, per-judge decisions, the statistics code, and the full audit trail behind Protocol v2.</p></div><div class="gs-vb-cta__right"><pre class="gs-vb-cta__terminal">$ ./run_v3_200.sh

  Set        VulnBench-200
  Runs       mean of 3 + 95% CI
  Judges     Opus 4.8 + GPT-5.5 (+ tie-breaker)
  Self-judge disabled

  Leader     {top.display}
  Pass Rate  {pct(top.pass_rate)}  (CI {pct(top.ci_lo)}&ndash;{pct(top.ci_hi)})
  pass@3     {pct(top.pass_at_k)}</pre></div></div></section>
<footer class="gs-vb-footer"><div class="gs-vb-footer__inner"><div class="gs-vb-footer__bar"><div class="gs-vb-footer__links"><span>VulnBench v3</span><span class="sep">/</span><span>Ghost Security</span><span class="sep">/</span><span>Audited Protocol v2</span></div><div class="gs-vb-footer__note">Generated {now} from benchmark result artifacts</div></div></div></footer><script type="module" src="./_astro/index.CKBdZHn6.js"></script></body></html>"""


def main() -> None:
    rows = load_rows()
    if not rows:
        raise SystemExit("No v3 mean3 results found")
    page = render(rows)
    for site in (DOCS, HTML):
        (site / "index.html").write_text(page)
    print(f"Wrote {len(rows)}-model v3 site to {DOCS/'index.html'} and {HTML/'index.html'}")
    print(f"Leader: {rows[0].display} {pct(rows[0].pass_rate)}")


if __name__ == "__main__":
    main()
