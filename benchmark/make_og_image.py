"""Generate the 1200x630 social-share card (og:image) for the v3 site.

Reads the current leader from the v3 results so the card headline always
matches the live leaderboard. Writes docs/og-image.png and html/og-image.png.
"""

from __future__ import annotations

import glob
import json
import os
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
RESULTS_V3 = ROOT / "results" / "v3"
SLOW = {"moonshotai_kimi-k3", "moonshotai_kimi-k2.7-code",
        "moonshotai_kimi-k2.6", "qwen_qwen3.7-max"}

W, H = 1200, 630
BG = (246, 247, 249)
INK = (15, 17, 21)
MUTE = (110, 116, 128)
AMBER = (245, 158, 11)
CARD = (255, 255, 255)
LINE = (226, 229, 234)

DISPLAY = {
    "anthropic/claude-opus-5": "Claude Opus 5",
    "openai/gpt-5.6-sol": "GPT-5.6 Sol",
}

FONTS = [
    "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
]


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    path = FONTS[0] if bold else FONTS[1]
    try:
        return ImageFont.truetype(path, size)
    except OSError:
        return ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", size)


def leader() -> tuple[str, float, int]:
    best = None
    for p in glob.glob(str(RESULTS_V3 / "mean3_*.json")):
        if os.path.basename(p)[6:-5] in SLOW:
            continue
        d = json.load(open(p))
        key = d["metadata"]["model"].replace("openrouter/", "")
        rate = d["metadata"]["across_runs"]["mean_pass_rate"]
        if best is None or rate > best[1]:
            best = (DISPLAY.get(key, key.split("/")[-1]), rate,
                    len([1]))
    n = len([p for p in glob.glob(str(RESULTS_V3 / "mean3_*.json"))
             if os.path.basename(p)[6:-5] not in SLOW])
    return best[0], best[1], n


def spaced(text: str, gap: str = " ") -> str:
    return gap.join(text)


def main() -> None:
    name, rate, n = leader()
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # left accent rail
    d.rectangle([0, 0, 12, H], fill=AMBER)

    # eyebrow
    d.text((70, 74), spaced("GHOST SECURITY"), font=font(22, True), fill=MUTE)
    d.text((70, 74 + 30), spaced("AUDITED FIND-AND-FIX BENCHMARK"),
           font=font(18), fill=MUTE)

    # title
    d.text((68, 150), "VulnBench v3", font=font(104, True), fill=INK)

    # subtitle
    d.text((70, 286), "Can LLMs fix real-world vulnerabilities?",
           font=font(38), fill=(60, 66, 78))

    # leader highlight card
    card_y = 372
    d.rounded_rectangle([70, card_y, W - 70, card_y + 128], radius=18,
                        fill=CARD, outline=LINE, width=2)
    d.rectangle([70, card_y + 18, 78, card_y + 110], fill=AMBER)
    d.text((108, card_y + 26), "LEADER", font=font(20, True), fill=MUTE)
    d.text((108, card_y + 54), name, font=font(46, True), fill=INK)
    rate_txt = f"{rate*100:.1f}%"
    rw = d.textlength(rate_txt, font=font(72, True))
    d.text((W - 70 - 44 - rw, card_y + 30), rate_txt, font=font(72, True), fill=AMBER)

    # footer
    d.text((70, H - 62),
           f"{n} models  ·  200 real CVEs  ·  best-of-3  ·  cross-vendor judges",
           font=font(24), fill=MUTE)
    url = "vulnbench.ghostsecurity.com"
    uw = d.textlength(url, font=font(24, True))
    d.text((W - 70 - uw, H - 62), url, font=font(24, True), fill=INK)

    for site in ("docs", "html"):
        out = ROOT / site / "og-image.png"
        img.save(out, "PNG")
        print(f"wrote {out}")
    print(f"leader on card: {name} {rate_txt} ({n} models)")


if __name__ == "__main__":
    main()
