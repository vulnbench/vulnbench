"""Sanitize benchmark JSON files to remove advisory leakage and gold file hints."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

# A section is scrubbed when its header BEGINS with any of these words —
# advisories use many variants ("Fix Commit(s)", "Remediation Advice",
# "Patches and Workarounds", "References and Prior work").
SCRUB_HEADER_PREFIX_RE = re.compile(
    r"^(?:recommended\s+)?"
    r"(?:patch(?:es)?|fix(?:es)?|remediation|references?|resources?|"
    r"resolution|workarounds?|solutions?|mitigations?)\b",
    re.IGNORECASE,
)

# Markdown headers at any level (#..######), e.g. "## Patches", "### Remediation"
SECTION_HEADER_RE = re.compile(r"^(#{1,6})\s*(.+?)\s*:?\s*$")

SCRUB_LINE_PATTERNS = [
    re.compile(r"https?://\S*(?:/commit/|\.patch\b)\S*", re.IGNORECASE),
    re.compile(r"\b(?:fixed|patched|addressed)\s+in\s+version\b", re.IGNORECASE),
    re.compile(r"\b(?:fixed|patched|addressed)\s+in\b", re.IGNORECASE),
    re.compile(r"\bupgrad(?:e|ing)\s+to\b", re.IGNORECASE),
]

# A commit hash needs at least one a-f letter; otherwise 7+ digit decimal
# tokens (legacy CVE suffixes like CVE-2017-1000220, issue numbers,
# timestamps) get mangled into [redacted].
COMMIT_HASH_RE = re.compile(r"\b(?=[0-9a-f]*[a-f])[0-9a-f]{7,40}\b")
SCRUB_REPLACEMENTS = [
    (
        re.compile(r"\b(?:identifier|name) of the patch is\b.*?(?:\.|$)", re.IGNORECASE),
        "",
    ),
    (
        re.compile(r"\bit is recommended to apply a patch to fix this issue\.?", re.IGNORECASE),
        "",
    ),
    (
        re.compile(r"\b(?:the )?patch can be viewed and applied from the following link:.*?(?:\.|$)", re.IGNORECASE),
        "",
    ),
    (
        re.compile(r"\b(?:recommended|best|only) course of action is to apply the provided patch.*?(?:\.|$)", re.IGNORECASE),
        "",
    ),
    (
        re.compile(
            r"\b(?:this (?:issue|vulnerability|problem) )?(?:was|is|has been|can be)\s+"
            r"(?:fixed|resolved|patched|addressed)\s+by\b.*?(?:\.|$)",
            re.IGNORECASE,
        ),
        "",
    ),
    (
        re.compile(
            r"\bupgrad(?:e|ing)\s+to\s+(?:version\s+)?[A-Za-z0-9._,\s-]+"
            r"(?:can|will|to)?\s*(?:resolve|fix|address|mitigate)[^.]*\.?",
            re.IGNORECASE,
        ),
        "",
    ),
]


def scrub_advisory_text(text: str) -> str:
    if not text:
        return ""

    scrubbed = _scrub_advisory_lines(text, strict=True)
    if len(scrubbed) < 80:
        scrubbed = _scrub_advisory_lines(text, strict=False)
    if len(scrubbed) < 80:
        scrubbed = _scrub_advisory_minimal(text)
    scrubbed = re.sub(r"\n{3,}", "\n\n", scrubbed)
    return scrubbed.strip()


def _scrub_advisory_lines(text: str, *, strict: bool) -> str:
    scrubbed_lines: list[str] = []
    skip_section = False

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        header_match = SECTION_HEADER_RE.match(stripped)
        if header_match:
            header = header_match.group(2).strip()
            skip_section = bool(SCRUB_HEADER_PREFIX_RE.match(header))
            if skip_section:
                continue

        if skip_section:
            continue

        cleaned = COMMIT_HASH_RE.sub("[redacted]", line)
        cleaned = re.sub(r"https?://\S+", "[redacted-url]", cleaned)
        for pattern, replacement in SCRUB_REPLACEMENTS:
            cleaned = pattern.sub(replacement, cleaned)
        cleaned = re.sub(
            r"\b(?:versions?|releases?)\s+(?:before|prior to)\s+[A-Za-z0-9._:-]+\b",
            "affected versions before [redacted-version]",
            cleaned,
            flags=re.IGNORECASE,
        )
        cleaned = re.sub(
            r"\b(?:fixed|patched|addressed)\s+in\s+[A-Za-z0-9._:-]+\b",
            "fixed in [redacted-version]",
            cleaned,
            flags=re.IGNORECASE,
        )
        if strict and any(p.search(cleaned) for p in SCRUB_LINE_PATTERNS):
            continue
        cleaned = cleaned.strip()
        if not cleaned:
            continue
        scrubbed_lines.append(cleaned)

    return "\n".join(scrubbed_lines)


def _scrub_advisory_minimal(text: str) -> str:
    cleaned = COMMIT_HASH_RE.sub("[redacted]", text)
    cleaned = re.sub(r"https?://\S+", "[redacted-url]", cleaned)
    for pattern, replacement in SCRUB_REPLACEMENTS:
        cleaned = pattern.sub(replacement, cleaned)
    cleaned = re.sub(
        r"\b(?:versions?|releases?)\s+(?:before|prior to)\s+[A-Za-z0-9._:-]+\b",
        "affected versions before [redacted-version]",
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(
        r"\b(?:fixed|patched|addressed)\s+in\s+[A-Za-z0-9._:-]+\b",
        "fixed in [redacted-version]",
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def sanitize_dataset(path: Path, *, clear_gold_hints: bool) -> None:
    data = json.loads(path.read_text())
    instances = data.get("instances", [])

    for instance in instances:
        task_prompt = instance.get("task_prompt", {})
        description = task_prompt.get("vulnerability_description", "")
        task_prompt["vulnerability_description"] = scrub_advisory_text(description)
        if clear_gold_hints:
            task_prompt["affected_files_hint"] = []
        task_prompt.setdefault("source_context", "")
        task_prompt.setdefault("source_context_files", [])

    metadata = data.setdefault("metadata", {})
    metadata["sanitized_for_prompt_leakage"] = True
    metadata["affected_files_hint_policy"] = "cleared" if clear_gold_hints else "retained"

    path.write_text(json.dumps(data, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Sanitize VulnBench dataset files")
    parser.add_argument("paths", nargs="+", help="Benchmark JSON paths to rewrite")
    parser.add_argument(
        "--clear-gold-hints",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Clear affected_files_hint values derived from gold patches",
    )
    args = parser.parse_args()

    for raw_path in args.paths:
        sanitize_dataset(Path(raw_path), clear_gold_hints=args.clear_gold_hints)
        print(f"Sanitized {raw_path}")


if __name__ == "__main__":
    main()
