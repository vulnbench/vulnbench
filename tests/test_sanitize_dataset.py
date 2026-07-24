"""Regression tests for the advisory sanitizer.

These pin the leakage classes found in the 2026-07 audit: fix-commit SHAs,
patch URLs, fix/remediation sections at any header level, "fixed by"
phrasing, and the hex regex that used to mangle legacy CVE IDs.
"""

import json
import re
import unittest
from pathlib import Path

from benchmark.sanitize_dataset import scrub_advisory_text

DATASET_200 = Path("data/benchmark/vulnbench_200.json")


class ScrubAdvisoryTextTests(unittest.TestCase):
    def test_removes_fix_sections_at_any_header_level(self):
        text = (
            "A serious bug exists in the parser that allows attacker-controlled "
            "input to reach eval() and execute arbitrary code in the host process.\n"
            "## Fix Commit(s)\n- `732e53151e8fbdfc0501182ddb0e900878bdc1e3`\n"
            "### Remediation Advice\nUpgrade now.\n"
            "# Patches and Workarounds\nApply the patch.\n"
            "## Impact\nRemote code execution."
        )
        scrubbed = scrub_advisory_text(text)
        self.assertNotIn("732e5315", scrubbed)
        self.assertNotIn("Remediation", scrubbed)
        self.assertNotIn("Patches", scrubbed)
        self.assertIn("Impact", scrubbed)

    def test_redacts_commit_hashes_but_not_long_numbers(self):
        text = (
            "The vulnerability CVE-2017-1000220 in build 20240115 was introduced "
            "by commit deadbeefcafe1234 affecting issue 12345678 in the tracker. "
            "Exploitation allows reading arbitrary files from the host system "
            "through crafted path traversal sequences in archive entries."
        )
        scrubbed = scrub_advisory_text(text)
        self.assertIn("CVE-2017-1000220", scrubbed)
        self.assertIn("20240115", scrubbed)
        self.assertIn("12345678", scrubbed)
        self.assertNotIn("deadbeefcafe1234", scrubbed)

    def test_removes_fixed_by_and_upgrade_phrases(self):
        text = (
            "A prototype pollution vulnerability exists in the merge helper and "
            "allows attackers to inject properties into Object.prototype via "
            "crafted JSON payloads sent to the configuration endpoint. "
            "This issue was fixed by adding a hasOwnProperty guard in merge(). "
            "Upgrading to version 1.0.4 can resolve this issue."
        )
        scrubbed = scrub_advisory_text(text)
        self.assertNotIn("fixed by adding", scrubbed)
        self.assertNotIn("1.0.4", scrubbed)
        self.assertIn("prototype pollution", scrubbed.lower())

    def test_redacts_urls(self):
        text = (
            "Path traversal in tar extraction allows writing outside the target "
            "directory when entry names contain dot-dot sequences. See "
            "https://github.com/example/repo/commit/abcdef1234567890 for details "
            "and https://example.com/advisory for the writeup."
        )
        scrubbed = scrub_advisory_text(text)
        self.assertNotIn("http", scrubbed)


@unittest.skipUnless(DATASET_200.exists(), "published dataset not present")
class PublishedDatasetLeakageTests(unittest.TestCase):
    """The shipped 200-instance set must stay free of fix leakage."""

    @classmethod
    def setUpClass(cls):
        data = json.loads(DATASET_200.read_text())
        cls.descriptions = [
            i["task_prompt"]["vulnerability_description"] for i in data["instances"]
        ]
        cls.joined = "\n".join(cls.descriptions)

    def test_no_commit_shas(self):
        self.assertEqual(
            re.findall(r"\b(?=[0-9a-f]*[a-f])[0-9a-f]{40}\b", self.joined), []
        )

    def test_no_live_urls(self):
        self.assertEqual(re.findall(r"https?://\S+", self.joined), [])

    def test_no_fix_sections(self):
        matches = re.findall(
            r"(?m)^#{1,6}\s*(?:recommended\s+)?(?:patch|fix|remediation|"
            r"reference|resource|resolution|workaround|solution|mitigation)",
            self.joined,
            re.IGNORECASE,
        )
        self.assertEqual(matches, [])

    def test_no_mangled_cve_ids(self):
        self.assertEqual(re.findall(r"CVE-\d{4}-\[redacted\]", self.joined), [])

    def test_no_empty_descriptions(self):
        empty = [d for d in self.descriptions if len(d.strip()) < 20]
        self.assertEqual(empty, [])


if __name__ == "__main__":
    unittest.main()
