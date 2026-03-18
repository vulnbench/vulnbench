"""Base model adapter protocol and dummy adapter for testing."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class ModelAdapter(Protocol):
    """Protocol for model adapters used in VulnBench evaluation.

    Implementations must provide a generate_patch method that takes a
    prompt string and returns a unified diff string.
    """

    def generate_patch(self, prompt: str) -> str:
        """Generate a patch given a vulnerability description prompt.

        Args:
            prompt: The rendered task prompt describing the vulnerability.

        Returns:
            A string containing a unified diff that fixes the vulnerability.
        """
        ...


class DummyAdapter:
    """Dummy adapter that returns an empty patch. Used for testing the harness."""

    def generate_patch(self, prompt: str) -> str:
        return (
            "diff --git a/dummy.py b/dummy.py\n"
            "--- a/dummy.py\n"
            "+++ b/dummy.py\n"
            "@@ -1,3 +1,3 @@\n"
            " # placeholder\n"
            "-# vulnerable code\n"
            "+# fixed code\n"
            " # end\n"
        )
