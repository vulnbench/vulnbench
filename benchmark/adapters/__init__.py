"""Model adapters for VulnBench evaluation."""

from benchmark.adapters.base import DummyAdapter, ModelAdapter

__all__ = ["DummyAdapter", "LiteLLMAdapter", "ModelAdapter"]


def __getattr__(name: str):
    if name == "LiteLLMAdapter":
        from benchmark.adapters.litellm_adapter import LiteLLMAdapter

        return LiteLLMAdapter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
