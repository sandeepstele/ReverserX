"""Single-provider model router — DeepSeek only."""

from __future__ import annotations

from reverserx.ai.models import ModelRequest, ModelResponse
from reverserx.ai.providers import DeepSeekProvider


class ModelRouter:
    """Routes all model requests to DeepSeek."""

    def __init__(self, provider: DeepSeekProvider) -> None:
        self._provider = provider

    def generate(self, request: ModelRequest) -> ModelResponse:
        return self._provider.generate(request)

    def estimate(self) -> dict[str, object]:
        return {
            "provider": "deepseek",
            "model": self._provider.model,
            "note": "DeepSeek is the sole provider — no routing needed.",
        }
