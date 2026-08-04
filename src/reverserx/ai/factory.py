"""Factory for the sole DeepSeek provider."""

from __future__ import annotations

from reverserx.ai.providers import DeepSeekProvider
from reverserx.config import Settings


def build_provider(settings: Settings) -> DeepSeekProvider | None:
    """Create the DeepSeek provider if an API key is configured."""
    if settings.deepseek_api_key is None:
        return None
    return DeepSeekProvider(
        api_key=settings.deepseek_api_key.get_secret_value(),
        model=settings.deepseek_model,
        base_url=settings.deepseek_base_url,
        timeout_seconds=settings.provider_timeout_seconds,
    )
