"""Configured provider registry for the application boundary."""

from __future__ import annotations

from reverserx.ai.models import Modality, ModelCapability, PrivacyLocation
from reverserx.ai.providers import (
    DeepSeekProvider,
    OllamaProvider,
    OpenAIResponsesProvider,
    ProviderRegistry,
)
from reverserx.config import Settings


def build_provider_registry(settings: Settings) -> ProviderRegistry:
    providers = ProviderRegistry()
    ollama_modalities = {Modality.TEXT, Modality.CODE, Modality.ARTIFACT}
    if settings.ollama_image_support:
        ollama_modalities.add(Modality.IMAGE)
    providers.register(
        OllamaProvider(
            ModelCapability(
                provider="ollama",
                model=settings.ollama_model,
                modalities=frozenset(ollama_modalities),
                privacy_location=PrivacyLocation.LOCAL,
                context_limit=131_072,
                structured_output=True,
                tool_calling=True,
                quality_priority=10,
            ),
            base_url=settings.ollama_base_url,
            timeout_seconds=settings.provider_timeout_seconds,
        )
    )
    if settings.hosted_models_enabled and settings.deepseek_api_key is not None:
        providers.register(
            DeepSeekProvider(
                ModelCapability(
                    provider="deepseek",
                    model=settings.deepseek_model,
                    modalities=frozenset({Modality.TEXT, Modality.CODE, Modality.ARTIFACT}),
                    privacy_location=PrivacyLocation.HOSTED,
                    context_limit=131_072,
                    structured_output=True,
                    tool_calling=True,
                    quality_priority=80,
                    input_cost_per_million=(settings.deepseek_input_cost_per_million),
                    output_cost_per_million=(settings.deepseek_output_cost_per_million),
                    image_cost_per_million=0,
                ),
                settings.deepseek_api_key.get_secret_value(),
                base_url=settings.deepseek_base_url,
                timeout_seconds=settings.provider_timeout_seconds,
            )
        )
    if settings.hosted_models_enabled and settings.openai_api_key is not None:
        providers.register(
            OpenAIResponsesProvider(
                ModelCapability(
                    provider="openai",
                    model=settings.openai_model,
                    modalities=frozenset(Modality),
                    privacy_location=PrivacyLocation.HOSTED,
                    context_limit=1_050_000,
                    structured_output=True,
                    tool_calling=True,
                    quality_priority=100,
                    input_cost_per_million=(settings.openai_input_cost_per_million),
                    output_cost_per_million=(settings.openai_output_cost_per_million),
                    image_cost_per_million=(settings.openai_image_cost_per_million),
                ),
                settings.openai_api_key.get_secret_value(),
                base_url=settings.openai_base_url,
                timeout_seconds=settings.provider_timeout_seconds,
            )
        )
    return providers
