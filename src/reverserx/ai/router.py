"""Capability-first model routing and deterministic cost estimates."""

from __future__ import annotations

from reverserx.ai.models import (
    CostEstimate,
    ModelCapability,
    ModelRequest,
    PrivacyLocation,
    ProjectModelPolicy,
    estimate_text_tokens,
)


class RoutingError(ValueError):
    """Raised when no model can satisfy capability and privacy requirements."""


class ModelRouter:
    def __init__(self, capabilities: tuple[ModelCapability, ...]) -> None:
        if not capabilities:
            raise ValueError("at least one model capability is required")
        self.capabilities = capabilities

    def route(
        self, request: ModelRequest, policy: ProjectModelPolicy
    ) -> ModelCapability:
        eligible: list[ModelCapability] = []
        for capability in self.capabilities:
            if not request.modalities.issubset(capability.modalities):
                continue
            if request.output_schema is not None and not capability.structured_output:
                continue
            if capability.privacy_location == PrivacyLocation.HOSTED:
                if policy.local_only or not policy.hosted_enabled:
                    continue
                if not request.modalities.issubset(policy.allowed_hosted_modalities):
                    continue
            estimate = self.estimate(request, capability)
            if (
                estimate.input_tokens + request.max_output_tokens
                > capability.context_limit
            ):
                continue
            eligible.append(capability)
        if not eligible:
            modalities = ", ".join(sorted(request.modalities))
            raise RoutingError(
                "no model satisfies the required modalities, structured-output, "
                f"context, and privacy policy (modalities: {modalities})"
            )

        preferred = {
            name: index for index, name in enumerate(policy.preferred_providers)
        }
        return min(
            eligible,
            key=lambda item: (
                preferred.get(item.provider, len(preferred)),
                -item.quality_priority,
                self.estimate(request, item).estimated_cost_usd,
                item.provider,
                item.model,
            ),
        )

    def estimate(
        self, request: ModelRequest, capability: ModelCapability
    ) -> CostEstimate:
        input_tokens = estimate_text_tokens(request)
        image_tokens = request.image_count * capability.estimated_image_tokens
        cost = (
            input_tokens * capability.input_cost_per_million
            + request.max_output_tokens * capability.output_cost_per_million
            + image_tokens * capability.image_cost_per_million
        ) / 1_000_000
        return CostEstimate(
            provider=capability.provider,
            model=capability.model,
            input_tokens=input_tokens,
            output_tokens=request.max_output_tokens,
            image_tokens=image_tokens,
            estimated_cost_usd=round(cost, 8),
        )
