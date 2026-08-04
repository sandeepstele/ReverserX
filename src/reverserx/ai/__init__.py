"""Model providers, capability routing, and multimodal contracts."""

from reverserx.ai.classifier import classify_task
from reverserx.ai.factory import build_provider_registry
from reverserx.ai.models import (
    ArtifactReferencePart,
    CodePart,
    CostEstimate,
    ImagePart,
    MessageRole,
    Modality,
    ModelCapability,
    ModelMessage,
    ModelRequest,
    ModelResponse,
    PrivacyLocation,
    ProjectModelPolicy,
    TaskType,
    TextPart,
    TokenUsage,
)
from reverserx.ai.providers import (
    ModelProvider,
    OllamaProvider,
    OpenAIResponsesProvider,
    ProviderError,
    ProviderRegistry,
    RecordedProvider,
)
from reverserx.ai.router import ModelRouter, RoutingError

__all__ = [
    "ArtifactReferencePart",
    "build_provider_registry",
    "classify_task",
    "CodePart",
    "CostEstimate",
    "ImagePart",
    "MessageRole",
    "Modality",
    "ModelCapability",
    "ModelMessage",
    "ModelProvider",
    "ModelRequest",
    "ModelResponse",
    "ModelRouter",
    "OllamaProvider",
    "OpenAIResponsesProvider",
    "PrivacyLocation",
    "ProjectModelPolicy",
    "ProviderError",
    "ProviderRegistry",
    "RecordedProvider",
    "RoutingError",
    "TaskType",
    "TextPart",
    "TokenUsage",
]
