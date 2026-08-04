"""Provider-independent multimodal model contracts."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Modality(StrEnum):
    TEXT = "text"
    CODE = "code"
    IMAGE = "image"
    ARTIFACT = "artifact"


class PrivacyLocation(StrEnum):
    LOCAL = "local"
    HOSTED = "hosted"


class TaskType(StrEnum):
    PLANNING = "planning"
    REVIEW = "review"
    CODE_ANALYSIS = "code_analysis"
    REPORTING = "reporting"
    VISUAL_ANALYSIS = "visual_analysis"


class MessageRole(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


class TextPart(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["text"] = "text"
    text: str = Field(min_length=1)


class CodePart(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["code"] = "code"
    code: str = Field(min_length=1)
    language: str = "text"
    locator: str | None = None


class ImagePart(BaseModel):
    """Transient image bytes with immutable evidence identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["image"] = "image"
    media_type: str
    sha256: str
    artifact_id: str
    evidence_locator: str
    data_base64: str = Field(exclude=True, repr=False, min_length=1)
    detail: Literal["auto", "low", "high", "original"] = "auto"

    @field_validator("media_type")
    @classmethod
    def validate_media_type(cls, value: str) -> str:
        if not value.startswith("image/"):
            raise ValueError("image media type must start with image/")
        return value

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError("sha256 must be 64 lowercase hexadecimal characters")
        return value


class ArtifactReferencePart(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["artifact"] = "artifact"
    artifact_id: str
    sha256: str
    media_type: str
    evidence_locator: str
    description: str = ""

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError("sha256 must be 64 lowercase hexadecimal characters")
        return value


MessagePart = Annotated[
    TextPart | CodePart | ImagePart | ArtifactReferencePart,
    Field(discriminator="kind"),
]


class ModelMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    role: MessageRole
    parts: tuple[MessagePart, ...] = Field(min_length=1)


class ModelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    task_type: TaskType
    messages: tuple[ModelMessage, ...] = Field(min_length=1)
    output_schema: dict[str, Any] | None = None
    output_schema_name: str = "reverserx_response"
    max_output_tokens: int = Field(default=4_096, ge=1)

    @property
    def modalities(self) -> frozenset[Modality]:
        return frozenset(
            Modality(part.kind) for message in self.messages for part in message.parts
        )

    @property
    def image_count(self) -> int:
        return sum(
            isinstance(part, ImagePart)
            for message in self.messages
            for part in message.parts
        )


class TokenUsage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    image_tokens: int = Field(default=0, ge=0)


class ModelResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: str
    model: str
    text: str
    structured: dict[str, Any] | None = None
    usage: TokenUsage = Field(default_factory=TokenUsage)
    request_id: str | None = None


class ModelCapability(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: str
    model: str
    modalities: frozenset[Modality]
    privacy_location: PrivacyLocation
    context_limit: int = Field(ge=1)
    structured_output: bool = False
    tool_calling: bool = False
    quality_priority: int = 0
    input_cost_per_million: float = Field(default=0, ge=0)
    output_cost_per_million: float = Field(default=0, ge=0)
    image_cost_per_million: float = Field(default=0, ge=0)
    estimated_image_tokens: int = Field(default=1_000, ge=0)


class ProjectModelPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    hosted_enabled: bool = True
    local_only: bool = False
    allowed_hosted_modalities: frozenset[Modality] = Field(
        default_factory=lambda: frozenset(Modality)
    )
    preferred_providers: tuple[str, ...] = ()


class CostEstimate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: str
    model: str
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    image_tokens: int = Field(ge=0)
    estimated_cost_usd: float = Field(ge=0)


def estimate_text_tokens(request: ModelRequest) -> int:
    characters = 0
    for message in request.messages:
        for part in message.parts:
            if isinstance(part, TextPart):
                characters += len(part.text)
            elif isinstance(part, CodePart):
                characters += len(part.code) + len(part.language)
            elif isinstance(part, ArtifactReferencePart):
                characters += len(part.description) + 180
    return max(1, (characters + 3) // 4)
