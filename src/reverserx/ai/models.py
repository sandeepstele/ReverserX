"""DeepSeek-only message contracts — text and code, no multimodal."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


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


MessagePart = TextPart | CodePart


class ModelMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    role: MessageRole
    parts: tuple[MessagePart, ...] = Field(min_length=1)


class ModelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    messages: tuple[ModelMessage, ...] = Field(min_length=1)
    output_schema: dict[str, Any] | None = None
    output_schema_name: str = "reverserx_response"
    max_output_tokens: int = Field(default=4_096, ge=1)


class TokenUsage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)


class ModelResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: str
    model: str
    text: str
    structured: dict[str, Any] | None = None
    usage: TokenUsage = Field(default_factory=TokenUsage)
    request_id: str | None = None


def estimate_text_tokens(request: ModelRequest) -> int:
    characters = 0
    for message in request.messages:
        for part in message.parts:
            if isinstance(part, TextPart):
                characters += len(part.text)
            elif isinstance(part, CodePart):
                characters += len(part.code) + len(part.language)
    return max(1, (characters + 3) // 4)
