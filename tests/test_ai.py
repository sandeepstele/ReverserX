"""Tests for simplified DeepSeek-only AI layer."""

import pytest
from pydantic import ValidationError

from reverserx.ai import (
    MessageRole,
    ModelMessage,
    ModelRequest,
    ModelResponse,
    TextPart,
    TokenUsage,
)
from reverserx.ai.providers import DeepSeekProvider, ProviderError, RecordedProvider


def test_message_roundtrip() -> None:
    msg = ModelMessage(
        role=MessageRole.USER,
        parts=(TextPart(text="Analyze this"),),
    )
    assert msg.role == MessageRole.USER
    assert len(msg.parts) == 1
    assert isinstance(msg.parts[0], TextPart)
    assert msg.parts[0].text == "Analyze this"


def test_text_part_min_length() -> None:
    with pytest.raises(ValidationError):
        TextPart(text="")


def test_request_requires_messages() -> None:
    with pytest.raises(ValidationError):
        ModelRequest(messages=())


def test_recorded_provider_replays_responses() -> None:
    resp = ModelResponse(
        provider="recorded",
        model="test",
        text='{"ok":true}',
        structured={"ok": True},
        usage=TokenUsage(input_tokens=5, output_tokens=3),
    )
    provider = RecordedProvider([resp])
    request = ModelRequest(
        messages=(ModelMessage(role=MessageRole.USER, parts=(TextPart(text="hi"),)),),
    )
    result = provider.generate(request)
    assert result.structured == {"ok": True}
    assert len(provider.requests) == 1


def test_recorded_provider_exhausted() -> None:
    provider = RecordedProvider([])
    request = ModelRequest(
        messages=(ModelMessage(role=MessageRole.USER, parts=(TextPart(text="hi"),)),),
    )
    with pytest.raises(ProviderError, match="no remaining response"):
        provider.generate(request)


def test_deepseek_provider_builds_chat_payload() -> None:
    captured: dict[str, object] = {}

    def transport(url, payload, headers, timeout):
        captured.update({"url": url, "payload": payload, "headers": headers, "timeout": timeout})
        return {
            "id": "resp_1",
            "choices": [{"message": {"role": "assistant", "content": '{"answer":"ok"}'}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }

    provider = DeepSeekProvider("sk-test", transport=transport)  # type: ignore[arg-type]
    request = ModelRequest(
        messages=(
            ModelMessage(role=MessageRole.SYSTEM, parts=(TextPart(text="You are helpful"),)),
            ModelMessage(role=MessageRole.USER, parts=(TextPart(text="Hello"),)),
        ),
        output_schema={"type": "object", "properties": {"answer": {"type": "string"}}},
        output_schema_name="test",
        max_output_tokens=100,
    )
    result = provider.generate(request)
    assert result.structured == {"answer": "ok"}
    assert result.usage.input_tokens == 10
    assert result.usage.output_tokens == 5
    assert result.provider == "deepseek"
    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload["model"] == "deepseek-chat"
    assert payload["temperature"] == 0
    assert payload["response_format"] == {"type": "json_object"}
