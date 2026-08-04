"""DeepSeek provider and recorded provider for tests."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from reverserx.ai.models import (
    CodePart,
    ModelRequest,
    ModelResponse,
    TextPart,
    TokenUsage,
)


class ProviderError(RuntimeError):
    """Normalized provider failure with explicit retry classification."""

    def __init__(self, message: str, *, transient: bool = False) -> None:
        super().__init__(message)
        self.transient = transient


class ModelProvider(ABC):
    @abstractmethod
    def generate(self, request: ModelRequest) -> ModelResponse:
        """Generate one normalized response."""


class RecordedProvider(ModelProvider):
    """Deterministic provider for scenario tests and offline replays."""

    def __init__(self, responses: Iterable[ModelResponse | ProviderError]) -> None:
        self._responses = list(responses)
        self.requests: list[ModelRequest] = []

    @property
    def capability(self) -> str:
        return "recorded"

    def generate(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        if not self._responses:
            raise ProviderError("recorded provider has no remaining response")
        response = self._responses.pop(0)
        if isinstance(response, ProviderError):
            raise response
        return response


class DeepSeekProvider(ModelProvider):
    """DeepSeek Chat Completions API provider (sole LLM for ReverserX)."""

    def __init__(
        self,
        api_key: str,
        *,
        model: str = "deepseek-chat",
        base_url: str = "https://api.deepseek.com/v1",
        timeout_seconds: float = 120,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    @property
    def capability(self) -> str:
        return f"deepseek/{self.model}"

    def generate(self, request: ModelRequest) -> ModelResponse:
        from reverserx.ai.models import ModelMessage

        messages: list[dict[str, object]] = []
        for msg_raw in request.messages:
            msg = ModelMessage.model_validate(msg_raw)
            parts_text: list[str] = []
            for part in msg.parts:
                if isinstance(part, TextPart):
                    parts_text.append(part.text)
                elif isinstance(part, CodePart):
                    locator = f"\nEvidence: {part.locator}" if part.locator else ""
                    parts_text.append(f"```{part.language}\n{part.code}\n```{locator}")
            content = "\n\n".join(parts_text)
            role = (
                "system" if msg.role.value == "system"
                else "assistant" if msg.role.value == "assistant"
                else "user"
            )
            messages.append({"role": role, "content": content})

        payload: dict[str, object] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": request.max_output_tokens,
            "temperature": 0,
            "stream": False,
        }
        if request.output_schema is not None:
            payload["response_format"] = {"type": "json_object"}
            schema_hint = (
                "Respond ONLY with a JSON object conforming to this schema:\n"
                f"{json.dumps(request.output_schema, sort_keys=True)}\n"
                f"Schema name: {request.output_schema_name}"
            )
            if messages and messages[0]["role"] == "system":
                messages[0]["content"] = f"{messages[0]['content']}\n\n{schema_hint}"
            else:
                messages.insert(0, {"role": "system", "content": schema_hint})

        response = _post_json(
            f"{self.base_url}/chat/completions",
            payload,
            {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            self.timeout_seconds,
        )
        text = _chat_output_text(response)
        structured = _parse_structured(text, request.output_schema is not None)
        usage_data = response.get("usage")
        usage = usage_data if isinstance(usage_data, dict) else {}
        return ModelResponse(
            provider="deepseek",
            model=self.model,
            text=text,
            structured=structured,
            usage=TokenUsage(
                input_tokens=_integer(usage.get("prompt_tokens")),
                output_tokens=_integer(usage.get("completion_tokens")),
            ),
            request_id=_optional_string(response.get("id")),
        )


# --- Helpers ---


def _chat_output_text(response: dict[str, object]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list) or len(choices) == 0:
        raise ProviderError("response has no choices")
    first = choices[0]
    if not isinstance(first, dict):
        raise ProviderError("choice is not an object")
    message = first.get("message")
    if not isinstance(message, dict):
        raise ProviderError("choice has no message")
    content = message.get("content")
    if not isinstance(content, str):
        raise ProviderError("message has no text content")
    return content


def _parse_structured(text: str, required: bool) -> dict[str, object] | None:
    if not required:
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def _post_json(
    url: str,
    payload: dict[str, object],
    headers: dict[str, str],
    timeout_seconds: float,
) -> dict[str, object]:
    request = Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
            raw = response.read()
    except HTTPError as exc:
        transient = exc.code in {408, 409, 429} or exc.code >= 500
        raise ProviderError(
            f"provider HTTP request failed with status {exc.code}",
            transient=transient,
        ) from exc
    except (TimeoutError, URLError) as exc:
        raise ProviderError(f"provider request failed: {exc}", transient=True) from exc
    try:
        parsed = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderError("provider returned invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise ProviderError("provider response must be a JSON object")
    return parsed


def _integer(value: object) -> int:
    return value if isinstance(value, int) and value >= 0 else 0


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None
