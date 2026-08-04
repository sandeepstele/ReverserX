"""Hosted, local, and recorded model-provider adapters."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from reverserx.ai.models import (
    ArtifactReferencePart,
    CodePart,
    ImagePart,
    ModelCapability,
    ModelRequest,
    ModelResponse,
    TextPart,
    TokenUsage,
    estimate_text_tokens,
)

JsonTransport = Callable[
    [str, dict[str, object], dict[str, str], float], dict[str, object]
]


class ProviderError(RuntimeError):
    """Normalized provider failure with explicit retry classification."""

    def __init__(self, message: str, *, transient: bool = False) -> None:
        super().__init__(message)
        self.transient = transient


class ModelProvider(ABC):
    capability: ModelCapability

    @abstractmethod
    def generate(self, request: ModelRequest) -> ModelResponse:
        """Generate one normalized response."""


class ProviderRegistry:
    def __init__(self, providers: Iterable[ModelProvider] = ()) -> None:
        self._providers: dict[tuple[str, str], ModelProvider] = {}
        for provider in providers:
            self.register(provider)

    def register(self, provider: ModelProvider) -> None:
        key = (provider.capability.provider, provider.capability.model)
        if key in self._providers:
            raise ValueError(f"provider model already registered: {key[0]}/{key[1]}")
        self._providers[key] = provider

    def get(self, capability: ModelCapability) -> ModelProvider:
        key = (capability.provider, capability.model)
        try:
            return self._providers[key]
        except KeyError as exc:
            raise ProviderError(
                f"provider model is not configured: {key[0]}/{key[1]}"
            ) from exc

    def capabilities(self) -> tuple[ModelCapability, ...]:
        return tuple(
            provider.capability
            for _, provider in sorted(self._providers.items(), key=lambda item: item[0])
        )


class RecordedProvider(ModelProvider):
    """Deterministic provider for scenario tests and offline replays."""

    def __init__(
        self,
        capability: ModelCapability,
        responses: Iterable[ModelResponse | ProviderError],
    ) -> None:
        self.capability = capability
        self._responses = list(responses)
        self.requests: list[ModelRequest] = []

    def generate(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        if not self._responses:
            raise ProviderError("recorded provider has no remaining response")
        response = self._responses.pop(0)
        if isinstance(response, ProviderError):
            raise response
        return response


class OpenAIResponsesProvider(ModelProvider):
    def __init__(
        self,
        capability: ModelCapability,
        api_key: str,
        *,
        base_url: str = "https://api.openai.com/v1",
        timeout_seconds: float = 120,
        transport: JsonTransport | None = None,
    ) -> None:
        self.capability = capability
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.transport = transport or _post_json

    def generate(self, request: ModelRequest) -> ModelResponse:
        payload: dict[str, object] = {
            "model": self.capability.model,
            "input": [_openai_message(message) for message in request.messages],
            "max_output_tokens": request.max_output_tokens,
            "store": False,
        }
        if request.output_schema is not None:
            payload["text"] = {
                "format": {
                    "type": "json_schema",
                    "name": request.output_schema_name,
                    "schema": request.output_schema,
                    # Tool arguments are intentionally open JSON objects; local
                    # Pydantic validation is the strict execution boundary.
                    "strict": False,
                }
            }
        response = self.transport(
            f"{self.base_url}/responses",
            payload,
            {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            self.timeout_seconds,
        )
        text = _openai_output_text(response)
        usage_data = response.get("usage")
        usage = usage_data if isinstance(usage_data, dict) else {}
        structured = _parse_structured(text, request.output_schema is not None)
        return ModelResponse(
            provider=self.capability.provider,
            model=self.capability.model,
            text=text,
            structured=structured,
            usage=TokenUsage(
                input_tokens=_integer(usage.get("input_tokens")),
                output_tokens=_integer(usage.get("output_tokens")),
                image_tokens=request.image_count
                * self.capability.estimated_image_tokens,
            ),
            request_id=_optional_string(response.get("id")),
        )


class OllamaProvider(ModelProvider):
    def __init__(
        self,
        capability: ModelCapability,
        *,
        base_url: str = "http://127.0.0.1:11434",
        timeout_seconds: float = 120,
        transport: JsonTransport | None = None,
    ) -> None:
        self.capability = capability
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.transport = transport or _post_json

    def generate(self, request: ModelRequest) -> ModelResponse:
        required_context = (
            estimate_text_tokens(request) + request.max_output_tokens + 2_048
        )
        context_window = min(
            self.capability.context_limit,
            _next_power_of_two(max(8_192, required_context)),
        )
        payload: dict[str, object] = {
            "model": self.capability.model,
            "messages": [_ollama_message(message) for message in request.messages],
            "stream": False,
            "options": {
                "num_predict": request.max_output_tokens,
                "num_ctx": context_window,
                "temperature": 0,
            },
        }
        if request.output_schema is not None:
            payload["format"] = request.output_schema
        response = self.transport(
            f"{self.base_url}/api/chat",
            payload,
            {"Content-Type": "application/json"},
            self.timeout_seconds,
        )
        message = response.get("message")
        if not isinstance(message, dict) or not isinstance(message.get("content"), str):
            raise ProviderError("Ollama response has no assistant message")
        text = str(message["content"])
        return ModelResponse(
            provider=self.capability.provider,
            model=self.capability.model,
            text=text,
            structured=_parse_structured(text, request.output_schema is not None),
            usage=TokenUsage(
                input_tokens=_integer(response.get("prompt_eval_count")),
                output_tokens=_integer(response.get("eval_count")),
                image_tokens=request.image_count
                * self.capability.estimated_image_tokens,
            ),
        )


class DeepSeekProvider(ModelProvider):
    """DeepSeek Chat Completions API provider (OpenAI-compatible)."""

    def __init__(
        self,
        capability: ModelCapability,
        api_key: str,
        *,
        base_url: str = "https://api.deepseek.com/v1",
        timeout_seconds: float = 120,
        transport: JsonTransport | None = None,
    ) -> None:
        self.capability = capability
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.transport = transport or _post_json

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
                    parts_text.append(_render_code(part))
                elif isinstance(part, ImagePart):
                    parts_text.append(
                        f"[image evidence {part.sha256} at {part.evidence_locator}]"
                    )
                else:
                    parts_text.append(_render_artifact(part))
            content = "\n\n".join(parts_text)
            # DeepSeek supports "system" role
            role = "system" if msg.role.value == "system" else (
                "assistant" if msg.role.value == "assistant" else "user"
            )
            messages.append({"role": role, "content": content})

        payload: dict[str, object] = {
            "model": self.capability.model,
            "messages": messages,
            "max_tokens": request.max_output_tokens,
            "temperature": 0,
            "stream": False,
        }
        if request.output_schema is not None:
            # Embed schema name in the system prompt; DeepSeek json_object
            # mode produces valid JSON but not schema-guaranteed output.
            payload["response_format"] = {"type": "json_object"}
            schema_hint = (
                f"Respond ONLY with a JSON object conforming to this schema:\n"
                f"{json.dumps(request.output_schema, sort_keys=True)}\n"
                f"Schema name: {request.output_schema_name}"
            )
            if messages and messages[0]["role"] == "system":
                messages[0]["content"] = (
                    f"{messages[0]['content']}\n\n{schema_hint}"
                )
            else:
                messages.insert(0, {"role": "system", "content": schema_hint})

        response = self.transport(
            f"{self.base_url}/chat/completions",
            payload,
            {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            self.timeout_seconds,
        )
        text = _deepseek_output_text(response)
        usage_data = response.get("usage")
        usage = usage_data if isinstance(usage_data, dict) else {}
        structured = _parse_structured(text, request.output_schema is not None)
        return ModelResponse(
            provider=self.capability.provider,
            model=self.capability.model,
            text=text,
            structured=structured,
            usage=TokenUsage(
                input_tokens=_integer(usage.get("prompt_tokens")),
                output_tokens=_integer(usage.get("completion_tokens")),
                image_tokens=0,  # DeepSeek does not support image inputs
            ),
            request_id=_optional_string(response.get("id")),
        )


def _deepseek_output_text(response: dict[str, object]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list) or len(choices) == 0:
        raise ProviderError("DeepSeek response has no choices")
    first = choices[0]
    if not isinstance(first, dict):
        raise ProviderError("DeepSeek choice is not an object")
    message = first.get("message")
    if not isinstance(message, dict):
        raise ProviderError("DeepSeek choice has no message")
    content = message.get("content")
    if not isinstance(content, str):
        raise ProviderError("DeepSeek message has no text content")
    return content


def _openai_message(message: object) -> dict[str, object]:
    from reverserx.ai.models import ModelMessage

    validated = ModelMessage.model_validate(message)
    content: list[dict[str, object]] = []
    for part in validated.parts:
        if isinstance(part, TextPart):
            content.append({"type": "input_text", "text": part.text})
        elif isinstance(part, CodePart):
            content.append(
                {
                    "type": "input_text",
                    "text": _render_code(part),
                }
            )
        elif isinstance(part, ImagePart):
            content.append(
                {
                    "type": "input_image",
                    "image_url": (f"data:{part.media_type};base64,{part.data_base64}"),
                    "detail": part.detail,
                }
            )
        else:
            content.append({"type": "input_text", "text": _render_artifact(part)})
    return {"role": validated.role.value, "content": content}


def _ollama_message(message: object) -> dict[str, object]:
    from reverserx.ai.models import ModelMessage

    validated = ModelMessage.model_validate(message)
    texts: list[str] = []
    images: list[str] = []
    for part in validated.parts:
        if isinstance(part, TextPart):
            texts.append(part.text)
        elif isinstance(part, CodePart):
            texts.append(_render_code(part))
        elif isinstance(part, ImagePart):
            images.append(part.data_base64)
            texts.append(f"[image evidence {part.sha256} at {part.evidence_locator}]")
        else:
            texts.append(_render_artifact(part))
    result: dict[str, object] = {
        "role": validated.role.value,
        "content": "\n\n".join(texts),
    }
    if images:
        result["images"] = images
    return result


def _render_code(part: CodePart) -> str:
    locator = f"\nEvidence: {part.locator}" if part.locator else ""
    return f"```{part.language}\n{part.code}\n```{locator}"


def _render_artifact(part: ArtifactReferencePart) -> str:
    return (
        f"Artifact {part.artifact_id} ({part.media_type}, sha256={part.sha256}) "
        f"at {part.evidence_locator}. {part.description}"
    ).strip()


def _openai_output_text(response: dict[str, object]) -> str:
    direct = response.get("output_text")
    if isinstance(direct, str):
        return direct
    output = response.get("output")
    if not isinstance(output, list):
        raise ProviderError("OpenAI response has no output")
    parts: list[str] = []
    for item in output:
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if isinstance(block, dict) and block.get("type") == "output_text":
                value = block.get("text")
                if isinstance(value, str):
                    parts.append(value)
    if not parts:
        raise ProviderError("OpenAI response has no output text")
    return "\n".join(parts)


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


def _next_power_of_two(value: int) -> int:
    return 1 << (value - 1).bit_length()
