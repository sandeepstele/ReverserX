import json

import pytest
from pydantic import ValidationError

from reverserx.ai import (
    ImagePart,
    MessageRole,
    Modality,
    ModelCapability,
    ModelMessage,
    ModelRequest,
    ModelRouter,
    OllamaProvider,
    OpenAIResponsesProvider,
    PrivacyLocation,
    ProjectModelPolicy,
    RoutingError,
    TaskType,
    TextPart,
    classify_task,
)


def _request(*, image: bool = False) -> ModelRequest:
    parts: list[TextPart | ImagePart] = [TextPart(text="Analyze this evidence")]
    if image:
        parts.append(
            ImagePart(
                media_type="image/png",
                sha256="a" * 64,
                artifact_id="art_fixture",
                evidence_locator="screenshot:login",
                data_base64="aW1hZ2U=",
            )
        )
    return ModelRequest(
        task_type=TaskType.VISUAL_ANALYSIS if image else TaskType.PLANNING,
        messages=(ModelMessage(role=MessageRole.USER, parts=tuple(parts)),),
        output_schema={"type": "object", "properties": {}},
        max_output_tokens=100,
    )


def _capability(
    *,
    provider: str,
    location: PrivacyLocation,
    image: bool = False,
    quality: int = 0,
) -> ModelCapability:
    modalities = {Modality.TEXT}
    if image:
        modalities.add(Modality.IMAGE)
    return ModelCapability(
        provider=provider,
        model=f"{provider}-model",
        modalities=frozenset(modalities),
        privacy_location=location,
        context_limit=10_000,
        structured_output=True,
        quality_priority=quality,
        input_cost_per_million=1,
        output_cost_per_million=2,
        image_cost_per_million=3,
        estimated_image_tokens=500,
    )


def test_image_parts_require_evidence_identity() -> None:
    with pytest.raises(ValidationError, match="sha256"):
        ImagePart(
            media_type="image/png",
            sha256="bad",
            artifact_id="art_fixture",
            evidence_locator="screen:1",
            data_base64="aW1hZ2U=",
        )


def test_task_classifier_is_capability_oriented() -> None:
    assert classify_task("Locate request encryption code", frozenset()) == (
        TaskType.CODE_ANALYSIS
    )
    assert classify_task("Review this screenshot", frozenset({Modality.IMAGE})) == (
        TaskType.VISUAL_ANALYSIS
    )


def test_router_enforces_local_only_and_never_drops_images() -> None:
    hosted = _capability(provider="hosted", location=PrivacyLocation.HOSTED, image=True)
    local_text = _capability(provider="local", location=PrivacyLocation.LOCAL)
    router = ModelRouter((hosted, local_text))

    with pytest.raises(RoutingError, match="no model satisfies"):
        router.route(_request(image=True), ProjectModelPolicy(local_only=True))


def test_router_prefers_capability_and_accounts_for_images() -> None:
    hosted = _capability(
        provider="hosted",
        location=PrivacyLocation.HOSTED,
        image=True,
        quality=10,
    )
    router = ModelRouter((hosted,))
    request = _request(image=True)

    selected = router.route(request, ProjectModelPolicy())
    estimate = router.estimate(request, selected)

    assert selected.provider == "hosted"
    assert estimate.image_tokens == 500
    assert estimate.estimated_cost_usd > 0


def test_hosted_modality_policy_blocks_images_explicitly() -> None:
    hosted = _capability(provider="hosted", location=PrivacyLocation.HOSTED, image=True)

    with pytest.raises(RoutingError):
        ModelRouter((hosted,)).route(
            _request(image=True),
            ProjectModelPolicy(allowed_hosted_modalities=frozenset({Modality.TEXT})),
        )


def test_openai_provider_normalizes_structured_response_and_image_payload() -> None:
    captured: dict[str, object] = {}

    def transport(
        url: str,
        payload: dict[str, object],
        headers: dict[str, str],
        timeout: float,
    ) -> dict[str, object]:
        captured.update(
            {"url": url, "payload": payload, "headers": headers, "timeout": timeout}
        )
        return {
            "id": "resp_123",
            "output_text": '{"answer":"found"}',
            "usage": {"input_tokens": 20, "output_tokens": 5},
        }

    capability = _capability(
        provider="openai", location=PrivacyLocation.HOSTED, image=True
    )
    response = OpenAIResponsesProvider(
        capability, "secret", transport=transport
    ).generate(_request(image=True))

    assert response.structured == {"answer": "found"}
    assert response.usage.input_tokens == 20
    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload["store"] is False
    assert "json_schema" in json.dumps(payload)
    assert "data:image/png;base64,aW1hZ2U=" in json.dumps(payload)


def test_ollama_provider_normalizes_local_usage() -> None:
    captured: dict[str, object] = {}

    def transport(
        url: str,
        payload: dict[str, object],
        headers: dict[str, str],
        timeout: float,
    ) -> dict[str, object]:
        del url, headers, timeout
        captured.update(payload)
        return {
            "message": {"role": "assistant", "content": '{"ok":true}'},
            "prompt_eval_count": 12,
            "eval_count": 3,
        }

    capability = _capability(provider="ollama", location=PrivacyLocation.LOCAL)
    response = OllamaProvider(capability, transport=transport).generate(_request())

    assert response.structured == {"ok": True}
    assert response.usage.input_tokens == 12
    assert response.usage.output_tokens == 3
    options = captured["options"]
    assert isinstance(options, dict)
    assert options["num_ctx"] >= 8_192
    assert options["temperature"] == 0


def test_malformed_provider_json_remains_available_for_bounded_repair() -> None:
    def transport(
        url: str,
        payload: dict[str, object],
        headers: dict[str, str],
        timeout: float,
    ) -> dict[str, object]:
        del url, payload, headers, timeout
        return {"message": {"role": "assistant", "content": "not-json"}}

    capability = _capability(provider="ollama", location=PrivacyLocation.LOCAL)
    response = OllamaProvider(capability, transport=transport).generate(_request())

    assert response.text == "not-json"
    assert response.structured is None
