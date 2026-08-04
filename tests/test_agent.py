"""Tests for agent service with DeepSeek-only provider."""
from pathlib import Path

from reverserx.agent import AgentLimits, AgentService
from reverserx.ai import (
    ModelResponse,
    ProviderError,
    RecordedProvider,
    TokenUsage,
)
from reverserx.core.models import Project, SessionStatus
from reverserx.storage import Database
from reverserx.tools import build_default_registry


def _response(data: dict[str, object], *, tokens: int = 10) -> ModelResponse:
    return ModelResponse(
        provider="deepseek",
        model="deepseek-chat",
        text="recorded",
        structured=data,
        usage=TokenUsage(input_tokens=tokens, output_tokens=tokens),
        request_id=f"resp_{id(data)}",
    )


def _plan(arguments: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "rationale": "Use the deterministic echo fixture.",
        "steps": [
            {
                "objective": "Collect fixture evidence",
                "tool_name": "echo",
                "arguments": arguments or {"message": "evidence"},
                "depends_on": [],
            }
        ],
    }


def _review(*, action: str = "accept") -> dict[str, object]:
    return {
        "action": action,
        "rationale": "The deterministic evidence supports the candidate finding.",
        "findings": [
            {
                "title": "Fixture evidence",
                "description": "The echo result contains the expected marker.",
                "severity": "info",
                "confidence": 0.9,
            }
        ],
        "hypotheses": [],
        "key_locations": ["tool-run:fixture"],
        "unresolved_items": [],
    }


def _service(
    tmp_path: Path,
    responses: list[ModelResponse | ProviderError],
    *,
    limits: AgentLimits | None = None,
) -> tuple[AgentService, Database, Project, RecordedProvider]:
    database = Database(tmp_path / "reverserx.sqlite3")
    database.initialize()
    project = database.create_project(Project(slug="fixture", name="Fixture"))
    provider = RecordedProvider(responses)
    service = AgentService(
        database=database,
        tools=build_default_registry(),
        provider=provider,  # type: ignore[arg-type]
        data_dir=tmp_path,
        artifact_root=tmp_path / "artifacts",
        limits=limits
        or AgentLimits(
            max_steps=3,
            max_input_tokens=100_000,
            max_output_tokens=100_000,
            model_output_tokens_per_call=128,
        ),
    )
    return service, database, project, provider


def test_recorded_agent_run_is_persistent_and_evidence_linked(tmp_path: Path) -> None:
    service, database, project, provider = _service(
        tmp_path, [_response(_plan()), _response(_review())]
    )

    result = service.run(project=project, goal="Locate fixture evidence")

    assert result.session.status == SessionStatus.COMPLETED
    assert result.steps[0].status == "completed"
    assert result.steps[0].tool_run_id is not None
    assert len(result.findings) == 1
    assert result.findings[0].evidence_ids
    assert len(database.list_evidence(project.id)) == 1
    assert len(database.list_model_usage(result.session.id)) == 2
    assert database.latest_checkpoint(result.session.id) is not None
    assert len(provider.requests) == 2


def test_transient_provider_failure_retries(tmp_path: Path) -> None:
    service, _, project, provider = _service(
        tmp_path,
        [
            ProviderError("temporary", transient=True),
            _response(_plan()),
            _response(_review()),
        ],
    )

    result = service.run(project=project, goal="Retry transient failures")
    assert result.session.status == SessionStatus.COMPLETED
    assert len(provider.requests) == 3


def test_agent_stops_on_step_limit(tmp_path: Path) -> None:
    infinite_plan = {
        "rationale": "Loop forever.",
        "steps": [
            {
                "objective": "Loop step",
                "tool_name": "echo",
                "arguments": {"message": "again"},
                "depends_on": [],
            }
        ],
    }
    # Review always injects another echo step
    inject_review = {
        "action": "inject",
        "rationale": "Keep going",
        "injected_step": {
            "objective": "Injected step",
            "tool_name": "echo",
            "arguments": {"message": "injected"},
            "depends_on": [],
        },
        "findings": [],
        "hypotheses": [],
        "key_locations": [],
        "unresolved_items": [],
    }

    service, _, project, _ = _service(
        tmp_path,
        [_response(infinite_plan)] + [_response(inject_review)] * 10,
        limits=AgentLimits(max_steps=2, max_input_tokens=999999, max_output_tokens=99999, model_output_tokens_per_call=128),
    )

    result = service.run(project=project, goal="Stop at limit")
    assert result.session.status == SessionStatus.PAUSED
