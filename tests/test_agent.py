from pathlib import Path

import pytest

from reverserx.agent import AgentLimits, AgentService, PlanDraft, PlanValidationError
from reverserx.agent.service import _source_references
from reverserx.ai import (
    Modality,
    ModelCapability,
    ModelResponse,
    ModelRouter,
    PrivacyLocation,
    ProjectModelPolicy,
    ProviderError,
    ProviderRegistry,
    RecordedProvider,
    TextPart,
    TokenUsage,
)
from reverserx.core.models import Project, SessionStatus
from reverserx.storage import Database
from reverserx.tools import build_default_registry


def _response(data: dict[str, object], *, tokens: int = 10) -> ModelResponse:
    return ModelResponse(
        provider="recorded",
        model="fixture-model",
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
    capability = ModelCapability(
        provider="recorded",
        model="fixture-model",
        modalities=frozenset({Modality.TEXT, Modality.CODE, Modality.ARTIFACT}),
        privacy_location=PrivacyLocation.LOCAL,
        context_limit=1_000_000,
        structured_output=True,
    )
    provider = RecordedProvider(capability, responses)
    providers = ProviderRegistry((provider,))
    service = AgentService(
        database=database,
        tools=build_default_registry(),
        providers=providers,
        router=ModelRouter(providers.capabilities()),
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

    result = service.run(
        project=project,
        goal="Locate fixture evidence",
        policy=ProjectModelPolicy(local_only=True),
    )

    assert result.session.status == SessionStatus.COMPLETED
    assert result.steps[0].status == "completed"
    assert result.steps[0].tool_run_id is not None
    assert len(result.findings) == 1
    assert result.findings[0].evidence_ids
    assert result.findings[0].description.startswith("Model interpretation:")
    assert len(database.list_evidence(project.id)) == 1
    assert len(database.list_model_usage(result.session.id)) == 2
    assert database.latest_checkpoint(result.session.id) is not None
    assert len(provider.requests) == 2


def test_invalid_plan_is_repaired_before_any_tool_executes(tmp_path: Path) -> None:
    invalid = _plan({"message": "bad", "undeclared": True})
    service, database, project, provider = _service(
        tmp_path,
        [_response(invalid), _response(_plan()), _response(_review())],
    )

    result = service.run(
        project=project,
        goal="Validate before execution",
        policy=ProjectModelPolicy(local_only=True),
    )

    assert result.session.status == SessionStatus.COMPLETED
    assert len(database.list_tool_runs(project.id)) == 1
    assert len(provider.requests) == 3
    attempts = database.list_plan_attempts(result.session.id)
    assert [attempt.valid for attempt in attempts] == [False, True]
    assert attempts[0].validation_error is not None
    assert attempts[1].response == _plan()
    repair_text = provider.requests[1].messages[1].parts[0]
    assert isinstance(repair_text, TextPart)
    assert "registered_tools" in repair_text.text
    assert "Validate before execution" in repair_text.text
    assert '"authorized_scope"' in repair_text.text
    assert "remove every undeclared key" in repair_text.text
    assert '"noop"' not in repair_text.text


def test_transient_provider_failure_retries_but_invalid_requests_do_not(
    tmp_path: Path,
) -> None:
    service, _, project, provider = _service(
        tmp_path,
        [
            ProviderError("temporary", transient=True),
            _response(_plan()),
            _response(_review()),
        ],
    )

    result = service.run(
        project=project,
        goal="Retry transient provider failures",
        policy=ProjectModelPolicy(local_only=True),
    )

    assert result.session.status == SessionStatus.COMPLETED
    assert len(provider.requests) == 3


def test_invalid_reviewer_decision_is_repaired_once(tmp_path: Path) -> None:
    service, _, project, provider = _service(
        tmp_path,
        [_response(_plan()), _response({}), _response(_review())],
    )

    result = service.run(
        project=project,
        goal="Repair reviewer structure",
        policy=ProjectModelPolicy(local_only=True),
    )

    assert result.session.status == SessionStatus.COMPLETED
    assert len(result.findings) == 1
    assert len(provider.requests) == 3
    repair_text = provider.requests[2].messages[1].parts[0]
    assert isinstance(repair_text, TextPart)
    assert "Repair reviewer structure" in repair_text.text
    assert "registered_tools" in repair_text.text


def test_explicit_final_tool_requirement_is_validated(tmp_path: Path) -> None:
    service, _, _, _ = _service(tmp_path, [])
    draft = PlanDraft.model_validate(_plan())

    with pytest.raises(PlanValidationError, match="agent_report as the final"):
        service._validate_plan(draft, goal="Find evidence and finish with agent_report")


def test_cost_limit_stops_before_a_provider_call(tmp_path: Path) -> None:
    database = Database(tmp_path / "reverserx.sqlite3")
    database.initialize()
    project = database.create_project(Project(slug="fixture", name="Fixture"))
    capability = ModelCapability(
        provider="recorded",
        model="paid",
        modalities=frozenset({Modality.TEXT}),
        privacy_location=PrivacyLocation.LOCAL,
        context_limit=1_000_000,
        structured_output=True,
        input_cost_per_million=1,
        output_cost_per_million=1,
    )
    provider = RecordedProvider(capability, [_response(_plan())])
    providers = ProviderRegistry((provider,))
    service = AgentService(
        database=database,
        tools=build_default_registry(),
        providers=providers,
        router=ModelRouter(providers.capabilities()),
        data_dir=tmp_path,
        artifact_root=tmp_path / "artifacts",
        limits=AgentLimits(
            max_steps=1,
            max_cost_usd=0,
            model_output_tokens_per_call=128,
        ),
    )

    result = service.run(
        project=project,
        goal="Respect cost limit",
        policy=ProjectModelPolicy(local_only=True),
    )

    assert result.session.status == SessionStatus.PAUSED
    assert "cost limit" in result.stop_reason
    assert provider.requests == []


def test_step_limit_stops_reviewer_injection(tmp_path: Path) -> None:
    injected_review = _review(action="inject")
    injected_review["injected_step"] = {
        "objective": "Repeat evidence",
        "tool_name": "echo",
        "arguments": {"message": "more"},
        "depends_on": [],
    }
    service, _, project, _ = _service(
        tmp_path,
        [_response(_plan()), _response(injected_review)],
        limits=AgentLimits(
            max_steps=1,
            max_input_tokens=100_000,
            max_output_tokens=100_000,
            model_output_tokens_per_call=128,
        ),
    )

    result = service.run(
        project=project,
        goal="Respect step limit",
        policy=ProjectModelPolicy(local_only=True),
    )

    assert result.session.status == SessionStatus.PAUSED
    assert "step limit" in result.stop_reason


def test_complete_fixture_agent_run_creates_evidence_linked_report(
    tmp_path: Path,
) -> None:
    plan: dict[str, object] = {
        "rationale": "Collect evidence, then render the bounded session report.",
        "steps": [
            {
                "objective": "Locate encryption marker",
                "tool_name": "echo",
                "arguments": {"message": "Cipher.getInstance"},
                "depends_on": [],
            },
            {
                "objective": "Render evidence-linked report",
                "tool_name": "agent_report",
                "arguments": {"title": "Encryption Location Analysis"},
                "depends_on": [0],
            },
        ],
    }
    final_review = _review()
    final_review["findings"] = []
    service, _, project, _ = _service(
        tmp_path,
        [_response(plan), _response(_review()), _response(final_review)],
    )

    result = service.run(
        project=project,
        goal="Locate request encryption and report evidence",
        policy=ProjectModelPolicy(local_only=True),
    )

    report_step = next(
        step for step in result.steps if step.tool_name == "agent_report"
    )
    assert report_step.status == "completed"
    reports = list((tmp_path / "reports" / project.id).glob("*.md"))
    assert len(reports) == 1
    markdown = reports[0].read_text(encoding="utf-8")
    assert "Cipher" not in markdown
    assert "Model interpretation:" in markdown
    assert "tool-run:" in markdown
    assert "does not prove runtime behavior" in markdown


def test_keyboard_interrupt_pauses_and_checkpoints_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, database, project, provider = _service(tmp_path, [_response(_plan())])

    def interrupt_provider(_request: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(provider, "generate", interrupt_provider)

    with pytest.raises(KeyboardInterrupt):
        service.run(
            project=project,
            goal="Preserve interrupted state",
            policy=ProjectModelPolicy(local_only=True),
        )

    session = database.list_sessions(project.id)[0]
    checkpoint = database.latest_checkpoint(session.id)
    assert session.status == SessionStatus.PAUSED
    assert session.state["stop_reason"] == "interrupted by user"
    assert checkpoint is not None
    assert checkpoint.state["session_status"] == "paused"


def test_source_references_are_bounded_and_line_linked() -> None:
    hits = [
        {
            "path": f"sources/Cipher{index}.java",
            "start_line": index + 1,
            "end_line": index + 3,
            "symbol": f"encrypt{index}",
        }
        for index in range(25)
    ]

    references = _source_references("source_search", {"hits": hits})

    assert len(references) == 20
    assert references[0] == {
        "path": "sources/Cipher0.java",
        "start_line": 1,
        "end_line": 3,
        "symbol": "encrypt0",
    }
