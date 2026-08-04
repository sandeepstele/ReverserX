"""Bounded, persistent plan-execute-review agent service."""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from reverserx.agent.models import (
    AgentError,
    AgentLimitError,
    AgentLimits,
    AgentRunEstimate,
    AgentRunResult,
    PlanDraft,
    PlanStepDraft,
    PlanValidationError,
    ReviewAction,
    ReviewerDecision,
    WorkingMemory,
)
from reverserx.agent.prompts import (
    PLANNER_SYSTEM,
    REVIEWER_SYSTEM,
    plan_repair_input,
    planner_input,
    review_repair_input,
    reviewer_input,
)
from reverserx.ai import (
    MessageRole,
    ModelMessage,
    ModelRequest,
    ModelResponse,
    ModelRouter,
    ProjectModelPolicy,
    ProviderError,
    ProviderRegistry,
    TaskType,
    TextPart,
)
from reverserx.ai.models import CostEstimate, ModelCapability
from reverserx.core.models import (
    AgentCheckpoint,
    AnalysisSession,
    Evidence,
    EvidenceKind,
    Finding,
    FindingSeverity,
    ModelUsage,
    PlanAttempt,
    PlanStep,
    PlanStepStatus,
    Project,
    SessionStatus,
    ToolRun,
    ToolRunStatus,
    utc_now,
)
from reverserx.storage import Database
from reverserx.tools import ToolContext, ToolRegistry
from reverserx.tools.registry import ToolRegistryError


@dataclass(slots=True)
class _Ledger:
    input_tokens: int = 0
    output_tokens: int = 0
    actual_cost_usd: float = 0


class AgentService:
    def __init__(
        self,
        *,
        database: Database,
        tools: ToolRegistry,
        providers: ProviderRegistry,
        router: ModelRouter,
        data_dir: Path,
        artifact_root: Path,
        limits: AgentLimits,
    ) -> None:
        self.database = database
        self.tools = tools
        self.providers = providers
        self.router = router
        self.data_dir = data_dir
        self.artifact_root = artifact_root
        self.limits = limits

    def estimate(
        self,
        *,
        project: Project,
        goal: str,
        policy: ProjectModelPolicy,
    ) -> AgentRunEstimate:
        request = self._planning_request(project, goal)
        capability = self.router.route(request, policy)
        one_call = self.router.estimate(request, capability)
        calls = self.limits.max_steps + 2
        return AgentRunEstimate(
            provider=capability.provider,
            model=capability.model,
            projected_model_calls=calls,
            projected_input_tokens=one_call.input_tokens * calls,
            projected_output_tokens=one_call.output_tokens * calls,
            projected_cost_usd=round(one_call.estimated_cost_usd * calls, 8),
        )

    def run(
        self,
        *,
        project: Project,
        goal: str,
        policy: ProjectModelPolicy,
    ) -> AgentRunResult:
        normalized_goal = goal.strip()
        if not normalized_goal:
            raise ValueError("analysis goal cannot be blank")
        started = time.monotonic()
        ledger = _Ledger()
        memory = WorkingMemory()
        session = self.database.create_session(
            AnalysisSession(
                project_id=project.id,
                goal=normalized_goal,
                status=SessionStatus.RUNNING,
                state={"phase": "planning", "stop_reason": None},
            )
        )
        checkpoint_sequence = 0
        try:
            draft = self._create_plan(
                project=project,
                session=session,
                goal=normalized_goal,
                policy=policy,
                ledger=ledger,
                started=started,
            )
            steps = self._persist_plan(session, draft)
            session = self._update_session(
                session,
                phase="executing",
                stop_reason=None,
                memory=memory,
                ledger=ledger,
            )
            checkpoint_sequence = self._checkpoint(
                session, checkpoint_sequence, memory, ledger
            )
            seen_calls: dict[str, int] = {}
            index = 0
            stop_reason = "plan completed"
            while index < len(steps):
                self._check_wall_time(started)
                step = steps[index]
                if step.status in {
                    PlanStepStatus.COMPLETED,
                    PlanStepStatus.SKIPPED,
                }:
                    index += 1
                    continue
                if not self._dependencies_completed(step, steps):
                    step = step.model_copy(update={"status": PlanStepStatus.SKIPPED})
                    self.database.update_plan_step(step)
                    steps[index] = step
                    index += 1
                    continue

                step, execution, evidence = self._execute_step(
                    project=project,
                    session=session,
                    step=step,
                    seen_calls=seen_calls,
                )
                steps[index] = step
                decision = self._review_step(
                    project=project,
                    session=session,
                    goal=normalized_goal,
                    step=step,
                    execution=execution,
                    memory=memory,
                    policy=policy,
                    ledger=ledger,
                    started=started,
                    remaining_steps=max(0, self.limits.max_steps - len(steps)),
                )
                memory = self._record_review(
                    project=project,
                    decision=decision,
                    evidence=evidence,
                    memory=memory,
                )

                if decision.action == ReviewAction.RETRY:
                    self._require_retry_available(step)
                    continue
                if decision.action == ReviewAction.REFINE:
                    self._require_retry_available(step)
                    if decision.refined_arguments is None:
                        raise AgentError("reviewer refine action has no arguments")
                    self._validate_tool_step(
                        PlanStepDraft(
                            objective=step.objective,
                            tool_name=step.tool_name or "",
                            arguments=decision.refined_arguments,
                        )
                    )
                    step = step.model_copy(
                        update={
                            "arguments": decision.refined_arguments,
                            "status": PlanStepStatus.PENDING,
                            "last_error": None,
                        }
                    )
                    self.database.update_plan_step(step)
                    steps[index] = step
                    continue

                terminal_status = (
                    PlanStepStatus.COMPLETED
                    if execution.status == ToolRunStatus.SUCCEEDED
                    else PlanStepStatus.FAILED
                )
                step = step.model_copy(update={"status": terminal_status})
                self.database.update_plan_step(step)
                steps[index] = step

                if decision.action == ReviewAction.INJECT:
                    if decision.injected_step is None:
                        raise AgentError("reviewer inject action has no step")
                    if len(steps) >= self.limits.max_steps:
                        raise AgentLimitError("step limit reached before injected step")
                    injected = self._persist_injected_step(
                        session=session,
                        draft=decision.injected_step,
                        sequence=len(steps),
                        depends_on=step.id,
                    )
                    steps.append(injected)
                if decision.action == ReviewAction.STOP:
                    stop_reason = f"reviewer stopped: {decision.rationale}"
                    break

                checkpoint_sequence = self._checkpoint(
                    session, checkpoint_sequence, memory, ledger
                )
                session = self._update_session(
                    session,
                    phase="executing",
                    stop_reason=None,
                    memory=memory,
                    ledger=ledger,
                )
                index += 1

            session = session.model_copy(
                update={
                    "status": SessionStatus.COMPLETED,
                    "state": {
                        **session.state,
                        "phase": "completed",
                        "stop_reason": stop_reason,
                        "memory": memory.model_dump(mode="json"),
                        "usage": self._ledger_data(ledger),
                    },
                    "updated_at": utc_now(),
                }
            )
            self.database.update_session(session)
            self._checkpoint(session, checkpoint_sequence, memory, ledger)
            return self._result(session, memory, ledger, stop_reason)
        except KeyboardInterrupt:
            interrupted = session.model_copy(
                update={
                    "status": SessionStatus.PAUSED,
                    "state": {
                        **session.state,
                        "phase": "paused",
                        "stop_reason": "interrupted by user",
                        "memory": memory.model_dump(mode="json"),
                        "usage": self._ledger_data(ledger),
                    },
                    "updated_at": utc_now(),
                }
            )
            self.database.update_session(interrupted)
            self._checkpoint(interrupted, checkpoint_sequence, memory, ledger)
            raise
        except AgentLimitError as exc:
            session = session.model_copy(
                update={
                    "status": SessionStatus.PAUSED,
                    "state": {
                        **session.state,
                        "phase": "paused",
                        "stop_reason": str(exc),
                        "memory": memory.model_dump(mode="json"),
                        "usage": self._ledger_data(ledger),
                    },
                    "updated_at": utc_now(),
                }
            )
            self.database.update_session(session)
            self._checkpoint(session, checkpoint_sequence, memory, ledger)
            return self._result(session, memory, ledger, str(exc))
        except Exception as exc:
            failed = session.model_copy(
                update={
                    "status": SessionStatus.FAILED,
                    "state": {
                        **session.state,
                        "phase": "failed",
                        "stop_reason": str(exc),
                        "memory": memory.model_dump(mode="json"),
                        "usage": self._ledger_data(ledger),
                    },
                    "updated_at": utc_now(),
                }
            )
            self.database.update_session(failed)
            self._checkpoint(failed, checkpoint_sequence, memory, ledger)
            raise

    def _create_plan(
        self,
        *,
        project: Project,
        session: AnalysisSession,
        goal: str,
        policy: ProjectModelPolicy,
        ledger: _Ledger,
        started: float,
    ) -> PlanDraft:
        request = self._planning_request(project, goal)
        response = self._call_model(project, session, request, policy, ledger, started)
        try:
            draft = PlanDraft.model_validate(response.structured)
            self._validate_plan(draft, goal=goal)
        except (ValidationError, PlanValidationError, ToolRegistryError) as first_error:
            self._record_plan_attempt(
                session=session,
                attempt=0,
                response=response,
                valid=False,
                validation_error=str(first_error),
            )
            repair_request = ModelRequest(
                task_type=TaskType.PLANNING,
                messages=(
                    ModelMessage(
                        role=MessageRole.SYSTEM,
                        parts=(TextPart(text=PLANNER_SYSTEM),),
                    ),
                    ModelMessage(
                        role=MessageRole.USER,
                        parts=(
                            TextPart(
                                text=plan_repair_input(
                                    response.structured or response.text,
                                    str(first_error),
                                    goal,
                                    project.scope,
                                    self.tools.list_schemas(),
                                    self.limits.max_steps,
                                )
                            ),
                        ),
                    ),
                ),
                output_schema=PlanDraft.model_json_schema(),
                output_schema_name="reverserx_plan",
                max_output_tokens=self.limits.model_output_tokens_per_call,
            )
            repaired = self._call_model(
                project, session, repair_request, policy, ledger, started
            )
            try:
                draft = PlanDraft.model_validate(repaired.structured)
                self._validate_plan(draft, goal=goal)
            except (ValidationError, PlanValidationError, ToolRegistryError) as exc:
                self._record_plan_attempt(
                    session=session,
                    attempt=1,
                    response=repaired,
                    valid=False,
                    validation_error=str(exc),
                )
                raise PlanValidationError(
                    f"model plan remained invalid after one repair: {exc}"
                ) from exc
            self._record_plan_attempt(
                session=session,
                attempt=1,
                response=repaired,
                valid=True,
                validation_error=None,
            )
            return draft
        self._record_plan_attempt(
            session=session,
            attempt=0,
            response=response,
            valid=True,
            validation_error=None,
        )
        return draft

    def _record_plan_attempt(
        self,
        *,
        session: AnalysisSession,
        attempt: int,
        response: ModelResponse,
        valid: bool,
        validation_error: str | None,
    ) -> None:
        self.database.save_plan_attempt(
            PlanAttempt(
                session_id=session.id,
                attempt=attempt,
                response=response.structured,
                raw_text=response.text,
                valid=valid,
                validation_error=validation_error,
            )
        )

    def _planning_request(self, project: Project, goal: str) -> ModelRequest:
        return ModelRequest(
            task_type=TaskType.PLANNING,
            messages=(
                ModelMessage(
                    role=MessageRole.SYSTEM,
                    parts=(TextPart(text=PLANNER_SYSTEM),),
                ),
                ModelMessage(
                    role=MessageRole.USER,
                    parts=(
                        TextPart(
                            text=planner_input(
                                goal,
                                project.scope,
                                self.tools.list_schemas(),
                                self.limits.max_steps,
                            )
                        ),
                    ),
                ),
            ),
            output_schema=PlanDraft.model_json_schema(),
            output_schema_name="reverserx_plan",
            max_output_tokens=self.limits.model_output_tokens_per_call,
        )

    def _validate_plan(self, draft: PlanDraft, *, goal: str) -> None:
        if len(draft.steps) > self.limits.max_steps:
            raise PlanValidationError(
                f"plan contains {len(draft.steps)} steps; limit is {self.limits.max_steps}"
            )
        for index, step in enumerate(draft.steps):
            if any(
                dependency < 0 or dependency >= index for dependency in step.depends_on
            ):
                raise PlanValidationError(
                    f"plan step {index} has a dependency that is not an earlier step"
                )
            self._validate_tool_step(step)
        for schema in self.tools.list_schemas():
            tool_name = schema.get("name")
            if not isinstance(tool_name, str):
                continue
            final_tool_pattern = re.compile(
                rf"\b(?:finish|end|conclude)\s+(?:the\s+plan\s+)?with\s+`?"
                rf"{re.escape(tool_name)}`?\b",
                re.IGNORECASE,
            )
            if (
                final_tool_pattern.search(goal)
                and draft.steps[-1].tool_name != tool_name
            ):
                raise PlanValidationError(
                    f"goal requires {tool_name} as the final plan step"
                )

    def _validate_tool_step(self, step: PlanStepDraft) -> None:
        self.tools.validate_arguments(step.tool_name, step.arguments)
        timeout = step.arguments.get("timeout_seconds")
        if (
            isinstance(timeout, (int, float))
            and not isinstance(timeout, bool)
            and timeout > self.limits.max_tool_duration_seconds
        ):
            raise PlanValidationError(
                f"tool timeout {timeout} exceeds run limit "
                f"{self.limits.max_tool_duration_seconds}"
            )

    def _persist_plan(
        self, session: AnalysisSession, draft: PlanDraft
    ) -> list[PlanStep]:
        steps: list[PlanStep] = []
        for sequence, item in enumerate(draft.steps):
            depends_on = tuple(steps[index].id for index in item.depends_on)
            step = PlanStep(
                session_id=session.id,
                sequence=sequence,
                objective=item.objective,
                tool_name=item.tool_name,
                arguments=item.arguments,
                depends_on=depends_on,
            )
            self.database.save_plan_step(step)
            steps.append(step)
        return steps

    def _persist_injected_step(
        self,
        *,
        session: AnalysisSession,
        draft: PlanStepDraft,
        sequence: int,
        depends_on: str,
    ) -> PlanStep:
        self._validate_tool_step(draft)
        step = PlanStep(
            session_id=session.id,
            sequence=sequence,
            objective=draft.objective,
            tool_name=draft.tool_name,
            arguments=draft.arguments,
            depends_on=(depends_on,),
        )
        return self.database.save_plan_step(step)

    @staticmethod
    def _check_dynamic_scope(project: Project, step: PlanStep) -> None:
        """Reject dynamic/network steps when project scope doesn't authorize them.

        Raises PlanValidationError if the step targets an unauthorized resource.
        """
        tool_name = step.tool_name or ""
        if not (
            tool_name.startswith(("adb_", "frida_", "proxy_"))
            or tool_name in {"interaction_wait"}
        ):
            return  # Static tool — always allowed

        scope = project.scope
        dynamic_enabled = scope.get("dynamic_enabled", False)
        if not dynamic_enabled:
            raise PlanValidationError(
                f"dynamic tool '{tool_name}' requires dynamic_enabled in project scope"
            )

        args = step.arguments
        if tool_name.startswith("adb_") or tool_name.startswith("frida_"):
            serial = args.get("serial")
            if serial and "devices" in scope:
                allowed = scope["devices"]
                if isinstance(allowed, list) and allowed and serial not in allowed:
                    raise PlanValidationError(
                        f"device '{serial}' not in project scope devices"
                    )

        if tool_name.startswith("frida_") or tool_name in {"adb_logcat"}:
            package = args.get("package")
            if package and "packages" in scope:
                allowed = scope["packages"]
                if isinstance(allowed, list) and allowed and package not in allowed:
                    raise PlanValidationError(
                        f"package '{package}' not in project scope packages"
                    )

        if tool_name.startswith("proxy_"):
            if not scope.get("allow_proxy", False):
                raise PlanValidationError(
                    f"proxy tool '{tool_name}' requires allow_proxy in project scope"
                )

    def _execute_step(
        self,
        *,
        project: Project,
        session: AnalysisSession,
        step: PlanStep,
        seen_calls: dict[str, int],
    ) -> tuple[PlanStep, ToolRun, Evidence]:
        if step.tool_name is None:
            raise PlanValidationError(f"plan step {step.id} has no tool")
        self.tools.validate_arguments(step.tool_name, step.arguments)
        self._check_dynamic_scope(project, step)
        fingerprint = hashlib.sha256(
            json.dumps(
                [step.tool_name, step.arguments],
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        seen_calls[fingerprint] = seen_calls.get(fingerprint, 0) + 1
        if seen_calls[fingerprint] > self.limits.max_retries + 1:
            raise AgentLimitError(
                f"loop detected for repeated tool call {step.tool_name}"
            )
        running = step.model_copy(
            update={
                "status": PlanStepStatus.RUNNING,
                "attempts": step.attempts + 1,
                "last_error": None,
            }
        )
        self.database.update_plan_step(running)
        tool = self.tools.get(step.tool_name)
        try:
            result = self.tools.execute(
                step.tool_name,
                ToolContext(
                    project_id=project.id,
                    data_dir=self.data_dir,
                    database_path=self.database.path,
                    artifact_root=self.artifact_root,
                    session_id=session.id,
                ),
                step.arguments,
            )
            run = ToolRun(
                project_id=project.id,
                session_id=session.id,
                tool_name=step.tool_name,
                tool_version=tool.version,
                status=ToolRunStatus.SUCCEEDED,
                input_data=step.arguments,
                output_data=result.output,
                completed_at=utc_now(),
            )
            notices = result.notices
        except Exception as exc:
            run = ToolRun(
                project_id=project.id,
                session_id=session.id,
                tool_name=step.tool_name,
                tool_version=tool.version,
                status=ToolRunStatus.FAILED,
                input_data=step.arguments,
                error=str(exc),
                completed_at=utc_now(),
            )
            notices = ()
        run = self.database.record_tool_run(run)
        updated = running.model_copy(
            update={"tool_run_id": run.id, "last_error": run.error}
        )
        self.database.update_plan_step(updated)
        source_references = _source_references(run.tool_name, run.output_data)
        # Phase 3: map dynamic tools to appropriate evidence kinds
        if run.tool_name.startswith("frida_"):
            evidence_kind = EvidenceKind.RUNTIME_EVENT
        elif run.tool_name.startswith("proxy_"):
            evidence_kind = EvidenceKind.NETWORK_FLOW
        else:
            evidence_kind = EvidenceKind.TOOL_OUTPUT
        evidence = self.database.save_evidence(
            Evidence(
                project_id=project.id,
                tool_run_id=run.id,
                kind=evidence_kind,
                locator=f"tool-run:{run.id}",
                summary=(
                    f"{run.tool_name} {run.status.value} for plan step {step.sequence}"
                    + (
                        f" with {len(source_references)} bounded source reference(s)"
                        if source_references
                        else ""
                    )
                ),
                metadata={
                    "notices": list(notices),
                    "plan_step_id": step.id,
                    "source_references": source_references,
                },
            )
        )
        return updated, run, evidence

    def _review_step(
        self,
        *,
        project: Project,
        session: AnalysisSession,
        goal: str,
        step: PlanStep,
        execution: ToolRun,
        memory: WorkingMemory,
        policy: ProjectModelPolicy,
        ledger: _Ledger,
        started: float,
        remaining_steps: int,
    ) -> ReviewerDecision:
        review_context = reviewer_input(
            goal=goal,
            step=step.model_dump(mode="json"),
            succeeded=execution.status == ToolRunStatus.SUCCEEDED,
            output=execution.output_data,
            error=execution.error,
            memory=memory.model_dump(mode="json"),
            remaining_steps=remaining_steps,
        )
        request = ModelRequest(
            task_type=TaskType.REVIEW,
            messages=(
                ModelMessage(
                    role=MessageRole.SYSTEM,
                    parts=(TextPart(text=REVIEWER_SYSTEM),),
                ),
                ModelMessage(
                    role=MessageRole.USER,
                    parts=(TextPart(text=review_context),),
                ),
            ),
            output_schema=ReviewerDecision.model_json_schema(),
            output_schema_name="reverserx_review",
            max_output_tokens=self.limits.model_output_tokens_per_call,
        )
        response = self._call_model(project, session, request, policy, ledger, started)
        decision = self._validate_review_decision(response, review_context, policy, project, session, ledger, started)
        if decision is not None:
            return decision
        raise AgentError("reviewer decision remained invalid after one repair")

    def _validate_review_decision(
        self,
        response: ModelResponse,
        review_context: str,
        policy: ProjectModelPolicy,
        project: Project,
        session: AnalysisSession,
        ledger: _Ledger,
        started: float,
    ) -> ReviewerDecision | None:
        """Validate and optionally repair a reviewer decision.

        Returns a valid ReviewerDecision or None if repair is exhausted.
        """
        try:
            decision = ReviewerDecision.model_validate(response.structured)
        except ValidationError as first_error:
            return self._repair_review_decision(
                review_context, str(first_error), response, policy, project, session, ledger, started
            )
        # Post-validate action-specific requirements that pydantic can't enforce
        action_error: str | None = None
        if decision.action == ReviewAction.REFINE and decision.refined_arguments is None:
            action_error = (
                "action is 'refine' but refined_arguments is null — "
                "provide corrected arguments for the same tool"
            )
        elif decision.action == ReviewAction.INJECT and decision.injected_step is None:
            action_error = (
                "action is 'inject' but injected_step is null — "
                "provide the new step to inject"
            )
        if action_error is not None:
            return self._repair_review_decision(
                review_context, action_error, response, policy, project, session, ledger, started
            )
        return decision

    def _repair_review_decision(
        self,
        review_context: str,
        error: str,
        response: ModelResponse,
        policy: ProjectModelPolicy,
        project: Project,
        session: AnalysisSession,
        ledger: _Ledger,
        started: float,
    ) -> ReviewerDecision | None:
        """Attempt one repair of a reviewer decision."""
        repair_request = ModelRequest(
            task_type=TaskType.REVIEW,
            messages=(
                ModelMessage(
                    role=MessageRole.SYSTEM,
                    parts=(TextPart(text=REVIEWER_SYSTEM),),
                ),
                ModelMessage(
                    role=MessageRole.USER,
                    parts=(
                        TextPart(
                            text=review_repair_input(
                                review_context,
                                response.structured or response.text,
                                error,
                                self.tools.list_schemas(),
                            )
                        ),
                    ),
                ),
            ),
            output_schema=ReviewerDecision.model_json_schema(),
            output_schema_name="reverserx_review_repair",
            max_output_tokens=self.limits.model_output_tokens_per_call,
        )
        repaired = self._call_model(
            project, session, repair_request, policy, ledger, started
        )
        try:
            decision = ReviewerDecision.model_validate(repaired.structured)
        except ValidationError:
            return None
        # Re-check action-specific requirements on repaired decision
        if decision.action == ReviewAction.REFINE and decision.refined_arguments is None:
            return None
        if decision.action == ReviewAction.INJECT and decision.injected_step is None:
            return None
        return decision

    def _record_review(
        self,
        *,
        project: Project,
        decision: ReviewerDecision,
        evidence: Evidence,
        memory: WorkingMemory,
    ) -> WorkingMemory:
        finding_ids = list(memory.finding_ids)
        for draft in decision.findings:
            try:
                severity = FindingSeverity(draft.severity)
            except ValueError as exc:
                raise AgentError(
                    f"reviewer returned unsupported finding severity: {draft.severity}"
                ) from exc
            finding = self.database.save_finding(
                Finding(
                    project_id=project.id,
                    title=draft.title,
                    description=f"Model interpretation: {draft.description}",
                    severity=severity,
                    confidence=draft.confidence,
                    evidence_ids=(evidence.id,),
                    inference=True,
                )
            )
            finding_ids.append(finding.id)
        return WorkingMemory(
            finding_ids=tuple(dict.fromkeys(finding_ids)),
            hypotheses=tuple(dict.fromkeys((*memory.hypotheses, *decision.hypotheses))),
            key_locations=tuple(
                dict.fromkeys((*memory.key_locations, *decision.key_locations))
            ),
            unresolved_items=tuple(
                dict.fromkeys((*memory.unresolved_items, *decision.unresolved_items))
            ),
        )

    def _call_model(
        self,
        project: Project,
        session: AnalysisSession,
        request: ModelRequest,
        policy: ProjectModelPolicy,
        ledger: _Ledger,
        started: float,
    ) -> ModelResponse:
        self._check_wall_time(started)
        capability = self.router.route(request, policy)
        estimate = self.router.estimate(request, capability)
        self._check_projected_limits(ledger, estimate)
        provider = self.providers.get(capability)
        attempts = 0
        while True:
            try:
                response = provider.generate(request)
                break
            except ProviderError as exc:
                if not exc.transient or attempts >= self.limits.max_retries:
                    raise
                attempts += 1
                self._check_wall_time(started)
        actual_cost = self._actual_cost(response, capability)
        ledger.input_tokens += response.usage.input_tokens
        ledger.output_tokens += response.usage.output_tokens
        ledger.actual_cost_usd = round(ledger.actual_cost_usd + actual_cost, 8)
        self.database.record_model_usage(
            ModelUsage(
                project_id=project.id,
                session_id=session.id,
                provider=response.provider,
                model=response.model,
                task_type=request.task_type.value,
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
                input_image_count=request.image_count,
                estimated_cost_usd=estimate.estimated_cost_usd,
                actual_cost_usd=actual_cost,
                request_id=response.request_id,
            )
        )
        if ledger.input_tokens > self.limits.max_input_tokens:
            raise AgentLimitError("input-token limit reached")
        if ledger.output_tokens > self.limits.max_output_tokens:
            raise AgentLimitError("output-token limit reached")
        if ledger.actual_cost_usd > self.limits.max_cost_usd:
            raise AgentLimitError("cost limit reached")
        return response

    def _check_projected_limits(self, ledger: _Ledger, estimate: CostEstimate) -> None:
        if ledger.input_tokens + estimate.input_tokens > self.limits.max_input_tokens:
            raise AgentLimitError("input-token limit would be exceeded")
        if (
            ledger.output_tokens + estimate.output_tokens
            > self.limits.max_output_tokens
        ):
            raise AgentLimitError("output-token limit would be exceeded")
        if (
            ledger.actual_cost_usd + estimate.estimated_cost_usd
            > self.limits.max_cost_usd
        ):
            raise AgentLimitError("cost limit would be exceeded")

    @staticmethod
    def _actual_cost(response: ModelResponse, capability: ModelCapability) -> float:
        cost = (
            response.usage.input_tokens * capability.input_cost_per_million
            + response.usage.output_tokens * capability.output_cost_per_million
            + response.usage.image_tokens * capability.image_cost_per_million
        ) / 1_000_000
        return round(cost, 8)

    def _check_wall_time(self, started: float) -> None:
        if time.monotonic() - started > self.limits.max_wall_time_seconds:
            raise AgentLimitError("wall-time limit reached")

    def _require_retry_available(self, step: PlanStep) -> None:
        if step.attempts > self.limits.max_retries:
            raise AgentLimitError(f"retry limit reached for plan step {step.sequence}")

    @staticmethod
    def _dependencies_completed(step: PlanStep, steps: list[PlanStep]) -> bool:
        by_id = {candidate.id: candidate for candidate in steps}
        return all(
            dependency in by_id and by_id[dependency].status == PlanStepStatus.COMPLETED
            for dependency in step.depends_on
        )

    def _checkpoint(
        self,
        session: AnalysisSession,
        sequence: int,
        memory: WorkingMemory,
        ledger: _Ledger,
    ) -> int:
        next_sequence = sequence + 1
        self.database.save_checkpoint(
            AgentCheckpoint(
                session_id=session.id,
                sequence=next_sequence,
                state={
                    "session_status": session.status.value,
                    "memory": memory.model_dump(mode="json"),
                    "usage": self._ledger_data(ledger),
                    "steps": [
                        step.model_dump(mode="json")
                        for step in self.database.list_plan_steps(session.id)
                    ],
                },
            )
        )
        return next_sequence

    def _update_session(
        self,
        session: AnalysisSession,
        *,
        phase: str,
        stop_reason: str | None,
        memory: WorkingMemory,
        ledger: _Ledger,
    ) -> AnalysisSession:
        updated = session.model_copy(
            update={
                "state": {
                    **session.state,
                    "phase": phase,
                    "stop_reason": stop_reason,
                    "memory": memory.model_dump(mode="json"),
                    "usage": self._ledger_data(ledger),
                },
                "updated_at": utc_now(),
            }
        )
        return self.database.update_session(updated)

    @staticmethod
    def _ledger_data(ledger: _Ledger) -> dict[str, int | float]:
        return {
            "input_tokens": ledger.input_tokens,
            "output_tokens": ledger.output_tokens,
            "actual_cost_usd": ledger.actual_cost_usd,
        }

    def _result(
        self,
        session: AnalysisSession,
        memory: WorkingMemory,
        ledger: _Ledger,
        stop_reason: str,
    ) -> AgentRunResult:
        finding_by_id = {
            finding.id: finding
            for finding in self.database.list_findings(session.project_id)
        }
        return AgentRunResult(
            session=session,
            steps=tuple(self.database.list_plan_steps(session.id)),
            findings=tuple(
                finding_by_id[finding_id]
                for finding_id in memory.finding_ids
                if finding_id in finding_by_id
            ),
            memory=memory,
            input_tokens=ledger.input_tokens,
            output_tokens=ledger.output_tokens,
            actual_cost_usd=ledger.actual_cost_usd,
            stop_reason=stop_reason,
        )


def _source_references(
    tool_name: str, output: dict[str, object]
) -> list[dict[str, object]]:
    key = "hits" if tool_name == "source_search" else "matches"
    if tool_name not in {"source_search", "context_query"}:
        return []
    candidates = output.get(key)
    if not isinstance(candidates, list):
        return []
    references: list[dict[str, object]] = []
    for candidate in candidates[:20]:
        if not isinstance(candidate, dict):
            continue
        path = candidate.get("path")
        start_line = candidate.get("start_line")
        end_line = candidate.get("end_line")
        if (
            not isinstance(path, str)
            or not isinstance(start_line, int)
            or isinstance(start_line, bool)
            or not isinstance(end_line, int)
            or isinstance(end_line, bool)
        ):
            continue
        reference: dict[str, object] = {
            "path": path,
            "start_line": start_line,
            "end_line": end_line,
        }
        symbol = candidate.get("symbol")
        if isinstance(symbol, str) and symbol:
            reference["symbol"] = symbol
        references.append(reference)
    return references
