"""Typed state and decisions for the bounded analysis agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from reverserx.core.models import AnalysisSession, Finding, PlanStep


class PlanStepDraft(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    objective: str = Field(min_length=1, max_length=1_000)
    tool_name: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    depends_on: tuple[int, ...] = ()


class PlanDraft(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rationale: str = Field(min_length=1)
    steps: tuple[PlanStepDraft, ...] = Field(min_length=1)


class ReviewAction(StrEnum):
    ACCEPT = "accept"
    RETRY = "retry"
    REFINE = "refine"
    INJECT = "inject"
    STOP = "stop"


class FindingDraft(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    title: str = Field(min_length=1, max_length=500)
    description: str = Field(min_length=1)
    severity: str = "info"
    confidence: float = Field(default=0.5, ge=0, le=1)


class ReviewerDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action: ReviewAction
    rationale: str = Field(min_length=1)
    refined_arguments: dict[str, Any] | None = None
    injected_step: PlanStepDraft | None = None
    findings: tuple[FindingDraft, ...] = ()
    hypotheses: tuple[str, ...] = ()
    key_locations: tuple[str, ...] = ()
    unresolved_items: tuple[str, ...] = ()


class WorkingMemory(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_ids: tuple[str, ...] = ()
    hypotheses: tuple[str, ...] = ()
    key_locations: tuple[str, ...] = ()
    unresolved_items: tuple[str, ...] = ()
    # Phase 3 — Dynamic analysis state
    active_device: str | None = None
    active_frida_session: str | None = None
    active_proxy_port: int | None = None
    needs_user_interaction: bool = False


class AgentLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_steps: int = Field(default=30, ge=1, le=1_000)
    max_retries: int = Field(default=2, ge=0, le=20)
    max_input_tokens: int = Field(default=500_000, ge=1)
    max_output_tokens: int = Field(default=100_000, ge=1)
    max_cost_usd: float = Field(default=5, ge=0)
    max_wall_time_seconds: float = Field(default=3_600, gt=0)
    max_tool_duration_seconds: float = Field(default=900, gt=0)
    model_output_tokens_per_call: int = Field(default=4_096, ge=128)


class AgentRunEstimate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: str
    model: str
    projected_model_calls: int = Field(ge=1)
    projected_input_tokens: int = Field(ge=0)
    projected_output_tokens: int = Field(ge=0)
    projected_cost_usd: float = Field(ge=0)
    requires_confirmation: bool = True


class AgentRunResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    session: AnalysisSession
    steps: tuple[PlanStep, ...]
    findings: tuple[Finding, ...]
    memory: WorkingMemory
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    actual_cost_usd: float = Field(ge=0)
    stop_reason: str


class AgentError(RuntimeError):
    """Base error for bounded agent failures."""


class PlanValidationError(AgentError):
    """Raised before execution when a model plan violates tool contracts."""


class AgentLimitError(AgentError):
    """Raised when an explicit run limit stops further work."""
