"""Versioned domain models shared by storage, tools, and the future agent."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "1.0"


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


class SchemaModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = SCHEMA_VERSION


class Project(SchemaModel):
    id: str = Field(default_factory=lambda: new_id("prj"))
    slug: str
    name: str
    description: str = ""
    scope: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, value: str) -> str:
        if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", value) is None:
            raise ValueError(
                "slug must contain lowercase ASCII words separated by hyphens"
            )
        return value


class SessionStatus(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AnalysisSession(SchemaModel):
    id: str = Field(default_factory=lambda: new_id("ses"))
    project_id: str
    goal: str
    status: SessionStatus = SessionStatus.CREATED
    state: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class Artifact(SchemaModel):
    id: str = Field(default_factory=lambda: new_id("art"))
    project_id: str
    sha256: str = Field(min_length=64, max_length=64)
    original_name: str
    media_type: str = "application/octet-stream"
    size_bytes: int = Field(ge=0)
    stored_path: str
    imported_at: datetime = Field(default_factory=utc_now)


class ToolRunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class ToolRun(SchemaModel):
    id: str = Field(default_factory=lambda: new_id("run"))
    project_id: str
    session_id: str | None = None
    tool_name: str
    tool_version: str
    status: ToolRunStatus
    input_data: dict[str, Any] = Field(default_factory=dict)
    output_data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None


class EvidenceKind(StrEnum):
    ARTIFACT = "artifact"
    SOURCE = "source"
    TOOL_OUTPUT = "tool_output"
    RUNTIME_EVENT = "runtime_event"
    NETWORK_FLOW = "network_flow"


class Evidence(SchemaModel):
    id: str = Field(default_factory=lambda: new_id("evd"))
    project_id: str
    tool_run_id: str | None = None
    artifact_id: str | None = None
    kind: EvidenceKind
    locator: str
    summary: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime = Field(default_factory=utc_now)


class FindingStatus(StrEnum):
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    MITIGATED = "mitigated"
    DUPLICATE = "duplicate"


class FindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(SchemaModel):
    id: str = Field(default_factory=lambda: new_id("fnd"))
    project_id: str
    title: str
    description: str
    status: FindingStatus = FindingStatus.CANDIDATE
    severity: FindingSeverity = FindingSeverity.INFO
    confidence: float = Field(default=0.5, ge=0, le=1)
    evidence_ids: tuple[str, ...] = ()
    inference: bool = True
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class PlanStepStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class PlanStep(SchemaModel):
    id: str = Field(default_factory=lambda: new_id("stp"))
    session_id: str
    sequence: int = Field(ge=0)
    objective: str
    tool_name: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    status: PlanStepStatus = PlanStepStatus.PENDING
    depends_on: tuple[str, ...] = ()
    tool_run_id: str | None = None
    attempts: int = Field(default=0, ge=0)
    last_error: str | None = None


class PlanAttempt(SchemaModel):
    id: str = Field(default_factory=lambda: new_id("pla"))
    session_id: str
    attempt: int = Field(ge=0)
    response: dict[str, Any] | None = None
    raw_text: str = ""
    valid: bool
    validation_error: str | None = None
    created_at: datetime = Field(default_factory=utc_now)


class ModelUsage(SchemaModel):
    id: str = Field(default_factory=lambda: new_id("mdl"))
    project_id: str
    session_id: str | None = None
    provider: str
    model: str
    task_type: str
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    input_image_count: int = Field(default=0, ge=0)
    estimated_cost_usd: float = Field(ge=0)
    actual_cost_usd: float | None = Field(default=None, ge=0)
    request_id: str | None = None
    created_at: datetime = Field(default_factory=utc_now)


class AgentCheckpoint(SchemaModel):
    id: str = Field(default_factory=lambda: new_id("chk"))
    session_id: str
    sequence: int = Field(ge=0)
    state: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
