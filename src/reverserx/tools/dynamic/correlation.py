"""Deterministic evidence correlation tool — links static, runtime, and network evidence."""

from __future__ import annotations

import sqlite3

from pydantic import BaseModel, ConfigDict, Field

from reverserx.core.correlation import CorrelationRecord
from reverserx.tools.base import BaseTool, ToolContext, ToolExecution


class CorrelationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_evidence_id: str = Field(
        default="",
        description="Static analysis evidence ID (source_search, context_query, etc.)",
    )
    runtime_evidence_id: str = Field(
        default="",
        description="Runtime evidence ID from Frida hook events",
    )
    network_evidence_id: str = Field(
        default="",
        description="Network capture evidence ID from proxy/har import",
    )
    relationship: str = Field(
        default="informs",
        description="How the evidence relates: validates, contradicts, informs",
    )
    rationale: str = Field(
        default="",
        min_length=1,
        description="Why these pieces of evidence are linked",
    )


class CorrelateEvidenceTool(BaseTool[CorrelationInput]):
    name = "correlate_evidence"
    description = (
        "Link static, runtime, and network evidence into a correlation chain. "
        "Creates a CorrelationRecord linking up to three evidence types."
    )
    version = "1.0.0"
    input_model = CorrelationInput

    def execute(self, context: ToolContext, arguments: CorrelationInput) -> ToolExecution:
        # Validate at least one evidence ID is provided
        ids = [
            eid
            for eid in (
                arguments.source_evidence_id,
                arguments.runtime_evidence_id,
                arguments.network_evidence_id,
            )
            if eid
        ]
        if not ids:
            return ToolExecution(
                output={"error": "At least one evidence ID must be provided"},
                notices=("No evidence IDs provided for correlation.",),
            )

        record = CorrelationRecord(
            project_id=context.project_id,
            session_id=context.session_id,
            source_evidence_id=arguments.source_evidence_id or None,
            runtime_evidence_id=arguments.runtime_evidence_id or None,
            network_evidence_id=arguments.network_evidence_id or None,
            relationship=arguments.relationship,
            description=arguments.rationale,
            confidence=0.8,  # Deterministic tool = high confidence
        )

        # Persist to database if available
        persisted = False
        if context.database_path:
            try:
                db = sqlite3.connect(str(context.database_path))
                db.execute(
                    """
                    INSERT INTO correlation_records
                    (id, schema_version, project_id, session_id,
                     source_evidence_id, runtime_evidence_id, network_evidence_id,
                     relationship, confidence, description, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.id,
                        "1.0",
                        record.project_id,
                        record.session_id,
                        record.source_evidence_id,
                        record.runtime_evidence_id,
                        record.network_evidence_id,
                        record.relationship,
                        record.confidence,
                        record.description,
                        record.created_at.isoformat(),
                    ),
                )
                db.commit()
                db.close()
                persisted = True
            except sqlite3.Error as exc:
                return ToolExecution(
                    output={"error": str(exc), "record_id": record.id},
                    notices=(f"Failed to persist correlation: {exc}",),
                )

        return ToolExecution(
            output={
                "correlation_id": record.id,
                "persisted": persisted,
                "source_evidence_id": record.source_evidence_id,
                "runtime_evidence_id": record.runtime_evidence_id,
                "network_evidence_id": record.network_evidence_id,
                "relationship": record.relationship,
            },
            notices=(
                f"Correlation {record.id} created: "
                f"source={record.source_evidence_id or 'none'}, "
                f"runtime={record.runtime_evidence_id or 'none'}, "
                f"network={record.network_evidence_id or 'none'}, "
                f"relationship={record.relationship}",
            ),
        )
