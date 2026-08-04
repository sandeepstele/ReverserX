"""Cross-domain correlation records linking static, runtime, and network evidence."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from reverserx.core.models import new_id, utc_now


class CorrelationRecord(BaseModel):
    """Connects evidence across static, runtime, and network domains.

    A correlation answers: "The static crypto method at X was observed at
    runtime via Frida hook Y, producing the encrypted field Z seen in
    captured API flow W."
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(default_factory=lambda: new_id("cor"))
    project_id: str
    session_id: str | None = None
    source_evidence_id: str | None = None
    runtime_evidence_id: str | None = None
    network_evidence_id: str | None = None
    relationship: str = Field(
        min_length=1,
        description="e.g. crypto_method_to_encrypted_field, intent_sender_to_receiver",
    )
    confidence: float = Field(default=0.5, ge=0, le=1)
    description: str = ""
    created_at: datetime = Field(default_factory=utc_now)
