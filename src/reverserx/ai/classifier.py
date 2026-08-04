"""Deterministic task classification independent of provider model names."""

from __future__ import annotations

from reverserx.ai.models import Modality, TaskType


def classify_task(goal: str, modalities: frozenset[Modality]) -> TaskType:
    normalized = goal.casefold()
    if Modality.IMAGE in modalities:
        return TaskType.VISUAL_ANALYSIS
    if any(word in normalized for word in ("report", "summarize", "write-up")):
        return TaskType.REPORTING
    if any(
        word in normalized
        for word in ("source", "method", "class", "code", "encryption", "cipher")
    ):
        return TaskType.CODE_ANALYSIS
    return TaskType.PLANNING
