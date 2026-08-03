"""Deterministic token estimation and ranked context packing."""

from __future__ import annotations

import math
from collections.abc import Iterable
from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from reverserx.context.chunking import SourceChunk

PACKED_CONTEXT_SCHEMA_VERSION: Literal["1.0"] = "1.0"


class ContextRepresentation(StrEnum):
    """How a selected source chunk is represented in the packed prompt."""

    SOURCE = "source"
    SUMMARY = "summary"


class RankedChunk(BaseModel):
    """A retrieval candidate and optional externally-produced summary."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    chunk: SourceChunk
    score: float
    summary: str | None = None

    @field_validator("score")
    @classmethod
    def require_finite_score(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("score must be finite")
        return value

    @field_validator("summary")
    @classmethod
    def normalize_summary(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("summary cannot be blank")
        return normalized


class PackedContextItem(BaseModel):
    """One selected representation in a packed context manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    chunk_id: str
    path: str
    symbol: str | None = None
    rank: int = Field(ge=1)
    score: float
    representation: ContextRepresentation
    estimated_tokens: int = Field(ge=1)
    text: str = Field(min_length=1)


class PackedContext(BaseModel):
    """A reproducible context payload that cannot exceed its stated budget."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["1.0"] = PACKED_CONTEXT_SCHEMA_VERSION
    token_budget: int = Field(ge=0)
    used_tokens: int = Field(ge=0)
    remaining_tokens: int = Field(ge=0)
    per_item_overhead_tokens: int = Field(ge=0)
    items: tuple[PackedContextItem, ...]
    omitted_chunk_ids: tuple[str, ...]
    text: str

    @model_validator(mode="after")
    def validate_accounting(self) -> Self:
        if self.used_tokens > self.token_budget:
            raise ValueError("used_tokens cannot exceed token_budget")
        if self.remaining_tokens != self.token_budget - self.used_tokens:
            raise ValueError("remaining_tokens does not match token accounting")
        expected = estimate_tokens(self.text) + self.per_item_overhead_tokens * len(
            self.items
        )
        if self.used_tokens != expected:
            raise ValueError("used_tokens does not match packed text")
        return self


def estimate_tokens(text: str) -> int:
    """Estimate tokens as the ceiling of UTF-8 bytes divided by four.

    This approximation is deliberately stable across hosts and has no model or
    tokenizer dependency.  Provider-specific tokenizers may replace it at a
    higher layer when exact billing counts are required.
    """

    if not text:
        return 0
    return (len(text.encode("utf-8")) + 3) // 4


def _single_line(value: str) -> str:
    return " ".join(value.splitlines())


def render_source_chunk(chunk: SourceChunk) -> str:
    """Render a source chunk with evidence metadata for prompt inclusion."""

    metadata = [
        f"id={chunk.id}",
        f"path={chunk.path}",
        f"lines={chunk.start_line}-{chunk.end_line}",
        f"language={chunk.language.value}",
        f"kind={chunk.kind.value}",
    ]
    if chunk.symbol is not None:
        metadata.append(f"symbol={_single_line(chunk.symbol)}")
    if chunk.start_instruction is not None and chunk.end_instruction is not None:
        metadata.append(
            f"instructions={chunk.start_instruction}-{chunk.end_instruction}"
        )
    header = " ".join(metadata)
    return f"[source {header}]\n{chunk.content}\n[/source]"


def render_chunk_summary(chunk: SourceChunk, summary: str) -> str:
    """Render a summary while retaining the source evidence locator."""

    normalized = summary.strip()
    if not normalized:
        raise ValueError("summary cannot be blank")
    symbol = f" symbol={_single_line(chunk.symbol)}" if chunk.symbol else ""
    return (
        f"[summary id={chunk.id} path={chunk.path} "
        f"lines={chunk.start_line}-{chunk.end_line}{symbol}]\n"
        f"{normalized}\n[/summary]"
    )


def _rank_candidates(candidates: Iterable[RankedChunk]) -> tuple[RankedChunk, ...]:
    ordered = sorted(
        candidates,
        key=lambda candidate: (
            -candidate.score,
            candidate.chunk.path.casefold(),
            candidate.chunk.start_line,
            candidate.chunk.id,
            candidate.summary or "",
        ),
    )
    unique: list[RankedChunk] = []
    seen_ids: set[str] = set()
    for candidate in ordered:
        if candidate.chunk.id in seen_ids:
            continue
        seen_ids.add(candidate.chunk.id)
        unique.append(candidate)
    return tuple(unique)


def pack_context(
    candidates: Iterable[RankedChunk],
    *,
    token_budget: int,
    allow_summary_fallback: bool = True,
    per_item_overhead_tokens: int = 0,
) -> PackedContext:
    """Greedily pack candidates by score without exceeding ``token_budget``.

    A full source chunk is always preferred.  If it does not fit and summary
    fallback is enabled, its summary is considered before moving to the next
    ranked candidate.  Candidates are de-duplicated by stable chunk identity.
    """

    if token_budget < 0:
        raise ValueError("token_budget cannot be negative")
    if per_item_overhead_tokens < 0:
        raise ValueError("per_item_overhead_tokens cannot be negative")

    ranked = _rank_candidates(candidates)
    selected: list[PackedContextItem] = []
    omitted: list[str] = []
    packed_text = ""
    used_tokens = 0

    for rank, candidate in enumerate(ranked, start=1):
        full_text = render_source_chunk(candidate.chunk)
        representations = [(ContextRepresentation.SOURCE, full_text)]
        if allow_summary_fallback and candidate.summary is not None:
            representations.append(
                (
                    ContextRepresentation.SUMMARY,
                    render_chunk_summary(candidate.chunk, candidate.summary),
                )
            )

        chosen: tuple[ContextRepresentation, str, int, str] | None = None
        for representation, rendered in representations:
            prospective_text = (
                rendered if not packed_text else f"{packed_text}\n\n{rendered}"
            )
            prospective_tokens = estimate_tokens(prospective_text) + (
                per_item_overhead_tokens * (len(selected) + 1)
            )
            if prospective_tokens <= token_budget:
                marginal_tokens = prospective_tokens - used_tokens
                chosen = (
                    representation,
                    rendered,
                    marginal_tokens,
                    prospective_text,
                )
                break

        if chosen is None:
            omitted.append(candidate.chunk.id)
            continue

        representation, rendered, marginal_tokens, packed_text = chosen
        used_tokens += marginal_tokens
        selected.append(
            PackedContextItem(
                chunk_id=candidate.chunk.id,
                path=candidate.chunk.path,
                symbol=candidate.chunk.symbol,
                rank=rank,
                score=candidate.score,
                representation=representation,
                estimated_tokens=marginal_tokens,
                text=rendered,
            )
        )

    return PackedContext(
        token_budget=token_budget,
        used_tokens=used_tokens,
        remaining_tokens=token_budget - used_tokens,
        per_item_overhead_tokens=per_item_overhead_tokens,
        items=tuple(selected),
        omitted_chunk_ids=tuple(omitted),
        text=packed_text,
    )
