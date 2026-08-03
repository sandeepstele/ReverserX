"""Deterministic exact-text and regular-expression search over source chunks."""

from __future__ import annotations

import importlib
import math
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from heapq import heappush, heapreplace
from typing import Literal, Protocol, Self, TypeAlias, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from reverserx.context.chunking import ChunkKind, SourceChunk, SourceLanguage

SEARCH_RESULT_SCHEMA_VERSION: Literal["1.1"] = "1.1"
MAX_REGEX_PATTERN_CHARS = 4096
DEFAULT_REGEX_TIMEOUT_SECONDS = 1.0
MAX_REGEX_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_MATCH_LINES = 200
MAX_MATCH_LINES = 10_000
_DEADLINE_CHECK_INTERVAL = 256


class RegexSearchUnavailableError(RuntimeError):
    """Raised when regex mode is used without the Phase 1 dependency."""


class RegexSearchTimeoutError(TimeoutError):
    """Raised when a regular expression exceeds its per-chunk time budget."""


class _MatchLike(Protocol):
    def start(self, group: int = 0, /) -> int: ...


class _TimeoutPattern(Protocol):
    def search(self, string: str, *, timeout: float) -> _MatchLike | None: ...

    def finditer(self, string: str, *, timeout: float) -> Iterable[_MatchLike]: ...


class _RegexModule(Protocol):
    def compile(self, pattern: str, flags: int = 0) -> _TimeoutPattern: ...


@dataclass(frozen=True, slots=True)
class _CompiledPattern:
    exact: re.Pattern[str] | None = None
    regex: _TimeoutPattern | None = None
    timeout_seconds: float = DEFAULT_REGEX_TIMEOUT_SECONDS

    @property
    def is_regex(self) -> bool:
        return self.regex is not None

    def finditer(self, text: str) -> Iterable[_MatchLike]:
        if self.exact is not None:
            return self.exact.finditer(text)
        if self.regex is None:  # pragma: no cover - internal construction invariant
            raise AssertionError("compiled search pattern is unavailable")
        return self.regex.finditer(text, timeout=self.timeout_seconds)


class SearchMode(StrEnum):
    """Supported lexical matching modes."""

    EXACT = "exact"
    REGEX = "regex"


class LexicalSearchHit(BaseModel):
    """A bounded preview and complete per-chunk match count."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["1.1"] = SEARCH_RESULT_SCHEMA_VERSION
    chunk_id: str
    language: SourceLanguage
    kind: ChunkKind
    path: str
    symbol: str | None = None
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    start_instruction: int | None = Field(default=None, ge=1)
    end_instruction: int | None = Field(default=None, ge=1)
    match_count: int = Field(ge=1)
    distinct_match_line_count: int = Field(ge=1)
    match_lines: tuple[int, ...] = Field(min_length=1, max_length=MAX_MATCH_LINES)
    match_lines_truncated: bool
    excerpt: str = Field(min_length=1)
    excerpt_start_line: int = Field(ge=1)
    excerpt_end_line: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_match_line_accounting(self) -> Self:
        if tuple(sorted(set(self.match_lines))) != self.match_lines:
            raise ValueError("match_lines must be sorted and unique")
        if self.distinct_match_line_count < len(self.match_lines):
            raise ValueError(
                "distinct_match_line_count cannot be smaller than match_lines"
            )
        expected_truncation = self.distinct_match_line_count > len(self.match_lines)
        if self.match_lines_truncated is not expected_truncation:
            raise ValueError("match_lines_truncated does not match line accounting")
        return self


_HitRank: TypeAlias = tuple[int, str, int, str]


@dataclass(frozen=True, slots=True)
class _RankedHit:
    """Reverse rank ordering so the heap root is the least useful hit."""

    rank: _HitRank
    hit: LexicalSearchHit

    def __lt__(self, other: _RankedHit) -> bool:
        return self.rank > other.rank


def _hit_rank(hit: LexicalSearchHit) -> _HitRank:
    return (
        -hit.match_count,
        hit.path.casefold(),
        hit.start_line,
        hit.chunk_id,
    )


def _retain_ranked_hit(
    retained: list[_RankedHit],
    hit: LexicalSearchHit,
    *,
    max_results: int,
) -> None:
    """Keep only the best ``max_results`` hits seen so far."""

    candidate = _RankedHit(rank=_hit_rank(hit), hit=hit)
    if len(retained) < max_results:
        heappush(retained, candidate)
    elif candidate.rank < retained[0].rank:
        heapreplace(retained, candidate)


def _compile_pattern(
    query: str,
    mode: SearchMode,
    *,
    case_sensitive: bool,
    regex_timeout_seconds: float,
) -> _CompiledPattern:
    if not query:
        raise ValueError("query cannot be empty")
    if mode is SearchMode.REGEX and len(query) > MAX_REGEX_PATTERN_CHARS:
        raise ValueError(
            f"regular expression cannot exceed {MAX_REGEX_PATTERN_CHARS} characters"
        )

    flags = re.MULTILINE
    if not case_sensitive:
        flags |= re.IGNORECASE
    if mode is SearchMode.EXACT:
        pattern = re.compile(re.escape(query), flags)
        if pattern.search("") is not None:  # pragma: no cover - escaped non-empty query
            raise ValueError("query must not match empty text")
        return _CompiledPattern(exact=pattern)

    try:
        module = cast(_RegexModule, importlib.import_module("regex"))
    except ImportError as error:
        raise RegexSearchUnavailableError(
            "regex search requires the Phase 1 dependencies; "
            "run `uv sync --extra phase1`"
        ) from error
    try:
        timeout_pattern = module.compile(query, int(flags))
        empty_match = timeout_pattern.search("", timeout=regex_timeout_seconds)
    except TimeoutError as error:
        raise ValueError("regular expression timed out during validation") from error
    except Exception as error:
        raise ValueError(f"invalid regular expression: {error}") from error
    if empty_match is not None:
        raise ValueError("query must not match empty text")
    return _CompiledPattern(
        regex=timeout_pattern,
        timeout_seconds=regex_timeout_seconds,
    )


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _bounded_excerpt(
    content: str,
    *,
    match_start: int,
    context_lines: int,
    max_chars: int,
    chunk_start_line: int,
) -> tuple[str, int, int]:
    lines = content.splitlines(keepends=True)
    local_match_line = _line_number(content, match_start)
    first_local_line = max(1, local_match_line - context_lines)
    last_local_line = min(len(lines), local_match_line + context_lines)

    content_start = sum(len(line) for line in lines[: first_local_line - 1])
    raw_excerpt = "".join(lines[first_local_line - 1 : last_local_line])
    relative_match_start = max(0, match_start - content_start)

    clip_start = 0
    clip_end = len(raw_excerpt)
    prefix = ""
    suffix = ""
    if len(raw_excerpt) > max_chars:
        # Keep roughly one third of the available space before the first match.
        clip_start = max(0, relative_match_start - max_chars // 3)
        clip_start = min(clip_start, len(raw_excerpt) - max_chars)
        clip_end = min(len(raw_excerpt), clip_start + max_chars)
        prefix = "…" if clip_start else ""
        suffix = "…" if clip_end < len(raw_excerpt) else ""
        payload_budget = max_chars - len(prefix) - len(suffix)
        clip_end = min(len(raw_excerpt), clip_start + payload_budget)

    clipped = raw_excerpt[clip_start:clip_end]
    excerpt = f"{prefix}{clipped}{suffix}"
    if not excerpt:
        # This only occurs for a pathological all-zero budget, rejected by caller.
        excerpt = content[match_start : match_start + 1]

    skipped_lines = raw_excerpt[:clip_start].count("\n")
    excerpt_start = chunk_start_line + first_local_line - 1 + skipped_lines
    excerpt_end = excerpt_start + clipped.count("\n")
    if clipped.endswith("\n") and excerpt_end > excerpt_start:
        excerpt_end -= 1
    return excerpt, excerpt_start, max(excerpt_start, excerpt_end)


def lexical_search(
    chunks: Iterable[SourceChunk],
    query: str,
    *,
    mode: SearchMode = SearchMode.EXACT,
    case_sensitive: bool = False,
    max_results: int = 50,
    context_lines: int = 2,
    max_excerpt_chars: int = 1200,
    max_match_lines: int = DEFAULT_MAX_MATCH_LINES,
    regex_timeout_seconds: float = DEFAULT_REGEX_TIMEOUT_SECONDS,
) -> tuple[LexicalSearchHit, ...]:
    """Search chunks and return deterministic, bounded, location-rich hits.

    Every returned ``match_count`` covers the complete chunk.  The excerpt is
    centered on the first match and is capped independently from source size.
    Duplicate chunk identities are searched only once.
    """

    if max_results < 1:
        raise ValueError("max_results must be at least 1")
    if context_lines < 0:
        raise ValueError("context_lines cannot be negative")
    if max_excerpt_chars < 16:
        raise ValueError("max_excerpt_chars must be at least 16")
    if not 1 <= max_match_lines <= MAX_MATCH_LINES:
        raise ValueError(f"max_match_lines must be between 1 and {MAX_MATCH_LINES}")
    if (
        not math.isfinite(regex_timeout_seconds)
        or regex_timeout_seconds <= 0
        or regex_timeout_seconds > MAX_REGEX_TIMEOUT_SECONDS
    ):
        raise ValueError(
            "regex_timeout_seconds must be greater than 0 and no greater than "
            f"{MAX_REGEX_TIMEOUT_SECONDS}"
        )

    pattern = _compile_pattern(
        query,
        mode,
        case_sensitive=case_sensitive,
        regex_timeout_seconds=regex_timeout_seconds,
    )
    retained: list[_RankedHit] = []
    seen_ids: set[str] = set()

    for chunk in chunks:
        if chunk.id in seen_ids:
            continue
        seen_ids.add(chunk.id)
        match_count = 0
        first_match_start: int | None = None
        match_lines: list[int] = []
        distinct_match_line_count = 0
        previous_match_line: int | None = None
        scan_offset = 0
        local_line = 1
        deadline = (
            time.monotonic() + regex_timeout_seconds if pattern.is_regex else None
        )
        try:
            for match in pattern.finditer(chunk.content):
                match_count += 1
                match_start = match.start()
                if first_match_start is None:
                    first_match_start = match_start
                local_line += chunk.content.count("\n", scan_offset, match_start)
                scan_offset = match_start
                absolute_line = chunk.start_line + local_line - 1
                if previous_match_line != absolute_line:
                    distinct_match_line_count += 1
                    previous_match_line = absolute_line
                    if len(match_lines) < max_match_lines:
                        match_lines.append(absolute_line)
                if (
                    deadline is not None
                    and match_count % _DEADLINE_CHECK_INTERVAL == 0
                    and time.monotonic() > deadline
                ):
                    raise TimeoutError
        except TimeoutError as error:
            raise RegexSearchTimeoutError(
                "regular expression exceeded the per-chunk timeout of "
                f"{regex_timeout_seconds:g}s at {chunk.path}"
            ) from error

        if first_match_start is None:
            continue

        excerpt, excerpt_start, excerpt_end = _bounded_excerpt(
            chunk.content,
            match_start=first_match_start,
            context_lines=context_lines,
            max_chars=max_excerpt_chars,
            chunk_start_line=chunk.start_line,
        )
        _retain_ranked_hit(
            retained,
            LexicalSearchHit(
                chunk_id=chunk.id,
                language=chunk.language,
                kind=chunk.kind,
                path=chunk.path,
                symbol=chunk.symbol,
                start_line=chunk.start_line,
                end_line=chunk.end_line,
                start_instruction=chunk.start_instruction,
                end_instruction=chunk.end_instruction,
                match_count=match_count,
                distinct_match_line_count=distinct_match_line_count,
                match_lines=tuple(match_lines),
                match_lines_truncated=(distinct_match_line_count > len(match_lines)),
                excerpt=excerpt,
                excerpt_start_line=excerpt_start,
                excerpt_end_line=excerpt_end,
            ),
            max_results=max_results,
        )

    return tuple(
        ranked.hit
        for ranked in sorted(
            retained,
            key=lambda ranked: ranked.rank,
        )
    )
