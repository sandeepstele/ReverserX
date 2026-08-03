"""Deterministic retrieval evaluation for source-context regression tests."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import PurePosixPath
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

BENCHMARK_SCHEMA_VERSION = "1.0"
MAX_BENCHMARK_K = 10_000


class BenchmarkCase(BaseModel):
    """A retrieval question with one or more acceptable source targets.

    A returned item is relevant when either its stable chunk identity or its
    normalized relative source path matches one of the expected values.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["1.0"] = "1.0"
    case_id: str
    query: str
    expected_chunk_ids: tuple[str, ...] = ()
    expected_paths: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()

    @field_validator("case_id")
    @classmethod
    def validate_case_id(cls, value: str) -> str:
        if re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", value) is None:
            raise ValueError(
                "case_id must contain lowercase ASCII segments separated by ., _, or -"
            )
        return value

    @field_validator("query")
    @classmethod
    def normalize_query(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("query cannot be blank")
        return normalized

    @field_validator("expected_chunk_ids")
    @classmethod
    def validate_expected_chunk_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(value.strip() for value in values)
        if any(not value for value in normalized):
            raise ValueError("expected chunk identifiers cannot be blank")
        if len(set(normalized)) != len(normalized):
            raise ValueError("expected chunk identifiers must be unique")
        return normalized

    @field_validator("expected_paths")
    @classmethod
    def normalize_expected_paths(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_normalize_relative_path(value) for value in values)
        if len(set(normalized)) != len(normalized):
            raise ValueError("expected paths must be unique")
        return normalized

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(value.strip() for value in values)
        if any(not value for value in normalized):
            raise ValueError("tags cannot be blank")
        if len(set(normalized)) != len(normalized):
            raise ValueError("tags must be unique")
        return normalized

    @model_validator(mode="after")
    def require_expected_target(self) -> Self:
        if not self.expected_chunk_ids and not self.expected_paths:
            raise ValueError(
                "at least one expected chunk identifier or path is required"
            )
        return self


class RetrievedItem(BaseModel):
    """One ranked item returned by a benchmark query callback."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    chunk_id: str
    path: str
    score: float | None = None

    @field_validator("chunk_id")
    @classmethod
    def validate_chunk_id(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("chunk_id cannot be blank")
        return normalized

    @field_validator("path")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        return _normalize_relative_path(value)

    @field_validator("score")
    @classmethod
    def validate_score(cls, value: float | None) -> float | None:
        if value is not None and not math.isfinite(value):
            raise ValueError("score must be finite")
        return value


class HitAtK(BaseModel):
    """Binary hit outcome for one case at a specific cutoff."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    k: int = Field(ge=1)
    hit: bool


class BenchmarkCaseResult(BaseModel):
    """Metrics and ranked evidence for one benchmark case."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["1.0"] = "1.0"
    case_id: str
    query: str
    expected_chunk_ids: tuple[str, ...]
    expected_paths: tuple[str, ...]
    returned_items: tuple[RetrievedItem, ...]
    first_relevant_rank: int | None = Field(default=None, ge=1)
    reciprocal_rank: float = Field(ge=0, le=1)
    hit_at_k: tuple[HitAtK, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_metrics(self) -> Self:
        actual_rank = next(
            (
                rank
                for rank, item in enumerate(self.returned_items, start=1)
                if item.chunk_id in self.expected_chunk_ids
                or item.path in self.expected_paths
            ),
            None,
        )
        if self.first_relevant_rank != actual_rank:
            raise ValueError("first_relevant_rank does not match returned items")
        expected_rr = 0.0 if actual_rank is None else 1.0 / actual_rank
        if not math.isclose(self.reciprocal_rank, expected_rr, abs_tol=1e-12):
            raise ValueError("reciprocal_rank does not match first_relevant_rank")
        metric_cutoffs = tuple(metric.k for metric in self.hit_at_k)
        if tuple(sorted(set(metric_cutoffs))) != metric_cutoffs:
            raise ValueError("hit_at_k cutoffs must be sorted and unique")
        for metric in self.hit_at_k:
            expected_hit = (
                self.first_relevant_rank is not None
                and self.first_relevant_rank <= metric.k
            )
            if metric.hit is not expected_hit:
                raise ValueError("hit_at_k does not match first_relevant_rank")
        return self


class AggregateHitAtK(BaseModel):
    """Aggregate hit count and rate for a cutoff."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    k: int = Field(ge=1)
    hits: int = Field(ge=0)
    total: int = Field(ge=1)
    rate: float = Field(ge=0, le=1)

    @model_validator(mode="after")
    def validate_rate(self) -> Self:
        if self.hits > self.total:
            raise ValueError("hits cannot exceed total")
        if not math.isclose(self.rate, self.hits / self.total, abs_tol=1e-12):
            raise ValueError("rate does not match hits divided by total")
        return self


class BenchmarkSummary(BaseModel):
    """Complete machine-readable results for one benchmark run."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["1.0"] = "1.0"
    case_count: int = Field(ge=1)
    cutoffs: tuple[int, ...] = Field(min_length=1)
    mean_reciprocal_rank: float = Field(ge=0, le=1)
    hit_at_k: tuple[AggregateHitAtK, ...] = Field(min_length=1)
    results: tuple[BenchmarkCaseResult, ...]

    @model_validator(mode="after")
    def validate_summary(self) -> Self:
        if self.case_count != len(self.results):
            raise ValueError("case_count does not match results")
        if tuple(sorted(set(self.cutoffs))) != self.cutoffs or any(
            cutoff < 1 for cutoff in self.cutoffs
        ):
            raise ValueError("cutoffs must be positive, sorted, and unique")
        if self.cutoffs != tuple(metric.k for metric in self.hit_at_k):
            raise ValueError("cutoffs do not match aggregate hit metrics")
        for metric in self.hit_at_k:
            expected_hits = sum(
                1
                for result in self.results
                if result.first_relevant_rank is not None
                and result.first_relevant_rank <= metric.k
            )
            if metric.hits != expected_hits or metric.total != self.case_count:
                raise ValueError("aggregate hit metrics do not match case results")
        expected_mrr = sum(result.reciprocal_rank for result in self.results) / len(
            self.results
        )
        if not math.isclose(self.mean_reciprocal_rank, expected_mrr, abs_tol=1e-12):
            raise ValueError("mean_reciprocal_rank does not match case results")
        return self

    def hit_rate(self, k: int) -> float:
        """Return the measured hit rate for a configured cutoff."""

        for metric in self.hit_at_k:
            if metric.k == k:
                return metric.rate
        raise ValueError(f"benchmark does not contain hit@{k}")


class BenchmarkRegressionError(AssertionError):
    """Raised when evaluated retrieval quality falls below a required threshold."""


QueryCallback = Callable[[str, int], Sequence[RetrievedItem]]


def _normalize_relative_path(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    parsed = PurePosixPath(normalized)
    if (
        not normalized
        or parsed.is_absolute()
        or parsed.as_posix() == "."
        or ".." in parsed.parts
    ):
        raise ValueError("path must be a non-empty relative source path")
    return parsed.as_posix()


def _validate_cutoffs(cutoffs: Iterable[int]) -> tuple[int, ...]:
    values = tuple(cutoffs)
    if not values:
        raise ValueError("at least one hit@k cutoff is required")
    if any(
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > MAX_BENCHMARK_K
        for value in values
    ):
        raise ValueError(f"cutoffs must be integers between 1 and {MAX_BENCHMARK_K}")
    if len(set(values)) != len(values):
        raise ValueError("cutoffs must be unique")
    return tuple(sorted(values))


def _deduplicate_results(
    raw_items: Sequence[object], limit: int
) -> tuple[RetrievedItem, ...]:
    selected: list[RetrievedItem] = []
    seen_ids: set[str] = set()
    for item in raw_items:
        if not isinstance(item, RetrievedItem):
            raise TypeError("query callback must return RetrievedItem instances")
        if item.chunk_id in seen_ids:
            continue
        seen_ids.add(item.chunk_id)
        selected.append(item)
        if len(selected) == limit:
            break
    return tuple(selected)


def _is_relevant(case: BenchmarkCase, item: RetrievedItem) -> bool:
    return item.chunk_id in case.expected_chunk_ids or item.path in case.expected_paths


def evaluate_benchmark(
    cases: Iterable[BenchmarkCase],
    query_callback: QueryCallback,
    *,
    cutoffs: Iterable[int] = (1, 3, 5, 10),
) -> BenchmarkSummary:
    """Evaluate ranked callback results using hit@k and reciprocal rank.

    The callback receives ``(query, max_cutoff)`` and must return best-first
    ``RetrievedItem`` objects.  Scores are retained for diagnostics but do not
    reorder callback output.  Duplicate chunk identities keep their first rank.
    """

    normalized_cases = tuple(cases)
    if not normalized_cases:
        raise ValueError("at least one benchmark case is required")
    if any(not isinstance(case, BenchmarkCase) for case in normalized_cases):
        raise TypeError("cases must contain BenchmarkCase instances")
    case_ids = tuple(case.case_id for case in normalized_cases)
    if len(set(case_ids)) != len(case_ids):
        raise ValueError("benchmark case identifiers must be unique")

    normalized_cutoffs = _validate_cutoffs(cutoffs)
    maximum_cutoff = normalized_cutoffs[-1]
    results: list[BenchmarkCaseResult] = []

    for case in normalized_cases:
        raw_result: object = query_callback(case.query, maximum_cutoff)
        if isinstance(raw_result, (str, bytes)) or not isinstance(raw_result, Sequence):
            raise TypeError("query callback must return a sequence of RetrievedItem")
        returned = _deduplicate_results(raw_result, maximum_cutoff)
        first_relevant_rank = next(
            (
                rank
                for rank, item in enumerate(returned, start=1)
                if _is_relevant(case, item)
            ),
            None,
        )
        reciprocal_rank = (
            0.0 if first_relevant_rank is None else 1.0 / first_relevant_rank
        )
        results.append(
            BenchmarkCaseResult(
                case_id=case.case_id,
                query=case.query,
                expected_chunk_ids=case.expected_chunk_ids,
                expected_paths=case.expected_paths,
                returned_items=returned,
                first_relevant_rank=first_relevant_rank,
                reciprocal_rank=reciprocal_rank,
                hit_at_k=tuple(
                    HitAtK(
                        k=k,
                        hit=first_relevant_rank is not None
                        and first_relevant_rank <= k,
                    )
                    for k in normalized_cutoffs
                ),
            )
        )

    aggregates = tuple(
        AggregateHitAtK(
            k=k,
            hits=sum(
                1
                for result in results
                if result.first_relevant_rank is not None
                and result.first_relevant_rank <= k
            ),
            total=len(results),
            rate=sum(
                1
                for result in results
                if result.first_relevant_rank is not None
                and result.first_relevant_rank <= k
            )
            / len(results),
        )
        for k in normalized_cutoffs
    )
    return BenchmarkSummary(
        case_count=len(results),
        cutoffs=normalized_cutoffs,
        mean_reciprocal_rank=sum(result.reciprocal_rank for result in results)
        / len(results),
        hit_at_k=aggregates,
        results=tuple(results),
    )


def assert_benchmark_thresholds(
    summary: BenchmarkSummary,
    *,
    minimum_hit_at_k: Mapping[int, float] | None = None,
    minimum_mean_reciprocal_rank: float = 0.0,
) -> None:
    """Raise ``BenchmarkRegressionError`` when a quality floor is missed."""

    if not 0 <= minimum_mean_reciprocal_rank <= 1:
        raise ValueError("minimum_mean_reciprocal_rank must be between 0 and 1")
    thresholds = minimum_hit_at_k or {}
    failures: list[str] = []
    threshold_items = tuple(thresholds.items())
    for k, minimum in threshold_items:
        if isinstance(k, bool) or not isinstance(k, int) or k < 1:
            raise ValueError("hit@k threshold keys must be positive integers")
        if not isinstance(minimum, (int, float)) or isinstance(minimum, bool):
            raise ValueError("hit@k thresholds must be numeric rates")
        numeric_minimum = float(minimum)
        if not math.isfinite(numeric_minimum) or not 0 <= numeric_minimum <= 1:
            raise ValueError("hit@k thresholds must be between 0 and 1")

    for k, minimum in sorted(threshold_items):
        numeric_minimum = float(minimum)
        actual = summary.hit_rate(k)
        if actual < numeric_minimum:
            failures.append(f"hit@{k} {actual:.6f} < {numeric_minimum:.6f}")

    if summary.mean_reciprocal_rank < minimum_mean_reciprocal_rank:
        failures.append(
            "mean reciprocal rank "
            f"{summary.mean_reciprocal_rank:.6f} < "
            f"{minimum_mean_reciprocal_rank:.6f}"
        )
    if failures:
        raise BenchmarkRegressionError("retrieval regression: " + "; ".join(failures))


def render_benchmark_json(summary: BenchmarkSummary, *, indent: int = 2) -> str:
    """Render deterministic, newline-terminated JSON for CI artifacts."""

    if isinstance(indent, bool) or not isinstance(indent, int) or not 0 <= indent <= 8:
        raise ValueError("indent must be an integer between 0 and 8")
    payload = summary.model_dump(mode="json")
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=indent,
            sort_keys=True,
        )
        + "\n"
    )
