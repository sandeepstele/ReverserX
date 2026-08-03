import json
from collections.abc import Sequence
from typing import cast

import pytest
from pydantic import ValidationError

from reverserx.context.benchmark import (
    AggregateHitAtK,
    BenchmarkCase,
    BenchmarkCaseResult,
    BenchmarkRegressionError,
    BenchmarkSummary,
    HitAtK,
    QueryCallback,
    RetrievedItem,
    assert_benchmark_thresholds,
    evaluate_benchmark,
    render_benchmark_json,
)
from reverserx.context.chunking import (
    ChunkKind,
    SourceChunk,
    chunk_java,
    chunk_kotlin,
    chunk_smali,
)
from reverserx.context.search import lexical_search


@pytest.fixture
def tiny_corpus() -> tuple[SourceChunk, ...]:
    java = """public class Crypto {
    byte[] encryptRequest(byte[] payload) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        return cipher.doFinal(payload);
    }
}
"""
    kotlin = """class TokenStore {
    fun bearerHeader(token: String): String {
        return "Bearer $token"
    }
}
"""
    smali = """.class public Lfixture/Signer;
.super Ljava/lang/Object;

.method public signPayload([B)[B
    .locals 1
    const-string v0, "HmacSHA256"
    return-object p1
.end method
"""
    return (
        *chunk_java(java, path="java/Crypto.java"),
        *chunk_kotlin(kotlin, path="kotlin/TokenStore.kt"),
        *chunk_smali(smali, path="smali/fixture/Signer.smali"),
    )


def _chunk_with_symbol(corpus: tuple[SourceChunk, ...], symbol: str) -> SourceChunk:
    return next(chunk for chunk in corpus if chunk.symbol == symbol)


def _lexical_callback(
    corpus: tuple[SourceChunk, ...],
) -> QueryCallback:
    def query(query_text: str, limit: int) -> Sequence[RetrievedItem]:
        return tuple(
            RetrievedItem(
                chunk_id=hit.chunk_id,
                path=hit.path,
                score=float(hit.match_count),
            )
            for hit in lexical_search(corpus, query_text, max_results=limit)
        )

    return query


def _hybrid_like_callback(
    corpus: tuple[SourceChunk, ...],
) -> QueryCallback:
    signals_by_query = {
        "where is the network request encrypted": (
            "encryptrequest",
            "cipher.getinstance",
        ),
        "how is the authorization header built": ("bearerheader", "bearer"),
        "find the native payload signature": ("signpayload", "hmacsha256"),
    }

    def query(query_text: str, limit: int) -> Sequence[RetrievedItem]:
        signals = signals_by_query[query_text]
        ranked: list[RetrievedItem] = []
        for chunk in corpus:
            searchable = f"{chunk.symbol or ''}\n{chunk.content}".casefold()
            score = float(sum(signal in searchable for signal in signals))
            if score == 0:
                continue
            if chunk.kind is ChunkKind.METHOD:
                score += 0.25
            ranked.append(
                RetrievedItem(chunk_id=chunk.id, path=chunk.path, score=score)
            )
        ranked.sort(key=lambda item: (-(item.score or 0.0), item.path, item.chunk_id))
        return tuple(ranked[:limit])

    return query


def test_lexical_corpus_metrics_and_regression_floor(
    tiny_corpus: tuple[SourceChunk, ...],
) -> None:
    java_method = _chunk_with_symbol(tiny_corpus, "Crypto.encryptRequest")
    smali_method = _chunk_with_symbol(tiny_corpus, "fixture.Signer->signPayload([B)[B")
    cases = (
        BenchmarkCase(
            case_id="java-cipher",
            query="Cipher.getInstance",
            expected_chunk_ids=(java_method.id,),
            tags=("java", "crypto"),
        ),
        BenchmarkCase(
            case_id="kotlin-bearer",
            query="Bearer ",
            expected_paths=("kotlin/TokenStore.kt",),
            tags=("kotlin", "authentication"),
        ),
        BenchmarkCase(
            case_id="smali-hmac",
            query="HmacSHA256",
            expected_chunk_ids=(smali_method.id,),
            tags=("smali", "crypto"),
        ),
    )

    summary = evaluate_benchmark(
        cases,
        _lexical_callback(tiny_corpus),
        cutoffs=(3, 1),
    )

    assert summary.case_count == 3
    assert summary.cutoffs == (1, 3)
    assert summary.hit_rate(1) == pytest.approx(2 / 3)
    assert summary.hit_rate(3) == 1.0
    assert summary.mean_reciprocal_rank == pytest.approx(5 / 6)
    assert summary.results[0].first_relevant_rank == 2
    assert summary.results[0].reciprocal_rank == 0.5
    assert summary.results[1].first_relevant_rank == 1
    assert_benchmark_thresholds(
        summary,
        minimum_hit_at_k={1: 2 / 3, 3: 1.0},
        minimum_mean_reciprocal_rank=0.8,
    )


def test_hybrid_like_callback_retrieves_expected_methods_at_one(
    tiny_corpus: tuple[SourceChunk, ...],
) -> None:
    expected = (
        (
            "natural-java",
            "where is the network request encrypted",
            "Crypto.encryptRequest",
        ),
        (
            "natural-kotlin",
            "how is the authorization header built",
            "TokenStore.bearerHeader",
        ),
        (
            "natural-smali",
            "find the native payload signature",
            "fixture.Signer->signPayload([B)[B",
        ),
    )
    cases = tuple(
        BenchmarkCase(
            case_id=case_id,
            query=query,
            expected_chunk_ids=(_chunk_with_symbol(tiny_corpus, symbol).id,),
        )
        for case_id, query, symbol in expected
    )

    summary = evaluate_benchmark(
        cases,
        _hybrid_like_callback(tiny_corpus),
        cutoffs=(1, 3),
    )

    assert summary.hit_rate(1) == 1.0
    assert summary.mean_reciprocal_rank == 1.0
    assert all(result.first_relevant_rank == 1 for result in summary.results)
    assert_benchmark_thresholds(
        summary,
        minimum_hit_at_k={1: 1.0},
        minimum_mean_reciprocal_rank=1.0,
    )


def test_evaluation_uses_path_or_chunk_id_and_deduplicates_results() -> None:
    cases = (
        BenchmarkCase(
            case_id="path-match",
            query="query",
            expected_chunk_ids=("expected-id",),
            expected_paths=("src/Expected.java",),
        ),
    )
    duplicate = RetrievedItem(chunk_id="noise", path="src/Noise.java", score=1.0)
    path_match = RetrievedItem(
        chunk_id="different-id", path="src/Expected.java", score=0.5
    )
    observed_limits: list[int] = []

    def query(_query_text: str, limit: int) -> Sequence[RetrievedItem]:
        observed_limits.append(limit)
        return duplicate, duplicate, path_match

    summary = evaluate_benchmark(cases, query, cutoffs=(1, 2))

    assert observed_limits == [2]
    assert len(summary.results[0].returned_items) == 2
    assert summary.results[0].first_relevant_rank == 2
    assert summary.hit_rate(1) == 0.0
    assert summary.hit_rate(2) == 1.0


def test_machine_readable_output_is_stable_and_complete() -> None:
    case = BenchmarkCase(
        case_id="json-case",
        query="find source",
        expected_chunk_ids=("chunk-1",),
    )
    item = RetrievedItem(chunk_id="chunk-1", path="src/Foo.java", score=0.8)
    summary = evaluate_benchmark((case,), lambda _query, _limit: (item,), cutoffs=(1,))

    first = render_benchmark_json(summary)
    second = render_benchmark_json(summary)
    payload = json.loads(first)

    assert first == second
    assert first.endswith("\n")
    assert payload["schema_version"] == "1.0"
    assert payload["case_count"] == 1
    assert payload["hit_at_k"][0] == {"hits": 1, "k": 1, "rate": 1.0, "total": 1}
    assert payload["results"][0]["returned_items"][0]["path"] == "src/Foo.java"
    with pytest.raises(ValueError, match="indent"):
        render_benchmark_json(summary, indent=9)


def test_case_and_retrieved_item_input_validation() -> None:
    with pytest.raises(ValidationError, match="case_id"):
        BenchmarkCase(case_id="Bad Case", query="valid", expected_chunk_ids=("x",))
    with pytest.raises(ValidationError, match="query"):
        BenchmarkCase(case_id="blank", query="  ", expected_chunk_ids=("x",))
    with pytest.raises(ValidationError, match="at least one expected"):
        BenchmarkCase(case_id="missing", query="valid")
    with pytest.raises(ValidationError, match="unique"):
        BenchmarkCase(
            case_id="duplicate",
            query="valid",
            expected_chunk_ids=("same", "same"),
        )
    with pytest.raises(ValidationError, match="relative source path"):
        BenchmarkCase(
            case_id="traversal",
            query="valid",
            expected_paths=("../secret.java",),
        )
    with pytest.raises(ValidationError):
        BenchmarkCase.model_validate(
            {
                "case_id": "strict",
                "query": "valid",
                "expected_chunk_ids": ["x"],
            }
        )
    with pytest.raises(ValidationError, match="finite"):
        RetrievedItem(chunk_id="x", path="src/X.java", score=float("nan"))


@pytest.mark.parametrize("cutoffs", [(), (0,), (True,), (1, 1), (10_001,)])
def test_evaluation_validates_cutoffs(cutoffs: tuple[int, ...]) -> None:
    case = BenchmarkCase(
        case_id="cutoff",
        query="valid",
        expected_chunk_ids=("x",),
    )

    with pytest.raises(ValueError, match="cutoff"):
        evaluate_benchmark((case,), lambda _query, _limit: (), cutoffs=cutoffs)


def test_evaluation_validates_cases_and_callback_contract() -> None:
    case = BenchmarkCase(
        case_id="contract",
        query="valid",
        expected_chunk_ids=("x",),
    )
    with pytest.raises(ValueError, match="at least one benchmark case"):
        evaluate_benchmark((), lambda _query, _limit: ())
    with pytest.raises(ValueError, match="case identifiers"):
        evaluate_benchmark((case, case), lambda _query, _limit: ())

    def invalid_sequence(_query: str, _limit: int) -> Sequence[RetrievedItem]:
        return cast(Sequence[RetrievedItem], "not-items")

    with pytest.raises(TypeError, match="sequence of RetrievedItem"):
        evaluate_benchmark((case,), invalid_sequence)

    def invalid_item(_query: str, _limit: int) -> Sequence[RetrievedItem]:
        return cast(Sequence[RetrievedItem], ("not-an-item",))

    with pytest.raises(TypeError, match="RetrievedItem instances"):
        evaluate_benchmark((case,), invalid_item)


def test_threshold_failure_and_validation() -> None:
    case = BenchmarkCase(
        case_id="miss",
        query="valid",
        expected_chunk_ids=("expected",),
    )
    noise = RetrievedItem(chunk_id="noise", path="src/Noise.java")
    summary = evaluate_benchmark((case,), lambda _query, _limit: (noise,), cutoffs=(1,))

    with pytest.raises(BenchmarkRegressionError, match=r"hit@1.*mean reciprocal"):
        assert_benchmark_thresholds(
            summary,
            minimum_hit_at_k={1: 1.0},
            minimum_mean_reciprocal_rank=0.5,
        )
    with pytest.raises(ValueError, match="between 0 and 1"):
        assert_benchmark_thresholds(summary, minimum_mean_reciprocal_rank=1.1)
    with pytest.raises(ValueError, match=r"does not contain hit@2"):
        assert_benchmark_thresholds(summary, minimum_hit_at_k={2: 0.5})


def test_result_and_summary_models_reject_inconsistent_metrics() -> None:
    item = RetrievedItem(chunk_id="expected", path="src/Expected.java")
    with pytest.raises(ValidationError, match="first_relevant_rank"):
        BenchmarkCaseResult(
            case_id="invalid",
            query="query",
            expected_chunk_ids=("expected",),
            expected_paths=(),
            returned_items=(item,),
            first_relevant_rank=None,
            reciprocal_rank=0.0,
            hit_at_k=(HitAtK(k=1, hit=False),),
        )

    valid_result = BenchmarkCaseResult(
        case_id="valid",
        query="query",
        expected_chunk_ids=("expected",),
        expected_paths=(),
        returned_items=(item,),
        first_relevant_rank=1,
        reciprocal_rank=1.0,
        hit_at_k=(HitAtK(k=1, hit=True),),
    )
    with pytest.raises(ValidationError, match="aggregate hit metrics"):
        BenchmarkSummary(
            case_count=1,
            cutoffs=(1,),
            mean_reciprocal_rank=1.0,
            hit_at_k=(AggregateHitAtK(k=1, hits=0, total=1, rate=0.0),),
            results=(valid_result,),
        )
