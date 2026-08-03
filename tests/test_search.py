from collections.abc import Callable, Iterator

import pytest

import reverserx.context.search as search_module
from reverserx.context.chunking import (
    ChunkKind,
    SourceChunk,
    SourceLanguage,
    chunk_java,
    chunk_kotlin,
    chunk_smali,
)
from reverserx.context.search import (
    RegexSearchTimeoutError,
    SearchMode,
    lexical_search,
)


def source_chunk(
    content: str,
    *,
    path: str = "src/Crypto.java",
    symbol: str = "Crypto.encrypt",
    start_line: int = 20,
) -> SourceChunk:
    return SourceChunk(
        language=SourceLanguage.JAVA,
        kind=ChunkKind.METHOD,
        path=path,
        symbol=symbol,
        start_line=start_line,
        end_line=start_line + max(0, len(content.splitlines()) - 1),
        content=content,
    )


def test_exact_search_counts_matches_preserves_locations_and_ranks() -> None:
    common = source_chunk(
        'String first = Cipher.getInstance("AES");\n'
        "return Cipher.doFinal(input);\n"
        "// cipher is intentionally mentioned again\n"
    )
    frequent = source_chunk(
        "Cipher Cipher Cipher Cipher\n",
        path="src/Many.java",
        symbol="Many.test",
        start_line=5,
    )

    hits = lexical_search((common, frequent), "cipher", context_lines=0)

    assert [hit.path for hit in hits] == ["src/Many.java", "src/Crypto.java"]
    assert [hit.match_count for hit in hits] == [4, 3]
    assert hits[0].match_lines == (5,)
    assert hits[0].distinct_match_line_count == 1
    assert hits[0].match_lines_truncated is False
    assert hits[1].match_lines == (20, 21, 22)
    assert hits[1].distinct_match_line_count == 3
    assert hits[1].match_lines_truncated is False
    assert hits[1].chunk_id == common.id
    assert hits[1].symbol == "Crypto.encrypt"
    assert hits[1].start_line == common.start_line
    assert hits[1].excerpt_start_line == 20
    assert "Cipher.getInstance" in hits[1].excerpt


def test_exact_search_can_be_case_sensitive() -> None:
    chunk = source_chunk("Cipher cipher CIPHER\n")

    insensitive = lexical_search((chunk,), "Cipher")
    sensitive = lexical_search((chunk,), "Cipher", case_sensitive=True)

    assert insensitive[0].match_count == 3
    assert sensitive[0].match_count == 1


def test_regex_search_reports_each_matching_line() -> None:
    chunk = source_chunk(
        'Cipher.getInstance("AES/GCM");\n'
        "value = Cipher.doFinal(payload);\n"
        "unrelated();\n",
        start_line=100,
    )

    hits = lexical_search(
        (chunk,),
        r"Cipher\.(?:getInstance|doFinal)\(",
        mode=SearchMode.REGEX,
    )

    assert len(hits) == 1
    assert hits[0].match_count == 2
    assert hits[0].match_lines == (100, 101)


@pytest.mark.parametrize("query", ["[unterminated", "("])
def test_regex_search_rejects_invalid_patterns(query: str) -> None:
    with pytest.raises(ValueError, match="invalid regular expression"):
        lexical_search((), query, mode=SearchMode.REGEX)


@pytest.mark.parametrize(
    ("query", "mode"),
    [("", SearchMode.EXACT), ("", SearchMode.REGEX), (".*", SearchMode.REGEX)],
)
def test_search_rejects_empty_or_empty_matching_queries(
    query: str, mode: SearchMode
) -> None:
    with pytest.raises(ValueError, match="empty|must not match empty"):
        lexical_search((), query, mode=mode)


def test_excerpt_is_bounded_around_first_match() -> None:
    chunk = source_chunk(f"{'a' * 300}needle{'z' * 300}\n")

    hit = lexical_search(
        (chunk,),
        "needle",
        context_lines=0,
        max_excerpt_chars=64,
    )[0]

    assert len(hit.excerpt) <= 64
    assert "needle" in hit.excerpt
    assert hit.excerpt.startswith("…")
    assert hit.excerpt.endswith("…")


def test_result_limit_and_duplicate_chunks_are_deterministic() -> None:
    alpha = source_chunk("needle\n", path="a.java")
    beta = source_chunk("needle needle\n", path="b.java")
    gamma = source_chunk("needle needle needle\n", path="c.java")

    hits = lexical_search(
        (alpha, gamma, beta, gamma),
        "needle",
        max_results=2,
    )

    assert [(hit.path, hit.match_count) for hit in hits] == [
        ("c.java", 3),
        ("b.java", 2),
    ]


def test_structured_chunkers_keep_unparsed_lines_searchable_and_stable() -> None:
    cases: tuple[
        tuple[
            Callable[..., tuple[SourceChunk, ...]],
            str,
            str,
            str,
        ],
        ...,
    ] = (
        (
            chunk_java,
            """package fixture;
import okhttp3.CertificatePinner;
class Client { void run() { execute(); } }
""",
            "fixture/Client.java",
            "CertificatePinner",
        ),
        (
            chunk_kotlin,
            """package fixture
val API_SECRET = "needle-only-top-level"
fun top() { println("ok") }
""",
            "fixture/Top.kt",
            "needle-only-top-level",
        ),
        (
            chunk_smali,
            """.class public Lfixture/Secrets;
.super Ljava/lang/Object;
.field private static final ALGORITHM:Ljava/lang/String; = "field-only-needle"

.method public run()V
    .locals 0
    return-void
.end method
""",
            "smali/fixture/Secrets.smali",
            "field-only-needle",
        ),
    )

    for chunker, source, path, query in cases:
        first = chunker(source, path=path)
        second = chunker(source, path=path)
        covered_lines = {
            line_number
            for chunk in first
            for line_number in range(chunk.start_line, chunk.end_line + 1)
        }

        assert [chunk.id for chunk in first] == [chunk.id for chunk in second]
        assert covered_lines == set(range(1, len(source.splitlines()) + 1))
        assert all(
            chunk.content != source for chunk in first if chunk.kind is ChunkKind.FILE
        )
        hits = lexical_search(first, query, case_sensitive=True)
        assert len(hits) == 1
        assert hits[0].kind is ChunkKind.FILE
        assert query in hits[0].excerpt


def test_large_search_retains_only_bounded_deterministic_top_hits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corpus_size = 2_500
    limit = 7
    maximum_retained = 0
    candidates_seen = 0
    original_retain = search_module._retain_ranked_hit

    def track_retained(
        retained: list[search_module._RankedHit],
        hit: search_module.LexicalSearchHit,
        *,
        max_results: int,
    ) -> None:
        nonlocal candidates_seen, maximum_retained
        original_retain(retained, hit, max_results=max_results)
        candidates_seen += 1
        maximum_retained = max(maximum_retained, len(retained))
        assert len(retained) <= max_results

    monkeypatch.setattr(search_module, "_retain_ranked_hit", track_retained)

    def corpus() -> Iterator[SourceChunk]:
        for index in range(corpus_size):
            match_count = index % 13 + 1
            yield source_chunk(
                f"{'needle ' * match_count}\n",
                path=f"src/{corpus_size - index:05}.java",
            )

    hits = lexical_search(corpus(), "needle", max_results=limit)
    expected_paths = sorted(
        f"src/{corpus_size - index:05}.java"
        for index in range(corpus_size)
        if index % 13 + 1 == 13
    )[:limit]

    assert candidates_seen == corpus_size
    assert maximum_retained == limit
    assert [hit.path for hit in hits] == expected_paths
    assert [hit.match_count for hit in hits] == [13] * limit
    assert all(hit.match_lines == (20,) for hit in hits)


def test_search_caps_match_line_locators_but_preserves_complete_counts() -> None:
    chunk = source_chunk("".join(f"needle line {line}\n" for line in range(50)))

    hit = lexical_search((chunk,), "needle", max_match_lines=5)[0]

    assert hit.match_count == 50
    assert hit.distinct_match_line_count == 50
    assert hit.match_lines == (20, 21, 22, 23, 24)
    assert hit.match_lines_truncated is True


def test_regex_search_times_out_on_catastrophic_backtracking() -> None:
    chunk = source_chunk("a" * 200_000 + "!")

    with pytest.raises(RegexSearchTimeoutError, match=r"timeout.*src/Crypto.java"):
        lexical_search(
            (chunk,),
            r"(a+)+$",
            mode=SearchMode.REGEX,
            regex_timeout_seconds=0.001,
        )


def test_search_validates_bounds() -> None:
    with pytest.raises(ValueError, match="max_results"):
        lexical_search((), "x", max_results=0)
    with pytest.raises(ValueError, match="context_lines"):
        lexical_search((), "x", context_lines=-1)
    with pytest.raises(ValueError, match="max_excerpt_chars"):
        lexical_search((), "x", max_excerpt_chars=15)
    with pytest.raises(ValueError, match="max_match_lines"):
        lexical_search((), "x", max_match_lines=0)
    with pytest.raises(ValueError, match="regex_timeout_seconds"):
        lexical_search((), "x", regex_timeout_seconds=0)
    with pytest.raises(ValueError, match="regex_timeout_seconds"):
        lexical_search((), "x", regex_timeout_seconds=float("inf"))
