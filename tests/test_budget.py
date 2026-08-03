import pytest
from pydantic import ValidationError

from reverserx.context.budget import (
    ContextRepresentation,
    PackedContext,
    RankedChunk,
    estimate_tokens,
    pack_context,
    render_chunk_summary,
    render_source_chunk,
)
from reverserx.context.chunking import ChunkKind, SourceChunk, SourceLanguage


def source_chunk(
    name: str,
    content: str,
    *,
    start_line: int = 1,
) -> SourceChunk:
    return SourceChunk(
        language=SourceLanguage.JAVA,
        kind=ChunkKind.METHOD,
        path=f"src/{name}.java",
        symbol=f"{name}.run",
        start_line=start_line,
        end_line=start_line + max(0, len(content.splitlines()) - 1),
        content=content,
    )


def test_token_estimator_is_deterministic_and_utf8_aware() -> None:
    assert estimate_tokens("") == 0
    assert estimate_tokens("a") == 1
    assert estimate_tokens("abcd") == 1
    assert estimate_tokens("abcde") == 2
    assert estimate_tokens("🔐") == 1
    assert estimate_tokens("🔐🔐") == 2


def test_source_and_summary_renderers_keep_evidence_locations() -> None:
    chunk = source_chunk("Crypto", "return encrypt(value);\n", start_line=40)

    source = render_source_chunk(chunk)
    summary = render_chunk_summary(chunk, " Calls the request encryptor. ")

    assert chunk.id in source
    assert "path=src/Crypto.java" in source
    assert "lines=40-40" in source
    assert "symbol=Crypto.run" in source
    assert "return encrypt(value);" in source
    assert chunk.id in summary
    assert "Calls the request encryptor." in summary


def test_packer_prefers_highest_ranked_full_source() -> None:
    high = source_chunk("High", "return high();\n")
    low = source_chunk("Low", "return low();\n")
    budget = estimate_tokens(render_source_chunk(high))

    packed = pack_context(
        (
            RankedChunk(chunk=low, score=0.1),
            RankedChunk(chunk=high, score=0.9),
        ),
        token_budget=budget,
    )

    assert packed.used_tokens <= packed.token_budget
    assert packed.remaining_tokens == packed.token_budget - packed.used_tokens
    assert [item.chunk_id for item in packed.items] == [high.id]
    assert packed.items[0].rank == 1
    assert packed.items[0].representation is ContextRepresentation.SOURCE
    assert packed.omitted_chunk_ids == (low.id,)
    assert packed.text == packed.items[0].text


def test_packer_uses_summary_when_full_source_does_not_fit() -> None:
    chunk = source_chunk("Huge", "x" * 2000)
    candidate = RankedChunk(
        chunk=chunk,
        score=1.0,
        summary="Performs authenticated encryption.",
    )
    summary_tokens = estimate_tokens(
        render_chunk_summary(chunk, "Performs authenticated encryption.")
    )

    packed = pack_context((candidate,), token_budget=summary_tokens)

    assert len(packed.items) == 1
    assert packed.items[0].representation is ContextRepresentation.SUMMARY
    assert packed.used_tokens == summary_tokens
    assert "authenticated encryption" in packed.text
    assert "x" * 100 not in packed.text


def test_summary_fallback_can_be_disabled() -> None:
    chunk = source_chunk("Huge", "x" * 2000)
    candidate = RankedChunk(chunk=chunk, score=1.0, summary="Short summary")

    packed = pack_context(
        (candidate,),
        token_budget=estimate_tokens(render_chunk_summary(chunk, "Short summary")),
        allow_summary_fallback=False,
    )

    assert packed.items == ()
    assert packed.text == ""
    assert packed.used_tokens == 0
    assert packed.omitted_chunk_ids == (chunk.id,)


def test_packer_can_skip_oversized_candidate_and_keep_next_rank() -> None:
    oversized = source_chunk("Oversized", "z" * 2000)
    compact = source_chunk("Compact", "ok();\n")
    budget = estimate_tokens(render_source_chunk(compact))

    packed = pack_context(
        (
            RankedChunk(chunk=compact, score=0.5),
            RankedChunk(chunk=oversized, score=1.0),
        ),
        token_budget=budget,
    )

    assert [item.chunk_id for item in packed.items] == [compact.id]
    assert packed.items[0].rank == 2
    assert packed.omitted_chunk_ids == (oversized.id,)


def test_packer_accounts_for_separators_and_per_item_overhead() -> None:
    first = source_chunk("First", "first();\n")
    second = source_chunk("Second", "second();\n")
    first_text = render_source_chunk(first)
    second_text = render_source_chunk(second)
    overhead = 3
    exact_budget = estimate_tokens(f"{first_text}\n\n{second_text}") + overhead * 2

    packed = pack_context(
        (
            RankedChunk(chunk=second, score=0.5),
            RankedChunk(chunk=first, score=1.0),
        ),
        token_budget=exact_budget,
        per_item_overhead_tokens=overhead,
    )

    assert len(packed.items) == 2
    assert packed.used_tokens == exact_budget
    assert sum(item.estimated_tokens for item in packed.items) == exact_budget
    assert packed.remaining_tokens == 0
    assert packed.text == f"{first_text}\n\n{second_text}"


def test_duplicate_candidates_use_highest_score_once() -> None:
    chunk = source_chunk("Duplicate", "x" * 1000)
    summary = "Higher ranked summary"
    budget = estimate_tokens(render_chunk_summary(chunk, summary))

    packed = pack_context(
        (
            RankedChunk(chunk=chunk, score=0.1, summary="Lower ranked summary"),
            RankedChunk(chunk=chunk, score=0.9, summary=summary),
        ),
        token_budget=budget,
    )

    assert len(packed.items) == 1
    assert packed.items[0].score == 0.9
    assert summary in packed.items[0].text


def test_packer_validates_budget_candidates_and_manifest_accounting() -> None:
    chunk = source_chunk("Invalid", "value();\n")
    with pytest.raises(ValueError, match="token_budget"):
        pack_context((), token_budget=-1)
    with pytest.raises(ValueError, match="overhead"):
        pack_context((), token_budget=1, per_item_overhead_tokens=-1)
    with pytest.raises(ValidationError, match="finite"):
        RankedChunk(chunk=chunk, score=float("inf"))
    with pytest.raises(ValidationError, match="blank"):
        RankedChunk(chunk=chunk, score=1.0, summary="  ")
    with pytest.raises(ValidationError, match="remaining_tokens"):
        PackedContext(
            token_budget=10,
            used_tokens=0,
            remaining_tokens=9,
            per_item_overhead_tokens=0,
            items=(),
            omitted_chunk_ids=(),
            text="",
        )
