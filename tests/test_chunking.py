from pathlib import Path

import pytest
from pydantic import ValidationError

from reverserx.context.chunking import (
    DEFAULT_MAX_SOURCE_BYTES,
    ChunkKind,
    SourceChunk,
    SourceLanguage,
    chunk_by_lines,
    chunk_java,
    chunk_kotlin,
    chunk_smali,
    index_source_tree,
    index_source_tree_with_report,
    infer_source_language,
)


def make_chunk(**overrides: object) -> SourceChunk:
    values: dict[str, object] = {
        "language": SourceLanguage.JAVA,
        "kind": ChunkKind.METHOD,
        "path": "src/example/Foo.java",
        "symbol": "Foo.encrypt",
        "start_line": 10,
        "end_line": 12,
        "content": 'String encrypt() {\n  return "AES";\n}\n',
    }
    values.update(overrides)
    return SourceChunk.model_validate(values)


def test_source_chunk_identity_is_stable_and_validated() -> None:
    first = make_chunk(path="src\\example\\Foo.java")
    second = make_chunk(path="src/example/Foo.java")

    assert first.schema_version == "1.0"
    assert first.path == "src/example/Foo.java"
    assert first.id == second.id
    assert first.id.startswith("chk_")
    assert len(first.content_sha256) == 64
    assert make_chunk(content="changed").id != first.id
    assert make_chunk(start_line=11, end_line=12).id != first.id

    restored = SourceChunk.model_validate(first.model_dump())
    assert restored == first

    forged = first.model_dump()
    forged["id"] = f"chk_{'0' * 64}"
    with pytest.raises(ValidationError, match="id does not match"):
        SourceChunk.model_validate(forged)


def test_source_chunk_is_strict_and_rejects_invalid_locations() -> None:
    with pytest.raises(ValidationError):
        make_chunk(language="java")
    with pytest.raises(ValidationError, match="end_line"):
        make_chunk(start_line=12, end_line=10)
    with pytest.raises(ValidationError, match="relative source path"):
        make_chunk(path="../secret.java")
    with pytest.raises(ValidationError, match="instruction bounds"):
        make_chunk(start_instruction=1)
    with pytest.raises(ValidationError, match="only valid for Smali"):
        make_chunk(start_instruction=1, end_instruction=2)
    with pytest.raises(ValidationError, match="Extra inputs"):
        make_chunk(unexpected=True)


def test_java_chunker_finds_nested_types_methods_and_constructor() -> None:
    source = """package example;

public class Vault {
    public Vault() {
        String brace = "}"; // a fake }
    }

    public String encrypt(
        String value
    ) throws Exception {
        return value + "{";
    }

    static class Helper {
        static String name() { return "helper"; }
    }
}
"""

    chunks = chunk_java(source, path="example/Vault.java")
    locations = {
        (chunk.kind, chunk.symbol): (chunk.start_line, chunk.end_line)
        for chunk in chunks
    }

    assert locations[(ChunkKind.TYPE, "Vault")] == (3, 17)
    assert locations[(ChunkKind.METHOD, "Vault.Vault")] == (4, 6)
    assert locations[(ChunkKind.METHOD, "Vault.encrypt")] == (8, 12)
    assert locations[(ChunkKind.TYPE, "Vault.Helper")] == (14, 16)
    assert locations[(ChunkKind.METHOD, "Vault.Helper.name")] == (15, 15)
    encrypt = next(chunk for chunk in chunks if chunk.symbol == "Vault.encrypt")
    assert encrypt.content.startswith("    public String encrypt(")
    assert encrypt.content.endswith("    }\n")


def test_kotlin_chunker_handles_init_block_expression_and_top_level_functions() -> None:
    source = """package example

data class Vault(val key: String) {
    init {
        println("{")
    }

    fun encrypt(
        value: String,
    ): String {
        return value + key
    }

    fun algorithm() = "AES/GCM"

    object Helper {
        fun label(): String { return "}" }
    }
}

fun top() { println("top") }
"""

    chunks = chunk_kotlin(source, path="example/Vault.kt")
    symbols = {(chunk.kind, chunk.symbol) for chunk in chunks}

    assert (ChunkKind.TYPE, "Vault") in symbols
    assert (ChunkKind.METHOD, "Vault.init") in symbols
    assert (ChunkKind.METHOD, "Vault.encrypt") in symbols
    assert (ChunkKind.METHOD, "Vault.algorithm") in symbols
    assert (ChunkKind.TYPE, "Vault.Helper") in symbols
    assert (ChunkKind.METHOD, "Vault.Helper.label") in symbols
    assert (ChunkKind.METHOD, "top") in symbols
    algorithm = next(chunk for chunk in chunks if chunk.symbol == "Vault.algorithm")
    assert (algorithm.start_line, algorithm.end_line) == (14, 14)


def test_malformed_java_uses_bounded_file_fallback() -> None:
    malformed = "class Broken {\n" + "\n".join(f"line {index}" for index in range(8))

    chunks = chunk_java(malformed, path="Broken.java")

    assert len(chunks) == 1
    assert chunks[0].kind is ChunkKind.FILE
    assert chunks[0].symbol == "<file>"


def test_smali_chunker_records_methods_and_instruction_ordinals() -> None:
    source = """.class public Lcom/example/Foo;
.super Ljava/lang/Object;

.method public encrypt(Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    const-string v0, "AES"
    invoke-static {v0}, Lx/Y;->go(Ljava/lang/String;)V
    return-object p1
.end method

.method public abstract noCode()V
.end method
"""

    chunks = chunk_smali(source, path="smali/com/example/Foo.smali")
    methods = [chunk for chunk in chunks if chunk.kind is ChunkKind.METHOD]

    assert [chunk.symbol for chunk in methods] == [
        "com.example.Foo->encrypt(Ljava/lang/String;)Ljava/lang/String;",
        "com.example.Foo->noCode()V",
    ]
    assert (methods[0].start_line, methods[0].end_line) == (4, 9)
    assert (methods[0].start_instruction, methods[0].end_instruction) == (1, 3)
    assert methods[1].start_instruction is None
    assert methods[1].end_instruction is None


def test_line_chunker_uses_deterministic_overlap() -> None:
    source = "".join(f"line-{line}\n" for line in range(1, 8))

    chunks = chunk_by_lines(
        source,
        path="notes.txt",
        chunk_lines=3,
        overlap_lines=1,
    )

    assert [(chunk.start_line, chunk.end_line) for chunk in chunks] == [
        (1, 3),
        (3, 5),
        (5, 7),
    ]
    assert chunks[0].content.endswith("line-3\n")
    assert chunks[1].content.startswith("line-3\n")
    with pytest.raises(ValueError, match="less than chunk_lines"):
        chunk_by_lines(source, path="notes.txt", chunk_lines=3, overlap_lines=3)


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("Foo.JAVA", SourceLanguage.JAVA),
        ("Foo.kt", SourceLanguage.KOTLIN),
        ("Foo.smali", SourceLanguage.SMALI),
        ("AndroidManifest.xml", SourceLanguage.TEXT),
        ("classes.dex", None),
    ],
)
def test_infer_source_language(filename: str, expected: SourceLanguage | None) -> None:
    assert infer_source_language(filename) is expected


def test_tree_index_is_reproducible_and_skips_unsafe_files(tmp_path: Path) -> None:
    source_root = tmp_path / "sources"
    nested = source_root / "nested"
    nested.mkdir(parents=True)
    (source_root / "B.java").write_text(
        "class B { int value() { return 2; } }\n", encoding="utf-8"
    )
    (nested / "A.kt").write_text("fun answer() = 42\n", encoding="utf-8")
    (source_root / "notes.txt").write_text("authorized fixture\n", encoding="utf-8")
    (source_root / "binary.xml").write_bytes(b"text\x00binary")
    (source_root / "invalid.txt").write_bytes(b"\xff\xfe")
    (source_root / "ignored.dex").write_bytes(b"dex\n035")
    (source_root / "large.java").write_text("x" * 101, encoding="utf-8")
    (source_root / "linked.java").symlink_to(source_root / "B.java")
    linked_directory = source_root / "linked-dir"
    linked_directory.symlink_to(nested, target_is_directory=True)

    first = index_source_tree(source_root, max_file_bytes=100)
    second = index_source_tree(source_root, max_file_bytes=100)
    report = index_source_tree_with_report(source_root, max_file_bytes=100)

    assert [chunk.id for chunk in first] == [chunk.id for chunk in second]
    indexed_paths = {chunk.path for chunk in first}
    assert indexed_paths == {"B.java", "large.java", "nested/A.kt", "notes.txt"}
    assert all(not chunk.path.startswith("linked") for chunk in first)
    assert report.indexed_file_count == 4
    assert report.skipped_file_count == 3
    assert report.oversized_fallback_file_count == 1
    assert report.warning_count == 4
    assert {(warning.path, warning.reason) for warning in report.warnings} == {
        ("binary.xml", "binary"),
        ("invalid.txt", "invalid_utf8"),
        ("large.java", "oversized_fallback"),
        ("linked.java", "symlink"),
    }


def test_tree_index_reports_bounded_fallback_for_oversized_source(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    line = f"// {'x' * 180}\n"
    line_count = DEFAULT_MAX_SOURCE_BYTES // len(line.encode("utf-8")) + 2
    oversized = source_root / "Huge.java"
    oversized.write_text(line * line_count, encoding="utf-8")

    first = index_source_tree_with_report(
        source_root,
        fallback_chunk_lines=40,
        fallback_overlap_lines=5,
    )
    second = index_source_tree_with_report(
        source_root,
        fallback_chunk_lines=40,
        fallback_overlap_lines=5,
    )

    assert oversized.stat().st_size > DEFAULT_MAX_SOURCE_BYTES
    assert [chunk.id for chunk in first.chunks] == [chunk.id for chunk in second.chunks]
    assert len(first.chunks) > 1
    assert all(chunk.path == "Huge.java" for chunk in first.chunks)
    assert all(chunk.kind is ChunkKind.FILE for chunk in first.chunks)
    assert all(chunk.end_line - chunk.start_line + 1 <= 40 for chunk in first.chunks)
    assert first.indexed_file_count == 1
    assert first.skipped_file_count == 0
    assert first.oversized_fallback_file_count == 1
    assert first.warning_count == len(first.warnings) == 1
    assert first.warnings[0].path == "Huge.java"
    assert first.warnings[0].reason == "oversized_fallback"


def test_tree_index_reports_files_above_the_fallback_hard_limit(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    oversized = source_root / "TooLarge.java"
    oversized.write_text("x" * 21, encoding="utf-8")

    result = index_source_tree_with_report(
        source_root,
        max_file_bytes=10,
        max_fallback_file_bytes=20,
    )

    assert result.chunks == ()
    assert result.indexed_file_count == 0
    assert result.skipped_file_count == 1
    assert result.oversized_fallback_file_count == 0
    assert result.warning_count == len(result.warnings) == 1
    assert result.warnings[0].path == "TooLarge.java"
    assert result.warnings[0].reason == "size_limit_exceeded"


def test_tree_index_bounds_retained_warnings_but_preserves_total(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    for name in ("A.txt", "B.txt", "C.txt"):
        (source_root / name).write_bytes(b"\xff")

    result = index_source_tree_with_report(source_root, max_warnings=2)

    assert result.indexed_file_count == 0
    assert result.skipped_file_count == 3
    assert result.warning_count == 3
    assert [warning.path for warning in result.warnings] == ["A.txt", "B.txt"]


def test_tree_index_rejects_invalid_root_and_limits(tmp_path: Path) -> None:
    file_path = tmp_path / "not-a-directory"
    file_path.write_text("text", encoding="utf-8")

    with pytest.raises(ValueError, match="source directory"):
        index_source_tree(file_path)
    with pytest.raises(ValueError, match="max_file_bytes"):
        index_source_tree(tmp_path, max_file_bytes=0)
    with pytest.raises(ValueError, match="max_fallback_file_bytes"):
        index_source_tree_with_report(tmp_path, max_fallback_file_bytes=0)
