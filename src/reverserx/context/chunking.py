"""Deterministic, model-independent source chunking primitives.

The parsers in this module are intentionally heuristic.  They preserve source
locations and fall back to bounded file windows when a source file cannot be
understood, which is safer for retrieval than silently dropping content.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from bisect import bisect_right
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SOURCE_CHUNK_SCHEMA_VERSION: Literal["1.0"] = "1.0"
SOURCE_CHUNKER_VERSION = "1.1.0"
DEFAULT_MAX_SOURCE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_FALLBACK_SOURCE_BYTES = 64 * 1024 * 1024
DEFAULT_FALLBACK_LINES = 200
DEFAULT_FALLBACK_OVERLAP = 20
DEFAULT_MAX_SOURCE_WARNINGS = 20


class SourceLanguage(StrEnum):
    """Languages understood by the built-in deterministic chunkers."""

    JAVA = "java"
    KOTLIN = "kotlin"
    SMALI = "smali"
    TEXT = "text"


class ChunkKind(StrEnum):
    """The source construct represented by a chunk."""

    TYPE = "type"
    METHOD = "method"
    FILE = "file"


class SourceIndexWarningReason(StrEnum):
    """Reasons a supported source needed fallback handling or was skipped."""

    OVERSIZED_FALLBACK = "oversized_fallback"
    SIZE_LIMIT_EXCEEDED = "size_limit_exceeded"
    UNREADABLE = "unreadable"
    BINARY = "binary"
    INVALID_UTF8 = "invalid_utf8"
    EMPTY = "empty"
    SYMLINK = "symlink"


class SourceChunk(BaseModel):
    """A versioned, immutable source fragment with a reproducible identity.

    ``id`` and ``content_sha256`` are derived from the normalized location and
    exact content.  Supplying either value is allowed for deserialization, but
    a stale or forged value is rejected.

    Lines and Smali instruction ordinals are one-based and inclusive.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["1.0"] = SOURCE_CHUNK_SCHEMA_VERSION
    id: str = ""
    content_sha256: str = ""
    language: SourceLanguage
    kind: ChunkKind
    path: str
    symbol: str | None = None
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    start_instruction: int | None = Field(default=None, ge=1)
    end_instruction: int | None = Field(default=None, ge=1)
    content: str = Field(min_length=1)

    @field_validator("path")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        normalized = value.replace("\\", "/")
        parsed = PurePosixPath(normalized)
        if (
            not normalized
            or parsed.is_absolute()
            or parsed.as_posix() == "."
            or ".." in parsed.parts
        ):
            raise ValueError("path must be a non-empty relative source path")
        return parsed.as_posix()

    @field_validator("symbol")
    @classmethod
    def normalize_symbol(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("symbol cannot be blank")
        return normalized

    @field_validator("content")
    @classmethod
    def reject_binary_content(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("source content cannot contain NUL bytes")
        return value

    @model_validator(mode="after")
    def validate_location_and_identity(self) -> Self:
        if self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")

        has_start = self.start_instruction is not None
        has_end = self.end_instruction is not None
        if has_start != has_end:
            raise ValueError("Smali instruction bounds must be supplied together")
        if (
            self.start_instruction is not None
            and self.end_instruction is not None
            and self.end_instruction < self.start_instruction
        ):
            raise ValueError(
                "end_instruction must be greater than or equal to start_instruction"
            )
        if self.language is not SourceLanguage.SMALI and has_start:
            raise ValueError("instruction bounds are only valid for Smali chunks")

        content_digest = hashlib.sha256(self.content.encode("utf-8")).hexdigest()
        identity = {
            "schema_version": self.schema_version,
            "language": self.language.value,
            "kind": self.kind.value,
            "path": self.path,
            "symbol": self.symbol,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "start_instruction": self.start_instruction,
            "end_instruction": self.end_instruction,
            "content_sha256": content_digest,
        }
        encoded = json.dumps(
            identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        expected_id = f"chk_{hashlib.sha256(encoded).hexdigest()}"

        if self.content_sha256 and self.content_sha256 != content_digest:
            raise ValueError("content_sha256 does not match content")
        if self.id and self.id != expected_id:
            raise ValueError("id does not match chunk content and location")

        object.__setattr__(self, "content_sha256", content_digest)
        object.__setattr__(self, "id", expected_id)
        return self


class SourceIndexWarning(BaseModel):
    """A bounded, user-visible source indexing warning."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1)
    reason: SourceIndexWarningReason
    detail: str = Field(min_length=1, max_length=1_000)


class SourceTreeIndexResult(BaseModel):
    """Chunks and accounting for one deterministic source-tree traversal."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    chunks: tuple[SourceChunk, ...]
    indexed_file_count: int = Field(ge=0)
    skipped_file_count: int = Field(ge=0)
    oversized_fallback_file_count: int = Field(ge=0)
    warning_count: int = Field(ge=0)
    warnings: tuple[SourceIndexWarning, ...] = ()

    @model_validator(mode="after")
    def validate_accounting(self) -> Self:
        if self.oversized_fallback_file_count > self.indexed_file_count:
            raise ValueError("oversized fallback count cannot exceed indexed files")
        expected_warning_count = (
            self.skipped_file_count + self.oversized_fallback_file_count
        )
        if self.warning_count != expected_warning_count:
            raise ValueError(
                "warning count must equal skipped and oversized fallback files"
            )
        if len(self.warnings) > self.warning_count:
            raise ValueError("retained warnings cannot exceed total warning count")
        return self


@dataclass(frozen=True)
class _LineIndex:
    starts: tuple[int, ...]

    @classmethod
    def from_text(cls, text: str) -> _LineIndex:
        starts = [0]
        starts.extend(index + 1 for index, char in enumerate(text) if char == "\n")
        return cls(tuple(starts))

    def number_at(self, offset: int) -> int:
        return bisect_right(self.starts, offset)


@dataclass(frozen=True)
class _Declaration:
    name: str
    start_offset: int
    open_brace: int
    close_brace: int


_TYPE_DECLARATION_RE = re.compile(
    r"""
    ^[ \t]*
    (?:(?:public|protected|private|internal|abstract|final|sealed|open|data|
          value|annotation|enum|static|strictfp|fun)\s+)*
    (?P<keyword>class|interface|enum|record|object)\s+
    (?P<name>[A-Za-z_$][\w$]*)
    [^{;]*?
    (?P<brace>\{)
    """,
    re.MULTILINE | re.VERBOSE,
)

_JAVA_METHOD_RE = re.compile(
    r"""
    ^[ \t]*
    (?P<header>
      (?:(?:@[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*
          (?:\([^()\n]*\))?)[ \t]*(?:\n[ \t]*)?)*
      (?:(?:public|protected|private|static|final|abstract|synchronized|native|
            strictfp|default|transient)\s+)*
      (?:<[^>{};]+>\s*)?
      (?P<return_type>
        (?:[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*
           (?:\s*<[^>{};]+>)?(?:\s*\[\s*\])?\s+)?
      )
      (?P<name>[A-Za-z_$][\w$]*)\s*
      \([^{};]*\)\s*
      (?:throws\s+[^{;]+)?
    )
    (?P<brace>\{)
    """,
    re.MULTILINE | re.VERBOSE,
)

_KOTLIN_FUNCTION_RE = re.compile(
    r"""
    ^[ \t]*
    (?P<header>
      (?:(?:@[A-Za-z_$][\w$.]*(?:\([^()\n]*\))?)[ \t]*(?:\n[ \t]*)?)*
      (?:(?:public|protected|private|internal|final|open|abstract|override|
            suspend|inline|tailrec|operator|infix|external)\s+)*
      fun\s+(?:<[^>{};]+>\s*)?
      (?:[A-Za-z_$][\w$<>?.]*\.)?
      (?P<name>`[^`]+`|[A-Za-z_$][\w$]*)\s*
      \([^{};]*\)
      [^{=;]*?
    )
    (?P<brace>\{)
    """,
    re.MULTILINE | re.VERBOSE,
)

_KOTLIN_CONSTRUCTOR_RE = re.compile(
    r"""
    ^[ \t]*
    (?:(?:public|protected|private|internal)\s+)*
    (?P<name>constructor)\s*\([^{};]*\)\s*
    (?P<brace>\{)
    """,
    re.MULTILINE | re.VERBOSE,
)

_KOTLIN_INIT_RE = re.compile(r"(?m)^[ \t]*(?P<name>init)[ \t]*(?P<brace>\{)")

_KOTLIN_EXPRESSION_FUNCTION_RE = re.compile(
    r"""
    ^[ \t]*
    (?:(?:public|protected|private|internal|final|open|abstract|override|
          suspend|inline|tailrec|operator|infix|external)\s+)*
    fun\s+(?:<[^>{};]+>\s*)?
    (?:[A-Za-z_$][\w$<>?.]*\.)?
    (?P<name>`[^`]+`|[A-Za-z_$][\w$]*)\s*
    \([^{};]*\)[^\n{=;]*=([^\n]*)$
    """,
    re.MULTILINE | re.VERBOSE,
)

_JAVA_NON_METHOD_NAMES = frozenset(
    {
        "catch",
        "do",
        "else",
        "for",
        "if",
        "new",
        "return",
        "switch",
        "synchronized",
        "try",
        "while",
    }
)

_SOURCE_LANGUAGES_BY_SUFFIX: dict[str, SourceLanguage] = {
    ".java": SourceLanguage.JAVA,
    ".kt": SourceLanguage.KOTLIN,
    ".kts": SourceLanguage.KOTLIN,
    ".smali": SourceLanguage.SMALI,
    ".aidl": SourceLanguage.TEXT,
    ".gradle": SourceLanguage.TEXT,
    ".json": SourceLanguage.TEXT,
    ".properties": SourceLanguage.TEXT,
    ".pro": SourceLanguage.TEXT,
    ".txt": SourceLanguage.TEXT,
    ".xml": SourceLanguage.TEXT,
    ".yaml": SourceLanguage.TEXT,
    ".yml": SourceLanguage.TEXT,
}


def infer_source_language(path: str | Path) -> SourceLanguage | None:
    """Infer a supported language from a source path, or return ``None``."""

    return _SOURCE_LANGUAGES_BY_SUFFIX.get(Path(path).suffix.casefold())


def _mask_non_code(text: str) -> str:
    """Replace comments and quoted strings while retaining offsets/newlines."""

    output = list(text)
    index = 0
    state = "code"
    quote = ""
    while index < len(text):
        if state == "code":
            if text.startswith("//", index):
                output[index] = output[index + 1] = " "
                index += 2
                state = "line_comment"
                continue
            if text.startswith("/*", index):
                output[index] = output[index + 1] = " "
                index += 2
                state = "block_comment"
                continue
            if text.startswith('"""', index):
                output[index : index + 3] = [" ", " ", " "]
                index += 3
                state = "triple_quote"
                continue
            if text[index] in {'"', "'"}:
                quote = text[index]
                output[index] = " "
                index += 1
                state = "quote"
                continue
            index += 1
            continue

        if state == "line_comment":
            if text[index] == "\n":
                state = "code"
            else:
                output[index] = " "
            index += 1
            continue

        if state == "block_comment":
            if text.startswith("*/", index):
                output[index] = output[index + 1] = " "
                index += 2
                state = "code"
            else:
                if text[index] != "\n":
                    output[index] = " "
                index += 1
            continue

        if state == "triple_quote":
            if text.startswith('"""', index):
                output[index : index + 3] = [" ", " ", " "]
                index += 3
                state = "code"
            else:
                if text[index] != "\n":
                    output[index] = " "
                index += 1
            continue

        if text[index] == "\\" and index + 1 < len(text):
            output[index] = " "
            if text[index + 1] != "\n":
                output[index + 1] = " "
            index += 2
        elif text[index] == quote:
            output[index] = " "
            index += 1
            state = "code"
        else:
            if text[index] != "\n":
                output[index] = " "
            index += 1

    return "".join(output)


def _matching_braces(masked: str) -> dict[int, int]:
    stack: list[int] = []
    pairs: dict[int, int] = {}
    for offset, character in enumerate(masked):
        if character == "{":
            stack.append(offset)
        elif character == "}" and stack:
            pairs[stack.pop()] = offset
    return pairs


def _type_declarations(masked: str, pairs: dict[int, int]) -> list[_Declaration]:
    declarations: list[_Declaration] = []
    for match in _TYPE_DECLARATION_RE.finditer(masked):
        brace = match.start("brace")
        close = pairs.get(brace)
        if close is not None:
            declarations.append(
                _Declaration(match.group("name"), match.start(), brace, close)
            )
    return sorted(declarations, key=lambda item: (item.start_offset, item.close_brace))


def _enclosing_type_names(
    declarations: list[_Declaration], offset: int, *, include_self: bool = False
) -> tuple[str, ...]:
    enclosing = [
        declaration
        for declaration in declarations
        if declaration.open_brace < offset < declaration.close_brace
        or (
            include_self
            and declaration.start_offset <= offset <= declaration.close_brace
        )
    ]
    enclosing.sort(key=lambda item: (item.open_brace, -item.close_brace))
    return tuple(item.name for item in enclosing)


def _source_slice(
    lines: list[str], line_index: _LineIndex, start_offset: int, end_offset: int
) -> tuple[int, int, str]:
    start_line = line_index.number_at(start_offset)
    end_line = line_index.number_at(end_offset)
    return start_line, end_line, "".join(lines[start_line - 1 : end_line])


def _declaration_chunk(
    *,
    text_lines: list[str],
    line_index: _LineIndex,
    language: SourceLanguage,
    kind: ChunkKind,
    path: str,
    symbol: str,
    start_offset: int,
    end_offset: int,
) -> SourceChunk:
    start_line, end_line, content = _source_slice(
        text_lines, line_index, start_offset, end_offset
    )
    return SourceChunk(
        language=language,
        kind=kind,
        path=path,
        symbol=symbol,
        start_line=start_line,
        end_line=end_line,
        content=content,
    )


def _uncovered_line_chunks(
    text: str,
    *,
    path: str,
    language: SourceLanguage,
    covered_chunks: list[SourceChunk],
    chunk_lines: int = DEFAULT_FALLBACK_LINES,
) -> list[SourceChunk]:
    """Represent source lines outside parsed constructs without whole-file copies."""

    lines = text.splitlines(keepends=True)
    if not lines:
        return []

    intervals = sorted(
        (max(1, chunk.start_line), min(len(lines), chunk.end_line))
        for chunk in covered_chunks
    )
    merged: list[tuple[int, int]] = []
    for start_line, end_line in intervals:
        if start_line > end_line:
            continue
        if merged and start_line <= merged[-1][1] + 1:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end_line))
        else:
            merged.append((start_line, end_line))

    gaps: list[tuple[int, int]] = []
    next_line = 1
    for start_line, end_line in merged:
        if next_line < start_line:
            gaps.append((next_line, start_line - 1))
        next_line = max(next_line, end_line + 1)
    if next_line <= len(lines):
        gaps.append((next_line, len(lines)))

    chunks: list[SourceChunk] = []
    for gap_start, gap_end in gaps:
        for start_line in range(gap_start, gap_end + 1, chunk_lines):
            end_line = min(start_line + chunk_lines - 1, gap_end)
            chunks.append(
                SourceChunk(
                    language=language,
                    kind=ChunkKind.FILE,
                    path=path,
                    symbol=f"<file>:{start_line}-{end_line}",
                    start_line=start_line,
                    end_line=end_line,
                    content="".join(lines[start_line - 1 : end_line]),
                )
            )
    return chunks


def _chunk_java_or_kotlin(
    text: str, path: str, language: SourceLanguage
) -> tuple[SourceChunk, ...]:
    if not text:
        return ()

    masked = _mask_non_code(text)
    pairs = _matching_braces(masked)
    declarations = _type_declarations(masked, pairs)
    line_index = _LineIndex.from_text(text)
    lines = text.splitlines(keepends=True)
    chunks: list[SourceChunk] = []

    for declaration in declarations:
        names = _enclosing_type_names(
            declarations, declaration.start_offset, include_self=True
        )
        chunks.append(
            _declaration_chunk(
                text_lines=lines,
                line_index=line_index,
                language=language,
                kind=ChunkKind.TYPE,
                path=path,
                symbol=".".join(names),
                start_offset=declaration.start_offset,
                end_offset=declaration.close_brace,
            )
        )

    callable_matches: list[tuple[re.Match[str], int]] = []
    if language is SourceLanguage.JAVA:
        for match in _JAVA_METHOD_RE.finditer(masked):
            name = match.group("name")
            brace = match.start("brace")
            enclosing_names = _enclosing_type_names(declarations, brace)
            return_type = match.group("return_type").strip()
            if name in _JAVA_NON_METHOD_NAMES:
                continue
            if not return_type and (not enclosing_names or name != enclosing_names[-1]):
                continue
            callable_matches.append((match, brace))
    else:
        for pattern in (
            _KOTLIN_FUNCTION_RE,
            _KOTLIN_CONSTRUCTOR_RE,
            _KOTLIN_INIT_RE,
        ):
            callable_matches.extend(
                (match, match.start("brace")) for match in pattern.finditer(masked)
            )

    for match, brace in callable_matches:
        close = pairs.get(brace)
        if close is None:
            continue
        name = match.group("name").strip("`")
        enclosing_names = _enclosing_type_names(declarations, brace)
        symbol = ".".join((*enclosing_names, name))
        chunks.append(
            _declaration_chunk(
                text_lines=lines,
                line_index=line_index,
                language=language,
                kind=ChunkKind.METHOD,
                path=path,
                symbol=symbol,
                start_offset=match.start(),
                end_offset=close,
            )
        )

    if language is SourceLanguage.KOTLIN:
        for match in _KOTLIN_EXPRESSION_FUNCTION_RE.finditer(masked):
            name = match.group("name").strip("`")
            enclosing_names = _enclosing_type_names(declarations, match.start())
            symbol = ".".join((*enclosing_names, name))
            start_line = line_index.number_at(match.start())
            content = lines[start_line - 1]
            chunks.append(
                SourceChunk(
                    language=language,
                    kind=ChunkKind.METHOD,
                    path=path,
                    symbol=symbol,
                    start_line=start_line,
                    end_line=start_line,
                    content=content,
                )
            )

    if not chunks:
        return chunk_by_lines(text, path=path, language=language)

    chunks.extend(
        _uncovered_line_chunks(
            text,
            path=path,
            language=language,
            covered_chunks=chunks,
        )
    )

    kind_order = {ChunkKind.TYPE: 0, ChunkKind.METHOD: 1, ChunkKind.FILE: 2}
    unique = {chunk.id: chunk for chunk in chunks}
    return tuple(
        sorted(
            unique.values(),
            key=lambda chunk: (
                chunk.start_line,
                kind_order[chunk.kind],
                chunk.end_line,
                chunk.symbol or "",
                chunk.id,
            ),
        )
    )


def chunk_java(text: str, *, path: str) -> tuple[SourceChunk, ...]:
    """Chunk Java types and concrete methods while retaining exact line ranges."""

    return _chunk_java_or_kotlin(text, path, SourceLanguage.JAVA)


def chunk_kotlin(text: str, *, path: str) -> tuple[SourceChunk, ...]:
    """Chunk Kotlin types, constructors, initializers, and functions."""

    return _chunk_java_or_kotlin(text, path, SourceLanguage.KOTLIN)


def _smali_class_name(lines: list[str]) -> str | None:
    for line in lines:
        match = re.match(r"\s*\.class\b.*\s(L[^;]+;)", line)
        if match:
            return match.group(1)[1:-1].replace("/", ".")
    return None


def _is_smali_instruction(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped) and not stripped.startswith((".", ":", "#"))


def _smali_instruction_ordinals(lines: list[str]) -> dict[int, int]:
    ordinals: dict[int, int] = {}
    ordinal = 0
    for line_number, line in enumerate(lines, start=1):
        if _is_smali_instruction(line):
            ordinal += 1
            ordinals[line_number] = ordinal
    return ordinals


def _instruction_bounds(
    ordinals: dict[int, int], start_line: int, end_line: int
) -> tuple[int | None, int | None]:
    values = [
        ordinal
        for line_number, ordinal in ordinals.items()
        if start_line <= line_number <= end_line
    ]
    if not values:
        return None, None
    return values[0], values[-1]


def chunk_smali(text: str, *, path: str) -> tuple[SourceChunk, ...]:
    """Chunk complete Smali methods and attach one-based instruction ordinals."""

    if not text:
        return ()
    lines = text.splitlines(keepends=True)
    class_name = _smali_class_name(lines)
    ordinals = _smali_instruction_ordinals(lines)
    chunks: list[SourceChunk] = []
    line_number = 1

    while line_number <= len(lines):
        match = re.match(r"\s*\.method\b(?P<header>[^\n\r]*)", lines[line_number - 1])
        if match is None:
            line_number += 1
            continue

        end_line = line_number + 1
        while end_line <= len(lines):
            if re.match(r"\s*\.end\s+method\b", lines[end_line - 1]):
                break
            end_line += 1
        if end_line > len(lines):
            line_number += 1
            continue

        header = match.group("header").strip()
        signature_match = re.search(r"([^\s(]+\([^\s]*)$", header)
        signature = signature_match.group(1) if signature_match else header
        symbol = f"{class_name}->{signature}" if class_name else signature
        instruction_start, instruction_end = _instruction_bounds(
            ordinals, line_number, end_line
        )
        chunks.append(
            SourceChunk(
                language=SourceLanguage.SMALI,
                kind=ChunkKind.METHOD,
                path=path,
                symbol=symbol,
                start_line=line_number,
                end_line=end_line,
                start_instruction=instruction_start,
                end_instruction=instruction_end,
                content="".join(lines[line_number - 1 : end_line]),
            )
        )
        line_number = end_line + 1

    if not chunks:
        return chunk_by_lines(text, path=path, language=SourceLanguage.SMALI)
    chunks.extend(
        _uncovered_line_chunks(
            text,
            path=path,
            language=SourceLanguage.SMALI,
            covered_chunks=chunks,
        )
    )
    return tuple(
        sorted(
            chunks,
            key=lambda chunk: (
                chunk.start_line,
                0 if chunk.kind is ChunkKind.METHOD else 1,
                chunk.end_line,
                chunk.id,
            ),
        )
    )


def chunk_by_lines(
    text: str,
    *,
    path: str,
    language: SourceLanguage = SourceLanguage.TEXT,
    chunk_lines: int = DEFAULT_FALLBACK_LINES,
    overlap_lines: int = DEFAULT_FALLBACK_OVERLAP,
) -> tuple[SourceChunk, ...]:
    """Split text into deterministic overlapping windows for safe fallback."""

    if chunk_lines < 1:
        raise ValueError("chunk_lines must be at least 1")
    if overlap_lines < 0 or overlap_lines >= chunk_lines:
        raise ValueError("overlap_lines must be non-negative and less than chunk_lines")
    if not text:
        return ()

    lines = text.splitlines(keepends=True)
    ordinals = (
        _smali_instruction_ordinals(lines) if language is SourceLanguage.SMALI else {}
    )
    step = chunk_lines - overlap_lines
    chunks: list[SourceChunk] = []
    start_line = 1
    while start_line <= len(lines):
        end_line = min(start_line + chunk_lines - 1, len(lines))
        instruction_start, instruction_end = _instruction_bounds(
            ordinals, start_line, end_line
        )
        symbol = (
            "<file>"
            if start_line == 1 and end_line == len(lines)
            else f"<file>:{start_line}-{end_line}"
        )
        chunks.append(
            SourceChunk(
                language=language,
                kind=ChunkKind.FILE,
                path=path,
                symbol=symbol,
                start_line=start_line,
                end_line=end_line,
                start_instruction=instruction_start,
                end_instruction=instruction_end,
                content="".join(lines[start_line - 1 : end_line]),
            )
        )
        if end_line == len(lines):
            break
        start_line += step
    return tuple(chunks)


def chunk_source(
    text: str, *, path: str, language: SourceLanguage | None = None
) -> tuple[SourceChunk, ...]:
    """Dispatch a source file to its language-specific deterministic chunker."""

    selected_language = language or infer_source_language(path) or SourceLanguage.TEXT
    if selected_language is SourceLanguage.JAVA:
        return chunk_java(text, path=path)
    if selected_language is SourceLanguage.KOTLIN:
        return chunk_kotlin(text, path=path)
    if selected_language is SourceLanguage.SMALI:
        return chunk_smali(text, path=path)
    return chunk_by_lines(text, path=path, language=selected_language)


@dataclass(frozen=True)
class _FallbackReadResult:
    chunks: tuple[SourceChunk, ...]
    byte_count: int
    reason: SourceIndexWarningReason | None = None
    detail: str | None = None


def _fallback_window_chunk(
    lines: list[tuple[str, int | None]],
    *,
    path: str,
    language: SourceLanguage,
    start_line: int,
    entire_file: bool,
) -> SourceChunk:
    end_line = start_line + len(lines) - 1
    instructions = [ordinal for _, ordinal in lines if ordinal is not None]
    symbol = "<file>" if entire_file else f"<file>:{start_line}-{end_line}"
    return SourceChunk(
        language=language,
        kind=ChunkKind.FILE,
        path=path,
        symbol=symbol,
        start_line=start_line,
        end_line=end_line,
        start_instruction=instructions[0] if instructions else None,
        end_instruction=instructions[-1] if instructions else None,
        content="".join(line for line, _ in lines),
    )


def _stream_fallback_chunks(
    source_path: Path,
    *,
    path: str,
    language: SourceLanguage,
    max_file_bytes: int,
    chunk_lines: int,
    overlap_lines: int,
) -> _FallbackReadResult:
    """Read at most ``max_file_bytes`` and emit deterministic line windows."""

    chunks: list[SourceChunk] = []
    window: list[tuple[str, int | None]] = []
    start_line = 1
    line_count = 0
    instruction_count = 0
    byte_count = 0
    first_line = True
    step = chunk_lines - overlap_lines

    try:
        with source_path.open("rb") as source:
            while True:
                remaining = max_file_bytes - byte_count
                raw_line = source.readline(remaining + 1)
                if not raw_line:
                    break
                byte_count += len(raw_line)
                if byte_count > max_file_bytes:
                    return _FallbackReadResult(
                        chunks=(),
                        byte_count=byte_count,
                        reason=SourceIndexWarningReason.SIZE_LIMIT_EXCEEDED,
                        detail=(
                            "source exceeds the fallback safety limit of "
                            f"{max_file_bytes} bytes"
                        ),
                    )
                if b"\x00" in raw_line:
                    return _FallbackReadResult(
                        chunks=(),
                        byte_count=byte_count,
                        reason=SourceIndexWarningReason.BINARY,
                        detail="source contains NUL bytes",
                    )
                try:
                    line = raw_line.decode("utf-8-sig" if first_line else "utf-8")
                except UnicodeDecodeError:
                    return _FallbackReadResult(
                        chunks=(),
                        byte_count=byte_count,
                        reason=SourceIndexWarningReason.INVALID_UTF8,
                        detail="source is not valid UTF-8",
                    )
                first_line = False
                if not line:
                    continue

                if len(window) == chunk_lines:
                    chunks.append(
                        _fallback_window_chunk(
                            window,
                            path=path,
                            language=language,
                            start_line=start_line,
                            entire_file=False,
                        )
                    )
                    window = window[-overlap_lines:] if overlap_lines else []
                    start_line += step

                line_count += 1
                ordinal: int | None = None
                if language is SourceLanguage.SMALI and _is_smali_instruction(line):
                    instruction_count += 1
                    ordinal = instruction_count
                window.append((line, ordinal))
    except OSError:
        return _FallbackReadResult(
            chunks=(),
            byte_count=byte_count,
            reason=SourceIndexWarningReason.UNREADABLE,
            detail="source could not be read",
        )

    if window:
        chunks.append(
            _fallback_window_chunk(
                window,
                path=path,
                language=language,
                start_line=start_line,
                entire_file=start_line == 1 and len(window) == line_count,
            )
        )
    return _FallbackReadResult(chunks=tuple(chunks), byte_count=byte_count)


def index_source_tree(
    root: Path,
    *,
    max_file_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
    max_fallback_file_bytes: int = DEFAULT_MAX_FALLBACK_SOURCE_BYTES,
    fallback_chunk_lines: int = DEFAULT_FALLBACK_LINES,
    fallback_overlap_lines: int = DEFAULT_FALLBACK_OVERLAP,
) -> tuple[SourceChunk, ...]:
    """Return chunks from :func:`index_source_tree_with_report`.

    This compatibility wrapper retains the original tuple-returning API. Call
    :func:`index_source_tree_with_report` when source accounting is required.
    """

    return index_source_tree_with_report(
        root,
        max_file_bytes=max_file_bytes,
        max_fallback_file_bytes=max_fallback_file_bytes,
        fallback_chunk_lines=fallback_chunk_lines,
        fallback_overlap_lines=fallback_overlap_lines,
    ).chunks


def index_source_tree_with_report(
    root: Path,
    *,
    max_file_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
    max_fallback_file_bytes: int = DEFAULT_MAX_FALLBACK_SOURCE_BYTES,
    fallback_chunk_lines: int = DEFAULT_FALLBACK_LINES,
    fallback_overlap_lines: int = DEFAULT_FALLBACK_OVERLAP,
    max_warnings: int = DEFAULT_MAX_SOURCE_WARNINGS,
) -> SourceTreeIndexResult:
    """Recursively chunk supported UTF-8 files and report every fallback/skip.

    ``max_file_bytes`` bounds whole-file parsing. Larger files are read as
    bounded line windows up to ``max_fallback_file_bytes``. Pathological files
    beyond that hard limit and unsafe inputs are skipped with explicit,
    bounded warnings rather than disappearing silently.
    """

    if max_file_bytes < 1:
        raise ValueError("max_file_bytes must be at least 1")
    if max_fallback_file_bytes < max_file_bytes:
        raise ValueError(
            "max_fallback_file_bytes must be greater than or equal to max_file_bytes"
        )
    if fallback_chunk_lines < 1:
        raise ValueError("fallback_chunk_lines must be at least 1")
    if fallback_overlap_lines < 0 or fallback_overlap_lines >= fallback_chunk_lines:
        raise ValueError(
            "fallback_overlap_lines must be non-negative and less than "
            "fallback_chunk_lines"
        )
    if max_warnings < 0:
        raise ValueError("max_warnings must be non-negative")
    if root.is_symlink() or not root.is_dir():
        raise ValueError("root must be a non-symlink source directory")

    indexed: list[SourceChunk] = []
    indexed_file_count = 0
    skipped_file_count = 0
    oversized_fallback_file_count = 0
    warning_count = 0
    warnings: list[SourceIndexWarning] = []

    def record_warning(
        path: str, reason: SourceIndexWarningReason, detail: str
    ) -> None:
        nonlocal warning_count
        warning_count += 1
        if len(warnings) < max_warnings:
            warnings.append(SourceIndexWarning(path=path, reason=reason, detail=detail))

    for current_dir, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current_dir)
        directories[:] = sorted(
            directory
            for directory in directories
            if not (current_path / directory).is_symlink()
        )
        for filename in sorted(filenames):
            source_path = current_path / filename
            language = infer_source_language(source_path)
            if language is None:
                continue
            relative_path = source_path.relative_to(root).as_posix()
            if source_path.is_symlink():
                skipped_file_count += 1
                record_warning(
                    relative_path,
                    SourceIndexWarningReason.SYMLINK,
                    "symbolic links are not indexed",
                )
                continue
            try:
                size = source_path.stat().st_size
            except OSError:
                skipped_file_count += 1
                record_warning(
                    relative_path,
                    SourceIndexWarningReason.UNREADABLE,
                    "source metadata could not be read",
                )
                continue
            if size > max_fallback_file_bytes:
                skipped_file_count += 1
                record_warning(
                    relative_path,
                    SourceIndexWarningReason.SIZE_LIMIT_EXCEEDED,
                    "source exceeds the fallback safety limit of "
                    f"{max_fallback_file_bytes} bytes",
                )
                continue

            raw: bytes | None = None
            use_fallback = size > max_file_bytes
            if not use_fallback:
                try:
                    with source_path.open("rb") as source:
                        raw = source.read(max_file_bytes + 1)
                except OSError:
                    skipped_file_count += 1
                    record_warning(
                        relative_path,
                        SourceIndexWarningReason.UNREADABLE,
                        "source could not be read",
                    )
                    continue
                use_fallback = len(raw) > max_file_bytes

            if use_fallback:
                fallback = _stream_fallback_chunks(
                    source_path,
                    path=relative_path,
                    language=language,
                    max_file_bytes=max_fallback_file_bytes,
                    chunk_lines=fallback_chunk_lines,
                    overlap_lines=fallback_overlap_lines,
                )
                if fallback.reason is not None:
                    skipped_file_count += 1
                    record_warning(
                        relative_path,
                        fallback.reason,
                        fallback.detail or "source could not be indexed",
                    )
                    continue
                if not fallback.chunks:
                    skipped_file_count += 1
                    record_warning(
                        relative_path,
                        SourceIndexWarningReason.EMPTY,
                        "source has no indexable UTF-8 content",
                    )
                    continue
                indexed.extend(fallback.chunks)
                indexed_file_count += 1
                oversized_fallback_file_count += 1
                record_warning(
                    relative_path,
                    SourceIndexWarningReason.OVERSIZED_FALLBACK,
                    f"{fallback.byte_count} bytes exceeds the structured-parser "
                    f"limit of {max_file_bytes} bytes; indexed as bounded line "
                    "windows",
                )
                continue

            assert raw is not None
            if b"\x00" in raw:
                skipped_file_count += 1
                record_warning(
                    relative_path,
                    SourceIndexWarningReason.BINARY,
                    "source contains NUL bytes",
                )
                continue
            try:
                text = raw.decode("utf-8-sig")
            except UnicodeDecodeError:
                skipped_file_count += 1
                record_warning(
                    relative_path,
                    SourceIndexWarningReason.INVALID_UTF8,
                    "source is not valid UTF-8",
                )
                continue

            if language is SourceLanguage.TEXT:
                chunks = chunk_by_lines(
                    text,
                    path=relative_path,
                    language=language,
                    chunk_lines=fallback_chunk_lines,
                    overlap_lines=fallback_overlap_lines,
                )
            else:
                chunks = chunk_source(text, path=relative_path, language=language)
            if not chunks:
                skipped_file_count += 1
                record_warning(
                    relative_path,
                    SourceIndexWarningReason.EMPTY,
                    "source has no indexable UTF-8 content",
                )
                continue
            indexed.extend(chunks)
            indexed_file_count += 1

    return SourceTreeIndexResult(
        chunks=tuple(indexed),
        indexed_file_count=indexed_file_count,
        skipped_file_count=skipped_file_count,
        oversized_fallback_file_count=oversized_fallback_file_count,
        warning_count=warning_count,
        warnings=tuple(warnings),
    )
