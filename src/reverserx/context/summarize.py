"""Deterministic hierarchy summaries used before model-generated summaries exist."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from pathlib import PurePosixPath

from reverserx.context.chunking import ChunkKind, SourceChunk
from reverserx.storage.context import ContextIndex, ContextSummary

INTERESTING_PATTERNS = {
    "cryptography": re.compile(
        r"\b(?:Cipher|SecretKey|MessageDigest|Mac|encrypt|decrypt)\b", re.I
    ),
    "networking": re.compile(
        r"\b(?:https?|Retrofit|OkHttp|Request|Response|socket)\b", re.I
    ),
    "authentication": re.compile(
        r"\b(?:auth|login|token|jwt|oauth|credential)\b", re.I
    ),
    "native/JNI": re.compile(r"\b(?:native|System\.loadLibrary|JNI)\b"),
    "reflection": re.compile(r"\b(?:Class\.forName|getDeclaredMethod|reflect)\b"),
}


def build_hierarchical_summaries(
    index: ContextIndex, chunks: tuple[SourceChunk, ...]
) -> tuple[ContextSummary, ...]:
    summaries: list[ContextSummary] = []
    for chunk in chunks:
        if chunk.kind is not ChunkKind.METHOD:
            continue
        summaries.append(
            _summary(
                index,
                "method",
                chunk.id,
                _method_summary(chunk),
            )
        )

    by_file: dict[str, list[SourceChunk]] = defaultdict(list)
    by_package: dict[str, list[SourceChunk]] = defaultdict(list)
    for chunk in chunks:
        by_file[chunk.path].append(chunk)
        package = PurePosixPath(chunk.path).parent.as_posix()
        by_package[package].append(chunk)

    for path, file_chunks in sorted(by_file.items()):
        symbols = sorted({chunk.symbol for chunk in file_chunks if chunk.symbol})
        indicators = _indicators("\n".join(chunk.content for chunk in file_chunks))
        content = (
            f"{path}: {len(file_chunks)} chunks, "
            f"{sum(chunk.kind is ChunkKind.METHOD for chunk in file_chunks)} methods. "
            f"Symbols: {_bounded_join(symbols, 20)}. "
            f"Indicators: {_bounded_join(indicators, 10)}."
        )
        summaries.append(_summary(index, "class", path, content))

    for package, package_chunks in sorted(by_package.items()):
        paths = sorted({chunk.path for chunk in package_chunks})
        symbols = sorted({chunk.symbol for chunk in package_chunks if chunk.symbol})
        content = (
            f"Package {package or '<root>'}: {len(paths)} files, "
            f"{len(package_chunks)} chunks. Files: {_bounded_join(paths, 15)}. "
            f"Symbols: {_bounded_join(symbols, 25)}."
        )
        summaries.append(_summary(index, "package", package or "<root>", content))

    languages = sorted({chunk.language.value for chunk in chunks})
    project_content = (
        f"Project index {index.id}: {len(by_file)} source files and {len(chunks)} chunks "
        f"across {', '.join(languages) or 'no recognized languages'}; "
        f"fingerprint {index.source_fingerprint}."
    )
    summaries.append(_summary(index, "project", index.project_id, project_content))
    return tuple(summaries)


def _method_summary(chunk: SourceChunk) -> str:
    indicators = _indicators(chunk.content)
    signature = next(
        (line.strip() for line in chunk.content.splitlines() if line.strip()),
        "<empty>",
    )
    if len(signature) > 240:
        signature = f"{signature[:237]}..."
    return (
        f"{chunk.symbol or '<anonymous>'} in {chunk.path}:{chunk.start_line}-"
        f"{chunk.end_line}; signature `{signature}`; indicators: "
        f"{_bounded_join(indicators, 10)}."
    )


def _indicators(content: str) -> list[str]:
    return [
        name
        for name, pattern in INTERESTING_PATTERNS.items()
        if pattern.search(content)
    ]


def _bounded_join(values: list[str], limit: int) -> str:
    if not values:
        return "none"
    selected = values[:limit]
    suffix = f" (+{len(values) - limit} more)" if len(values) > limit else ""
    return ", ".join(selected) + suffix


def _summary(
    index: ContextIndex,
    level: str,
    scope: str,
    content: str,
) -> ContextSummary:
    digest = hashlib.sha256(
        f"{index.id}\0{level}\0{scope}\0{index.source_fingerprint}".encode()
    ).hexdigest()
    return ContextSummary.model_validate(
        {
            "id": f"sum_{digest}",
            "index_id": index.id,
            "level": level,
            "scope": scope,
            "source_fingerprint": index.source_fingerprint,
            "content": content,
        }
    )
