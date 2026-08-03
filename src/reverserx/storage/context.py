"""Durable source-index metadata and chunk persistence."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from reverserx.context.chunking import (
    SOURCE_CHUNKER_VERSION,
    ChunkKind,
    SourceChunk,
    SourceLanguage,
)
from reverserx.core.models import new_id, utc_now
from reverserx.storage.database import Database, NotFoundError

DEFAULT_CHUNK_FETCH_BATCH_SIZE = 512
MAX_CHUNK_FETCH_BATCH_SIZE = 10_000
SQLITE_SAFE_IN_BATCH_SIZE = 500
MAX_CANDIDATE_CHUNK_IDS = 10_000
MAX_KNOWN_PATH_PREFIXES = 64
MAX_KNOWN_PATH_PREFIX_LENGTH = 1_024
MAX_KNOWN_PATH_RESULTS = 10_000
KNOWN_PATH_SQL_BATCH_SIZE = 32


class ContextIndex(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    id: str = Field(default_factory=lambda: new_id("idx"))
    project_id: str
    artifact_id: str | None = None
    source_root: str
    source_fingerprint: str
    chunker_version: str = SOURCE_CHUNKER_VERSION
    chunk_count: int = Field(ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class ContextSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(default_factory=lambda: new_id("sum"))
    index_id: str
    level: Literal["method", "class", "package", "project"]
    scope: str
    source_fingerprint: str
    content: str
    created_at: datetime = Field(default_factory=utc_now)


class VectorIndexMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    index_id: str
    backend: str
    collection_name: str
    embedding_provider: str
    dimensions: int = Field(ge=0)
    document_count: int = Field(ge=0)
    updated_at: datetime = Field(default_factory=utc_now)


class ContextRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def replace_index(
        self,
        *,
        project_id: str,
        source_root: Path,
        chunks: tuple[SourceChunk, ...],
        artifact_id: str | None = None,
        chunker_version: str = SOURCE_CHUNKER_VERSION,
        metadata: dict[str, Any] | None = None,
    ) -> ContextIndex:
        canonical_artifact_id = self.validate_project_artifact(project_id, artifact_id)
        resolved_root = str(source_root.expanduser().resolve())
        fingerprint = source_fingerprint(chunks, chunker_version=chunker_version)
        deterministic_id = _index_id(project_id, canonical_artifact_id, resolved_root)
        now = utc_now()
        with self.database.connect() as connection:
            matching_identity = connection.execute(
                """
                SELECT id FROM analysis_indexes
                WHERE project_id = ? AND artifact_id IS ? AND source_root = ?
                ORDER BY created_at, id LIMIT 1
                """,
                (project_id, canonical_artifact_id, resolved_root),
            ).fetchone()
            index_id = (
                matching_identity["id"]
                if matching_identity is not None
                else deterministic_id
            )
            existing = connection.execute(
                "SELECT created_at FROM analysis_indexes WHERE id = ?", (index_id,)
            ).fetchone()
            created_at = existing["created_at"] if existing else now.isoformat()
            connection.execute(
                """
                INSERT INTO analysis_indexes(
                    id, schema_version, project_id, artifact_id, source_root,
                    source_fingerprint, chunker_version, chunk_count,
                    metadata_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    artifact_id = excluded.artifact_id,
                    source_fingerprint = excluded.source_fingerprint,
                    chunker_version = excluded.chunker_version,
                    chunk_count = excluded.chunk_count,
                    metadata_json = excluded.metadata_json,
                    updated_at = excluded.updated_at
                """,
                (
                    index_id,
                    "1.0",
                    project_id,
                    canonical_artifact_id,
                    resolved_root,
                    fingerprint,
                    chunker_version,
                    len(chunks),
                    _json(metadata or {}),
                    created_at,
                    now.isoformat(),
                ),
            )
            connection.execute(
                "DELETE FROM source_chunks WHERE index_id = ?", (index_id,)
            )
            connection.execute(
                "DELETE FROM context_summaries WHERE index_id = ?", (index_id,)
            )
            connection.executemany(
                """
                INSERT INTO source_chunks(
                    id, schema_version, index_id, project_id, artifact_id,
                    content_sha256, language, kind, relative_path, symbol,
                    start_line, end_line, start_instruction, end_instruction,
                    content, summary, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    (
                        chunk.id,
                        chunk.schema_version,
                        index_id,
                        project_id,
                        canonical_artifact_id,
                        chunk.content_sha256,
                        chunk.language.value,
                        chunk.kind.value,
                        chunk.path,
                        chunk.symbol,
                        chunk.start_line,
                        chunk.end_line,
                        chunk.start_instruction,
                        chunk.end_instruction,
                        chunk.content,
                        None,
                        "{}",
                    )
                    for chunk in chunks
                ),
            )
        return self.get_index(index_id)

    def get_index(self, reference: str) -> ContextIndex:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM analysis_indexes WHERE id = ?", (reference,)
            ).fetchone()
        if row is None:
            raise NotFoundError(f"context index not found: {reference}")
        return _index_from_row(row)

    def validate_project_artifact(
        self, project_id: str, artifact_id: str | None
    ) -> str | None:
        """Require project ownership and return the canonical artifact ID."""

        project = self.database.get_project(project_id)
        if project.id != project_id:
            raise NotFoundError(f"project not found: {project_id}")
        if artifact_id is not None:
            return self.database.get_artifact(project_id, artifact_id).id
        return None

    def latest_index(self, project_id: str) -> ContextIndex:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM analysis_indexes
                WHERE project_id = ? ORDER BY updated_at DESC, id DESC LIMIT 1
                """,
                (project_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError(f"no context index found for project: {project_id}")
        return _index_from_row(row)

    def list_chunks(self, index_id: str) -> tuple[SourceChunk, ...]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM source_chunks
                WHERE index_id = ? ORDER BY relative_path, start_line, id
                """,
                (index_id,),
            ).fetchall()
        return tuple(_chunk_from_row(row) for row in rows)

    def iter_chunks(
        self,
        index_id: str,
        *,
        batch_size: int = DEFAULT_CHUNK_FETCH_BATCH_SIZE,
    ) -> Iterator[SourceChunk]:
        """Yield ordered chunks without materializing the complete index."""

        if not 1 <= batch_size <= MAX_CHUNK_FETCH_BATCH_SIZE:
            raise ValueError(
                f"batch_size must be between 1 and {MAX_CHUNK_FETCH_BATCH_SIZE}"
            )

        with self.database.connect() as connection:
            cursor = connection.execute(
                """
                SELECT * FROM source_chunks
                WHERE index_id = ? ORDER BY relative_path, start_line, id
                """,
                (index_id,),
            )
            while rows := cursor.fetchmany(batch_size):
                for row in rows:
                    yield _chunk_from_row(row)

    def get_chunks_by_ids(
        self, index_id: str, chunk_ids: Iterable[str]
    ) -> tuple[SourceChunk, ...]:
        """Fetch a bounded chunk set using safe SQLite ``IN`` batches."""

        ids = _bounded_unique_strings(
            chunk_ids,
            maximum=MAX_CANDIDATE_CHUNK_IDS,
            label="chunk IDs",
        )
        if not ids:
            return ()
        by_id: dict[str, SourceChunk] = {}
        with self.database.connect() as connection:
            for batch in _string_batches(ids, SQLITE_SAFE_IN_BATCH_SIZE):
                placeholders = ",".join("?" for _ in batch)
                rows = connection.execute(
                    f"""
                    SELECT * FROM source_chunks
                    WHERE index_id = ? AND id IN ({placeholders})
                    """,  # noqa: S608 - placeholders are generated, not user input
                    (index_id, *batch),
                ).fetchall()
                by_id.update((str(row["id"]), _chunk_from_row(row)) for row in rows)
        return tuple(by_id[chunk_id] for chunk_id in ids if chunk_id in by_id)

    def list_chunks_by_path_prefixes(
        self,
        index_id: str,
        path_prefixes: Iterable[str],
        *,
        limit: int,
    ) -> tuple[SourceChunk, ...]:
        """Return a bounded set of chunks whose relative paths match hints."""

        if not 1 <= limit <= MAX_KNOWN_PATH_RESULTS:
            raise ValueError(f"limit must be between 1 and {MAX_KNOWN_PATH_RESULTS}")
        prefixes = _bounded_unique_strings(
            path_prefixes,
            maximum=MAX_KNOWN_PATH_PREFIXES,
            label="known path prefixes",
            maximum_length=MAX_KNOWN_PATH_PREFIX_LENGTH,
        )
        if not prefixes:
            return ()
        by_id: dict[str, SourceChunk] = {}
        with self.database.connect() as connection:
            for batch in _string_batches(prefixes, KNOWN_PATH_SQL_BATCH_SIZE):
                clauses = " OR ".join(
                    "substr(relative_path, 1, length(?)) = ?" for _ in batch
                )
                parameters: list[str | int] = [index_id]
                for prefix in batch:
                    parameters.extend((prefix, prefix))
                parameters.append(limit)
                rows = connection.execute(
                    f"""
                    SELECT * FROM source_chunks
                    WHERE index_id = ? AND ({clauses})
                    ORDER BY relative_path, start_line, id
                    LIMIT ?
                    """,  # noqa: S608 - clauses contain only fixed SQL fragments
                    parameters,
                ).fetchall()
                for row in rows:
                    by_id.setdefault(str(row["id"]), _chunk_from_row(row))
                    if len(by_id) == limit:
                        break
                if len(by_id) == limit:
                    break
        return tuple(
            sorted(
                by_id.values(),
                key=lambda chunk: (chunk.path, chunk.start_line, chunk.id),
            )
        )

    def save_summaries(self, summaries: tuple[ContextSummary, ...]) -> None:
        if not summaries:
            return
        with self.database.connect() as connection:
            connection.executemany(
                """
                INSERT INTO context_summaries(
                    id, index_id, level, scope, source_fingerprint, content, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(index_id, level, scope) DO UPDATE SET
                    id = excluded.id,
                    source_fingerprint = excluded.source_fingerprint,
                    content = excluded.content,
                    created_at = excluded.created_at
                """,
                (
                    (
                        summary.id,
                        summary.index_id,
                        summary.level,
                        summary.scope,
                        summary.source_fingerprint,
                        summary.content,
                        summary.created_at.isoformat(),
                    )
                    for summary in summaries
                ),
            )

    def list_summaries(self, index_id: str) -> tuple[ContextSummary, ...]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM context_summaries
                WHERE index_id = ? ORDER BY level, scope
                """,
                (index_id,),
            ).fetchall()
        return tuple(
            ContextSummary.model_validate(
                {
                    "id": row["id"],
                    "index_id": row["index_id"],
                    "level": row["level"],
                    "scope": row["scope"],
                    "source_fingerprint": row["source_fingerprint"],
                    "content": row["content"],
                    "created_at": row["created_at"],
                }
            )
            for row in rows
        )

    def list_method_summaries_by_chunk_ids(
        self,
        index_id: str,
        chunk_ids: Iterable[str],
    ) -> tuple[ContextSummary, ...]:
        """Fetch only method summaries associated with bounded candidates."""

        ids = _bounded_unique_strings(
            chunk_ids,
            maximum=MAX_CANDIDATE_CHUNK_IDS,
            label="chunk IDs",
        )
        if not ids:
            return ()
        summaries: dict[str, ContextSummary] = {}
        with self.database.connect() as connection:
            for batch in _string_batches(ids, SQLITE_SAFE_IN_BATCH_SIZE):
                placeholders = ",".join("?" for _ in batch)
                rows = connection.execute(
                    f"""
                    SELECT * FROM context_summaries
                    WHERE index_id = ? AND level = 'method'
                      AND scope IN ({placeholders})
                    """,  # noqa: S608 - placeholders are generated, not user input
                    (index_id, *batch),
                ).fetchall()
                for row in rows:
                    summary = _summary_from_row(row)
                    summaries[summary.scope] = summary
        return tuple(summaries[scope] for scope in ids if scope in summaries)

    def save_vector_metadata(self, metadata: VectorIndexMetadata) -> None:
        data = metadata.model_dump(mode="json")
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO vector_indexes(
                    index_id, backend, collection_name, embedding_provider,
                    dimensions, document_count, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(index_id) DO UPDATE SET
                    backend = excluded.backend,
                    collection_name = excluded.collection_name,
                    embedding_provider = excluded.embedding_provider,
                    dimensions = excluded.dimensions,
                    document_count = excluded.document_count,
                    updated_at = excluded.updated_at
                """,
                (
                    data["index_id"],
                    data["backend"],
                    data["collection_name"],
                    data["embedding_provider"],
                    data["dimensions"],
                    data["document_count"],
                    data["updated_at"],
                ),
            )

    def get_vector_metadata(self, index_id: str) -> VectorIndexMetadata | None:
        """Return the last successfully published vector build, if present."""

        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM vector_indexes WHERE index_id = ?", (index_id,)
            ).fetchone()
        if row is None:
            return None
        return VectorIndexMetadata.model_validate(
            {
                "index_id": row["index_id"],
                "backend": row["backend"],
                "collection_name": row["collection_name"],
                "embedding_provider": row["embedding_provider"],
                "dimensions": row["dimensions"],
                "document_count": row["document_count"],
                "updated_at": row["updated_at"],
            }
        )


def source_fingerprint(
    chunks: tuple[SourceChunk, ...],
    *,
    chunker_version: str = SOURCE_CHUNKER_VERSION,
) -> str:
    digest = hashlib.sha256()
    digest.update(b"reverserx-source-index\0")
    digest.update(chunker_version.encode("utf-8"))
    digest.update(b"\0")
    for chunk in sorted(chunks, key=lambda item: item.id):
        digest.update(chunk.id.encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def _index_id(project_id: str, artifact_id: str | None, source_root: str) -> str:
    identity = _json(
        {
            "artifact_id": artifact_id,
            "project_id": project_id,
            "source_root": source_root,
        }
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return f"idx_{digest}"


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _bounded_unique_strings(
    values: Iterable[str],
    *,
    maximum: int,
    label: str,
    maximum_length: int | None = None,
) -> tuple[str, ...]:
    unique: dict[str, None] = {}
    for value in values:
        if not isinstance(value, str):
            raise ValueError(f"{label} must contain strings")
        if not value or "\x00" in value:
            raise ValueError(f"{label} cannot contain blank or NUL values")
        if maximum_length is not None and len(value) > maximum_length:
            raise ValueError(
                f"{label} values cannot exceed {maximum_length} characters"
            )
        unique.setdefault(value, None)
        if len(unique) > maximum:
            raise ValueError(f"{label} cannot contain more than {maximum} values")
    return tuple(unique)


def _string_batches(values: tuple[str, ...], size: int) -> Iterator[tuple[str, ...]]:
    for start in range(0, len(values), size):
        yield values[start : start + size]


def _index_from_row(row: sqlite3.Row) -> ContextIndex:
    return ContextIndex.model_validate(
        {
            "id": row["id"],
            "schema_version": row["schema_version"],
            "project_id": row["project_id"],
            "artifact_id": row["artifact_id"],
            "source_root": row["source_root"],
            "source_fingerprint": row["source_fingerprint"],
            "chunker_version": row["chunker_version"],
            "chunk_count": row["chunk_count"],
            "metadata": json.loads(row["metadata_json"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
    )


def _chunk_from_row(row: sqlite3.Row) -> SourceChunk:
    return SourceChunk.model_validate(
        {
            "schema_version": row["schema_version"],
            "id": row["id"],
            "content_sha256": row["content_sha256"],
            "language": SourceLanguage(row["language"]),
            "kind": ChunkKind(row["kind"]),
            "path": row["relative_path"],
            "symbol": row["symbol"],
            "start_line": row["start_line"],
            "end_line": row["end_line"],
            "start_instruction": row["start_instruction"],
            "end_instruction": row["end_instruction"],
            "content": row["content"],
        }
    )


def _summary_from_row(row: sqlite3.Row) -> ContextSummary:
    return ContextSummary.model_validate(
        {
            "id": row["id"],
            "index_id": row["index_id"],
            "level": row["level"],
            "scope": row["scope"],
            "source_fingerprint": row["source_fingerprint"],
            "content": row["content"],
            "created_at": row["created_at"],
        }
    )
