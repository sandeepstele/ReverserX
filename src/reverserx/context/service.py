"""Phase 1 source indexing and hybrid context retrieval orchestration."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from reverserx.context.budget import PackedContext, RankedChunk, pack_context
from reverserx.context.chunking import (
    SourceChunk,
    SourceIndexWarning,
    index_source_tree_with_report,
)
from reverserx.context.embedding import (
    ChromaVectorIndex,
    EmbeddingError,
    HashingEmbeddingProvider,
    MemoryVectorIndex,
    OllamaEmbeddingProvider,
    SemanticDocument,
    chroma_collection_name,
    memory_collection_name,
)
from reverserx.context.summarize import build_hierarchical_summaries
from reverserx.storage.context import (
    ContextIndex,
    ContextRepository,
    VectorIndexMetadata,
)

QUERY_TOKEN = re.compile(r"[A-Za-z_$][A-Za-z0-9_$.-]*|[0-9]+")
MAX_MEMORY_VECTOR_CHUNKS = 10_000
MIN_SEMANTIC_CANDIDATES = 100
SEMANTIC_CANDIDATE_MULTIPLIER = 5
MAX_SEMANTIC_CANDIDATES = 2_000
MAX_KNOWN_PATH_CANDIDATES = 1_000


class ContextIsolationError(ValueError):
    """Raised when source indexing escapes its owning project's data area."""


class ContextBuildResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    index: ContextIndex
    source_file_count: int = Field(ge=0)
    skipped_source_file_count: int = Field(default=0, ge=0)
    oversized_fallback_source_file_count: int = Field(default=0, ge=0)
    source_index_warning_count: int = Field(default=0, ge=0)
    source_index_warnings: tuple[SourceIndexWarning, ...] = ()
    chunk_count: int = Field(ge=0)
    summary_count: int = Field(ge=0)
    vector_backend: str
    embedding_provider: str


class HybridMatch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    chunk_id: str
    path: str
    symbol: str | None = None
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    lexical_score: float = Field(ge=0, le=1)
    semantic_score: float = Field(ge=0, le=1)
    location_boost: float = Field(ge=0, le=1)
    score: float = Field(ge=0, le=1)


class ContextQueryResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    index_id: str
    query: str
    matches: tuple[HybridMatch, ...]
    packed_context: PackedContext


class ContextService:
    def __init__(
        self,
        repository: ContextRepository,
        vector_root: Path,
        *,
        data_dir: Path | None = None,
    ) -> None:
        self.repository = repository
        self.vector_root = vector_root.expanduser().resolve()
        self.data_dir = (
            data_dir.expanduser().resolve()
            if data_dir is not None
            else self.vector_root.parent
        )

    def build(
        self,
        *,
        project_id: str,
        source_root: Path,
        artifact_id: str | None = None,
        vector_backend: Literal["chroma", "memory"] = "chroma",
        embedding_provider: Literal["hashing", "ollama"] = "hashing",
    ) -> ContextBuildResult:
        canonical_artifact_id = self.repository.validate_project_artifact(
            project_id, artifact_id
        )
        resolved_source_root = _require_project_source_root(
            source_root,
            data_dir=self.data_dir,
            project_id=project_id,
        )
        source_index = index_source_tree_with_report(resolved_source_root)
        chunks = source_index.chunks
        if vector_backend == "memory" and len(chunks) > MAX_MEMORY_VECTOR_CHUNKS:
            raise EmbeddingError(
                "memory vector backend is limited to "
                f"{MAX_MEMORY_VECTOR_CHUNKS} chunks; use Chroma for this index"
            )
        index = self.repository.replace_index(
            project_id=project_id,
            artifact_id=canonical_artifact_id,
            source_root=resolved_source_root,
            chunks=chunks,
            metadata={"embedding_provider": embedding_provider},
        )
        summaries = build_hierarchical_summaries(index, chunks)
        self.repository.save_summaries(summaries)
        provider = _embedding_provider(embedding_provider)
        documents = tuple(_document(chunk) for chunk in chunks)
        if vector_backend == "chroma":
            vectors = ChromaVectorIndex(
                self.vector_root,
                index.id,
                provider,
                source_fingerprint=index.source_fingerprint,
                store_documents=False,
            )
            vectors.rebuild(documents)
            collection_name = vectors.collection_name
        else:
            memory = MemoryVectorIndex(provider)
            memory.rebuild(documents)
            collection_name = memory_collection_name(
                index.id, index.source_fingerprint, provider.name
            )
        self.repository.save_vector_metadata(
            VectorIndexMetadata(
                index_id=index.id,
                backend=vector_backend,
                collection_name=collection_name,
                embedding_provider=provider.name,
                dimensions=provider.dimensions,
                document_count=len(documents),
            )
        )
        return ContextBuildResult(
            index=index,
            source_file_count=source_index.indexed_file_count,
            skipped_source_file_count=source_index.skipped_file_count,
            oversized_fallback_source_file_count=(
                source_index.oversized_fallback_file_count
            ),
            source_index_warning_count=source_index.warning_count,
            source_index_warnings=source_index.warnings,
            chunk_count=len(chunks),
            summary_count=len(summaries),
            vector_backend=vector_backend,
            embedding_provider=provider.name,
        )

    def query(
        self,
        *,
        project_id: str,
        query: str,
        token_budget: int,
        limit: int = 20,
        vector_backend: Literal["chroma", "memory"] = "chroma",
        embedding_provider: Literal["hashing", "ollama"] = "hashing",
        known_paths: tuple[str, ...] = (),
    ) -> ContextQueryResult:
        normalized_query = query.strip()
        if not normalized_query:
            raise ValueError("query cannot be blank")
        if limit < 1 or limit > 1_000:
            raise ValueError("limit must be between 1 and 1000")
        index = self.repository.latest_index(project_id)
        provider = _embedding_provider(embedding_provider)
        expected_collection = _expected_collection_name(
            vector_backend=vector_backend,
            index=index,
            embedding_provider=provider.name,
        )
        metadata = self.repository.get_vector_metadata(index.id)
        _require_ready_vector_metadata(
            metadata,
            vector_backend=vector_backend,
            embedding_provider=provider.name,
            collection_name=expected_collection,
            document_count=index.chunk_count,
        )
        if vector_backend == "chroma":
            chroma_vectors = ChromaVectorIndex(
                self.vector_root,
                index.id,
                provider,
                source_fingerprint=index.source_fingerprint,
                store_documents=False,
            )
            physical_count = chroma_vectors.count()
            if physical_count != index.chunk_count:
                raise EmbeddingError(
                    "vector index is not ready: Chroma collection contains "
                    f"{physical_count} of {index.chunk_count} documents"
                )
            semantic_limit = min(
                index.chunk_count,
                max(
                    limit,
                    min(
                        MAX_SEMANTIC_CANDIDATES,
                        max(
                            MIN_SEMANTIC_CANDIDATES,
                            limit * SEMANTIC_CANDIDATE_MULTIPLIER,
                        ),
                    ),
                ),
            )
            semantic_matches = (
                chroma_vectors.query(normalized_query, limit=semantic_limit)
                if semantic_limit
                else []
            )
            semantic = {match.id: match.score for match in semantic_matches}
            chunks_by_id = {
                chunk.id: chunk
                for chunk in self.repository.get_chunks_by_ids(
                    index.id, semantic.keys()
                )
            }
            if known_paths:
                known_path_chunks = self.repository.list_chunks_by_path_prefixes(
                    index.id,
                    known_paths,
                    limit=MAX_KNOWN_PATH_CANDIDATES,
                )
                chunks_by_id.update((chunk.id, chunk) for chunk in known_path_chunks)
            chunks = tuple(chunks_by_id.values())
        else:
            if index.chunk_count > MAX_MEMORY_VECTOR_CHUNKS:
                raise EmbeddingError(
                    "memory vector backend is limited to "
                    f"{MAX_MEMORY_VECTOR_CHUNKS} chunks; use Chroma for this index"
                )
            chunks = self.repository.list_chunks(index.id)
            if len(chunks) != index.chunk_count:
                raise EmbeddingError(
                    "vector index is not ready: persisted chunk count does not match "
                    "the context index"
                )
            documents = tuple(_document(chunk) for chunk in chunks)
            memory_vectors = MemoryVectorIndex(provider)
            memory_vectors.rebuild(documents)
            semantic_matches = memory_vectors.query(normalized_query, limit=limit)
            semantic = {match.id: match.score for match in semantic_matches}
        query_tokens = {
            token.lower() for token in QUERY_TOKEN.findall(normalized_query)
        }
        summary_by_scope = {
            summary.scope: summary.content
            for summary in self.repository.list_method_summaries_by_chunk_ids(
                index.id, (chunk.id for chunk in chunks)
            )
            if summary.source_fingerprint == index.source_fingerprint
        }
        scored: list[tuple[SourceChunk, HybridMatch, str | None]] = []
        for chunk in chunks:
            lexical = _lexical_score(chunk, query_tokens, normalized_query)
            semantic_score = semantic.get(chunk.id, 0.0)
            location_boost = (
                1.0 if any(chunk.path.startswith(path) for path in known_paths) else 0.0
            )
            score = min(
                1.0, lexical * 0.5 + semantic_score * 0.45 + location_boost * 0.05
            )
            if score == 0:
                continue
            summary = summary_by_scope.get(chunk.id)
            scored.append(
                (
                    chunk,
                    HybridMatch(
                        chunk_id=chunk.id,
                        path=chunk.path,
                        symbol=chunk.symbol,
                        start_line=chunk.start_line,
                        end_line=chunk.end_line,
                        lexical_score=round(lexical, 6),
                        semantic_score=round(semantic_score, 6),
                        location_boost=location_boost,
                        score=round(score, 6),
                    ),
                    summary,
                )
            )
        scored.sort(
            key=lambda item: (
                -item[1].score,
                item[0].path,
                item[0].start_line,
                item[0].id,
            )
        )
        selected = scored[:limit]
        packed = pack_context(
            (
                RankedChunk(chunk=chunk, score=match.score, summary=summary)
                for chunk, match, summary in selected
            ),
            token_budget=token_budget,
            allow_summary_fallback=True,
        )
        return ContextQueryResult(
            index_id=index.id,
            query=normalized_query,
            matches=tuple(match for _, match, _ in selected),
            packed_context=packed,
        )


def _embedding_provider(
    name: str,
) -> HashingEmbeddingProvider | OllamaEmbeddingProvider:
    if name == "hashing":
        return HashingEmbeddingProvider()
    if name == "ollama":
        return OllamaEmbeddingProvider()
    raise ValueError(f"unsupported embedding provider: {name}")


def _expected_collection_name(
    *,
    vector_backend: str,
    index: ContextIndex,
    embedding_provider: str,
) -> str:
    if vector_backend == "chroma":
        return chroma_collection_name(
            index.id,
            index.source_fingerprint,
            embedding_provider,
            store_documents=False,
        )
    return memory_collection_name(
        index.id, index.source_fingerprint, embedding_provider
    )


def _require_ready_vector_metadata(
    metadata: VectorIndexMetadata | None,
    *,
    vector_backend: str,
    embedding_provider: str,
    collection_name: str,
    document_count: int,
) -> None:
    if metadata is None:
        raise EmbeddingError(
            "vector index is not ready: no completed build is published"
        )
    mismatches: list[str] = []
    if metadata.backend != vector_backend:
        mismatches.append("backend")
    if metadata.embedding_provider != embedding_provider:
        mismatches.append("embedding provider")
    if metadata.collection_name != collection_name:
        mismatches.append("collection identity")
    if metadata.document_count != document_count:
        mismatches.append("document count")
    if mismatches:
        raise EmbeddingError(
            "vector index is not ready: published metadata does not match "
            + ", ".join(mismatches)
        )


def _require_project_source_root(
    source_root: Path, *, data_dir: Path, project_id: str
) -> Path:
    projects_root = (data_dir / "projects").resolve()
    project_root = (projects_root / project_id).resolve()
    try:
        project_root.relative_to(projects_root)
    except ValueError as exc:
        raise ContextIsolationError("project area escapes the data directory") from exc

    try:
        resolved_source_root = source_root.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ContextIsolationError(
            f"source root cannot be resolved: {source_root}"
        ) from exc
    if not resolved_source_root.is_dir():
        raise ContextIsolationError(
            f"source root is not a directory: {resolved_source_root}"
        )
    try:
        resolved_source_root.relative_to(project_root)
    except ValueError as exc:
        raise ContextIsolationError(
            f"source root must be inside the project area: {project_root}"
        ) from exc
    return resolved_source_root


def _document(chunk: SourceChunk) -> SemanticDocument:
    metadata: dict[str, str | int | float | bool] = {
        "path": chunk.path,
        "language": chunk.language.value,
        "kind": chunk.kind.value,
        "start_line": chunk.start_line,
        "end_line": chunk.end_line,
    }
    if chunk.symbol:
        metadata["symbol"] = chunk.symbol
    return SemanticDocument(id=chunk.id, text=chunk.content, metadata=metadata)


def _lexical_score(chunk: SourceChunk, query_tokens: set[str], raw_query: str) -> float:
    lowered = chunk.content.lower()
    symbol_path = f"{chunk.path} {chunk.symbol or ''}".lower()
    if raw_query.lower() in lowered or raw_query.lower() in symbol_path:
        phrase = 0.45
    else:
        phrase = 0.0
    if not query_tokens:
        return phrase
    matched_content = sum(token in lowered for token in query_tokens) / len(
        query_tokens
    )
    matched_location = sum(token in symbol_path for token in query_tokens) / len(
        query_tokens
    )
    return min(1.0, phrase + matched_content * 0.4 + matched_location * 0.15)
