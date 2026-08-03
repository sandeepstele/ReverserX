from collections.abc import Iterable, Sequence
from pathlib import Path

import pytest

import reverserx.context.service as context_service_module
from reverserx.context.chunking import ChunkKind, SourceChunk, SourceLanguage
from reverserx.context.embedding import (
    ChromaVectorIndex,
    EmbeddingError,
    HashingEmbeddingProvider,
    SemanticDocument,
    memory_collection_name,
)
from reverserx.context.service import (
    MAX_KNOWN_PATH_CANDIDATES,
    MAX_SEMANTIC_CANDIDATES,
    ContextService,
)
from reverserx.core.models import Project
from reverserx.storage import Database
from reverserx.storage.context import (
    ContextRepository,
    ContextSummary,
    VectorIndexMetadata,
)


def _database_and_project(tmp_path: Path) -> tuple[Database, Project, Path]:
    database = Database(tmp_path / "state.sqlite3")
    database.initialize()
    project = database.create_project(Project(slug="fixture", name="Fixture"))
    source_root = tmp_path / "projects" / project.id / "sources"
    source_root.mkdir(parents=True)
    return database, project, source_root


def _chunk(content: str) -> SourceChunk:
    return SourceChunk(
        language=SourceLanguage.JAVA,
        kind=ChunkKind.METHOD,
        path="fixture/Crypto.java",
        symbol="Crypto.seal",
        start_line=1,
        end_line=1,
        content=content,
    )


def test_source_replacement_preserves_last_vector_metadata_until_publish(
    tmp_path: Path,
) -> None:
    database, project, source_root = _database_and_project(tmp_path)
    repository = ContextRepository(database)
    original = repository.replace_index(
        project_id=project.id,
        source_root=source_root,
        chunks=(_chunk("void seal() { oldCipher(); }"),),
    )
    published = VectorIndexMetadata(
        index_id=original.id,
        backend="memory",
        collection_name=memory_collection_name(
            original.id, original.source_fingerprint, "local-hashing-v1"
        ),
        embedding_provider="local-hashing-v1",
        dimensions=384,
        document_count=1,
    )
    repository.save_vector_metadata(published)

    replaced = repository.replace_index(
        project_id=project.id,
        source_root=source_root,
        chunks=(_chunk("void seal() { newCipher(); }"),),
    )

    assert replaced.id == original.id
    assert replaced.source_fingerprint != original.source_fingerprint
    assert repository.get_vector_metadata(replaced.id) == published
    with pytest.raises(EmbeddingError, match="collection identity"):
        ContextService(repository, tmp_path / "vectors").query(
            project_id=project.id,
            query="cipher",
            token_budget=1_000,
            vector_backend="memory",
        )


def test_changed_fingerprint_builds_beside_last_complete_chroma_collection(
    tmp_path: Path,
) -> None:
    database, project, source_root = _database_and_project(tmp_path)
    source = source_root / "Crypto.java"
    source.write_text("class Crypto { void seal() { oldCipher(); } }", encoding="utf-8")
    repository = ContextRepository(database)
    vector_root = tmp_path / "vectors"
    service = ContextService(repository, vector_root)
    first = service.build(
        project_id=project.id,
        source_root=source_root,
        vector_backend="chroma",
    )
    first_metadata = repository.get_vector_metadata(first.index.id)
    assert first_metadata is not None
    first_vectors = ChromaVectorIndex(
        vector_root,
        first.index.id,
        HashingEmbeddingProvider(),
        source_fingerprint=first.index.source_fingerprint,
        store_documents=False,
    )

    source.write_text("class Crypto { void seal() { newCipher(); } }", encoding="utf-8")
    second = service.build(
        project_id=project.id,
        source_root=source_root,
        vector_backend="chroma",
    )
    second_metadata = repository.get_vector_metadata(second.index.id)

    assert second.index.id == first.index.id
    assert second.index.source_fingerprint != first.index.source_fingerprint
    assert second_metadata is not None
    assert second_metadata.collection_name != first_metadata.collection_name
    assert first_vectors.count() == first.chunk_count
    assert service.query(
        project_id=project.id,
        query="new cipher",
        token_budget=1_000,
        vector_backend="chroma",
    ).matches


def test_context_query_rejects_physically_partial_chroma_collection(
    tmp_path: Path,
) -> None:
    database, project, source_root = _database_and_project(tmp_path)
    (source_root / "Crypto.java").write_text(
        "class Crypto { void seal() { Cipher.doFinal(); } }", encoding="utf-8"
    )
    (source_root / "Network.java").write_text(
        "class Network { void send() { client.execute(); } }", encoding="utf-8"
    )
    repository = ContextRepository(database)
    vector_root = tmp_path / "vectors"
    service = ContextService(repository, vector_root)
    built = service.build(
        project_id=project.id,
        source_root=source_root,
        vector_backend="chroma",
    )
    chunks = repository.list_chunks(built.index.id)
    assert len(chunks) > 1
    partial = ChromaVectorIndex(
        vector_root,
        built.index.id,
        HashingEmbeddingProvider(),
        source_fingerprint=built.index.source_fingerprint,
        store_documents=False,
    )
    partial.rebuild(
        (
            SemanticDocument(
                id=chunks[0].id,
                text=chunks[0].content,
                metadata={"path": chunks[0].path},
            ),
        )
    )

    with pytest.raises(EmbeddingError, match="contains 1 of"):
        service.query(
            project_id=project.id,
            query="Cipher",
            token_budget=1_000,
            vector_backend="chroma",
        )


def test_chroma_query_uses_only_bounded_candidate_repository_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, project, source_root = _database_and_project(tmp_path)
    for number in range(12):
        relative = Path("known" if number < 6 else "other") / f"Type{number}.java"
        path = source_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"class Type{number} {{ void run() {{ token{number}(); }} }}",
            encoding="utf-8",
        )
    repository = ContextRepository(database)
    service = ContextService(repository, tmp_path / "vectors")
    service.build(
        project_id=project.id,
        source_root=source_root,
        vector_backend="chroma",
    )
    observed: dict[str, int] = {}
    original_get_chunks = repository.get_chunks_by_ids
    original_path_chunks = repository.list_chunks_by_path_prefixes
    original_summaries = repository.list_method_summaries_by_chunk_ids

    def reject_full_read(_index_id: str) -> tuple[SourceChunk, ...]:
        raise AssertionError("Chroma query must not materialize the complete index")

    def reject_full_summary_read(_index_id: str) -> tuple[ContextSummary, ...]:
        raise AssertionError("Chroma query must not materialize every summary")

    def bounded_chunks(
        index_id: str, chunk_ids: Iterable[str]
    ) -> tuple[SourceChunk, ...]:
        ids = tuple(chunk_ids)
        observed["semantic_ids"] = len(ids)
        return original_get_chunks(index_id, ids)

    def bounded_paths(
        index_id: str, path_prefixes: Iterable[str], *, limit: int
    ) -> tuple[SourceChunk, ...]:
        observed["path_limit"] = limit
        return original_path_chunks(index_id, path_prefixes, limit=limit)

    def bounded_summaries(
        index_id: str, chunk_ids: Iterable[str]
    ) -> tuple[ContextSummary, ...]:
        ids = tuple(chunk_ids)
        observed["summary_ids"] = len(ids)
        return original_summaries(index_id, ids)

    monkeypatch.setattr(repository, "list_chunks", reject_full_read)
    monkeypatch.setattr(repository, "list_summaries", reject_full_summary_read)
    monkeypatch.setattr(repository, "get_chunks_by_ids", bounded_chunks)
    monkeypatch.setattr(repository, "list_chunks_by_path_prefixes", bounded_paths)
    monkeypatch.setattr(
        repository, "list_method_summaries_by_chunk_ids", bounded_summaries
    )
    monkeypatch.setattr(
        context_service_module,
        "_document",
        lambda _chunk: (_ for _ in ()).throw(
            AssertionError("Chroma query must not construct all semantic documents")
        ),
    )

    result = service.query(
        project_id=project.id,
        query="token3",
        token_budget=1_000,
        limit=2,
        vector_backend="chroma",
        known_paths=("known/",),
    )

    assert result.matches
    assert observed["semantic_ids"] <= MAX_SEMANTIC_CANDIDATES
    assert observed["path_limit"] == MAX_KNOWN_PATH_CANDIDATES
    assert observed["summary_ids"] <= (
        MAX_SEMANTIC_CANDIDATES + MAX_KNOWN_PATH_CANDIDATES
    )


def test_memory_backend_rejects_build_and_query_above_explicit_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, project, source_root = _database_and_project(tmp_path)
    (source_root / "Crypto.java").write_text(
        "class Crypto { void seal() { Cipher.doFinal(); } }", encoding="utf-8"
    )
    (source_root / "Network.java").write_text(
        "class Network { void send() { client.execute(); } }", encoding="utf-8"
    )
    repository = ContextRepository(database)
    service = ContextService(repository, tmp_path / "vectors")
    built = service.build(
        project_id=project.id,
        source_root=source_root,
        vector_backend="memory",
    )
    assert built.chunk_count > 1
    monkeypatch.setattr(context_service_module, "MAX_MEMORY_VECTOR_CHUNKS", 1)

    with pytest.raises(EmbeddingError, match="limited to 1 chunks"):
        service.build(
            project_id=project.id,
            source_root=source_root,
            vector_backend="memory",
        )

    def reject_full_read(_index_id: str) -> tuple[SourceChunk, ...]:
        raise AssertionError("memory cap must be checked before materialization")

    monkeypatch.setattr(repository, "list_chunks", reject_full_read)
    with pytest.raises(EmbeddingError, match="limited to 1 chunks"):
        service.query(
            project_id=project.id,
            query="Cipher",
            token_budget=1_000,
            vector_backend="memory",
        )


class _CountingHashingProvider(HashingEmbeddingProvider):
    def __init__(self) -> None:
        super().__init__(dimensions=64)
        self.calls = 0

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        self.calls += 1
        return super().embed(texts)


def test_chroma_reuses_complete_deterministic_collection(tmp_path: Path) -> None:
    provider = _CountingHashingProvider()
    vectors = ChromaVectorIndex(
        tmp_path / "vectors",
        "idx_fixture",
        provider,
        source_fingerprint="a" * 64,
    )
    documents = (
        SemanticDocument(id="one", text="first", metadata={"path": "One.java"}),
        SemanticDocument(id="two", text="second", metadata={"path": "Two.java"}),
    )

    assert vectors.rebuild(documents) is True
    calls_after_build = provider.calls
    assert vectors.rebuild(documents) is False
    assert provider.calls == calls_after_build
