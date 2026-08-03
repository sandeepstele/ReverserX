from pathlib import Path

from reverserx.context.embedding import (
    ChromaVectorIndex,
    HashingEmbeddingProvider,
    SemanticDocument,
)
from reverserx.context.service import ContextService
from reverserx.core.models import Artifact, Project
from reverserx.storage import Database
from reverserx.storage.context import ContextRepository


def test_chroma_index_rebuilds_persists_and_queries(tmp_path: Path) -> None:
    documents = (
        SemanticDocument(
            id="crypto",
            text="EncryptionManager encryptRequest AES GCM Cipher",
            metadata={"path": "crypto/EncryptionManager.java"},
        ),
        SemanticDocument(
            id="profile",
            text="ProfileActivity avatar image layout",
            metadata={"path": "ui/ProfileActivity.java"},
        ),
    )
    provider = HashingEmbeddingProvider(dimensions=64)
    index = ChromaVectorIndex(tmp_path / "vectors", "fixture-index", provider)

    index.rebuild(documents)
    first = index.query("AES request cipher", limit=2)
    reopened = ChromaVectorIndex(
        tmp_path / "vectors", "fixture-index", HashingEmbeddingProvider(64)
    )
    second = reopened.query("AES request cipher", limit=2)

    assert [match.id for match in first] == ["crypto", "profile"]
    assert [match.model_dump() for match in second] == [
        match.model_dump() for match in first
    ]
    assert first[0].score > first[1].score


def test_context_service_reindex_does_not_duplicate_chroma_records(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "reverserx.sqlite3")
    database.initialize()
    project = database.create_project(Project(slug="fixture", name="Fixture"))
    source = tmp_path / "projects" / project.id / "sources"
    source.mkdir(parents=True)
    (source / "Crypto.java").write_text(
        "public class Crypto { void seal() { Cipher.doFinal(); } }",
        encoding="utf-8",
    )
    repository = ContextRepository(database)
    service = ContextService(repository, tmp_path / "vectors")

    first = service.build(
        project_id=project.id, source_root=source, vector_backend="chroma"
    )
    second = service.build(
        project_id=project.id, source_root=source, vector_backend="chroma"
    )
    result = service.query(
        project_id=project.id,
        query="Cipher doFinal",
        token_budget=1_000,
        vector_backend="chroma",
    )

    assert second.index.id == first.index.id
    assert second.chunk_count == first.chunk_count
    assert len(repository.list_chunks(first.index.id)) == first.chunk_count
    assert result.matches[0].path == "Crypto.java"


def test_same_source_root_different_artifacts_use_distinct_chroma_collections(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "reverserx.sqlite3")
    database.initialize()
    project = database.create_project(Project(slug="fixture", name="Fixture"))
    first_artifact = database.save_artifact(
        Artifact(
            project_id=project.id,
            sha256="a" * 64,
            original_name="first.apk",
            size_bytes=10,
            stored_path="fixture/first",
        )
    )
    second_artifact = database.save_artifact(
        Artifact(
            project_id=project.id,
            sha256="b" * 64,
            original_name="second.apk",
            size_bytes=10,
            stored_path="fixture/second",
        )
    )
    source = tmp_path / "projects" / project.id / "sources"
    source.mkdir(parents=True)
    (source / "Crypto.java").write_text(
        "public class Crypto { void seal() { Cipher.doFinal(); } }",
        encoding="utf-8",
    )
    vector_root = tmp_path / "vectors"
    repository = ContextRepository(database)
    service = ContextService(repository, vector_root)

    first = service.build(
        project_id=project.id,
        artifact_id=first_artifact.id,
        source_root=source,
        vector_backend="chroma",
    )
    second = service.build(
        project_id=project.id,
        artifact_id=second_artifact.id,
        source_root=source,
        vector_backend="chroma",
    )
    provider = HashingEmbeddingProvider()
    first_vectors = ChromaVectorIndex(
        vector_root,
        first.index.id,
        provider,
        source_fingerprint=first.index.source_fingerprint,
        store_documents=False,
    )
    second_vectors = ChromaVectorIndex(
        vector_root,
        second.index.id,
        provider,
        source_fingerprint=second.index.source_fingerprint,
        store_documents=False,
    )

    assert first.index.id != second.index.id
    assert first_vectors.collection_name != second_vectors.collection_name
    assert first_vectors.query("Cipher doFinal", limit=1)[0].id
    assert second_vectors.query("Cipher doFinal", limit=1)[0].id
