from collections.abc import Iterable
from pathlib import Path

import pytest

import reverserx.context.service as context_service_module
from reverserx.context.budget import PackedContext, RankedChunk, pack_context
from reverserx.context.chunking import (
    DEFAULT_MAX_SOURCE_BYTES,
    ChunkKind,
    SourceChunk,
    SourceLanguage,
)
from reverserx.context.embedding import memory_collection_name
from reverserx.context.service import ContextIsolationError, ContextService
from reverserx.core.models import Artifact, Project
from reverserx.storage import Database, NotFoundError
from reverserx.storage.context import (
    ContextRepository,
    ContextSummary,
    VectorIndexMetadata,
)


def test_context_service_builds_and_queries_hybrid_index(tmp_path: Path) -> None:
    database = Database(tmp_path / "reverserx.sqlite3")
    database.initialize()
    project = database.create_project(Project(slug="fixture", name="Fixture"))
    source = tmp_path / "projects" / project.id / "sources"
    source.mkdir(parents=True)
    (source / "EncryptionManager.java").write_text(
        """
        package com.example.crypto;
        public class EncryptionManager {
            public byte[] encryptRequest(byte[] payload) {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                return cipher.doFinal(payload);
            }
        }
        """,
        encoding="utf-8",
    )
    (source / "ProfileActivity.java").write_text(
        """
        package com.example.ui;
        public class ProfileActivity {
            public void renderAvatar() { imageView.setVisible(true); }
        }
        """,
        encoding="utf-8",
    )
    service = ContextService(ContextRepository(database), tmp_path / "vectors")

    built = service.build(
        project_id=project.id,
        source_root=source,
        vector_backend="memory",
    )
    result = service.query(
        project_id=project.id,
        query="AES request encryption Cipher",
        token_budget=1_000,
        vector_backend="memory",
    )

    assert built.source_file_count == 2
    assert built.chunk_count >= 4
    assert built.summary_count > built.source_file_count
    assert result.matches
    assert result.matches[0].path == "EncryptionManager.java"
    assert result.packed_context.used_tokens <= 1_000
    assert "EncryptionManager.java" in result.packed_context.text


def test_context_service_surfaces_oversized_fallback_stats(tmp_path: Path) -> None:
    database = Database(tmp_path / "reverserx.sqlite3")
    database.initialize()
    project = database.create_project(Project(slug="fixture", name="Fixture"))
    source = tmp_path / "projects" / project.id / "sources"
    source.mkdir(parents=True)
    line = f"// {'x' * 180}\n"
    line_count = DEFAULT_MAX_SOURCE_BYTES // len(line.encode("utf-8")) + 2
    oversized = source / "Huge.java"
    oversized.write_text(line * line_count, encoding="utf-8")
    repository = ContextRepository(database)

    built = ContextService(repository, tmp_path / "vectors").build(
        project_id=project.id,
        source_root=source,
        vector_backend="memory",
    )
    persisted = repository.list_chunks(built.index.id)

    assert oversized.stat().st_size > DEFAULT_MAX_SOURCE_BYTES
    assert built.source_file_count == 1
    assert built.skipped_source_file_count == 0
    assert built.oversized_fallback_source_file_count == 1
    assert built.source_index_warning_count == len(built.source_index_warnings) == 1
    assert built.source_index_warnings[0].path == "Huge.java"
    assert built.source_index_warnings[0].reason == "oversized_fallback"
    assert built.chunk_count == len(persisted) > 1
    assert all(chunk.path == "Huge.java" for chunk in persisted)
    assert all(chunk.kind is ChunkKind.FILE for chunk in persisted)


def test_context_service_looks_up_overload_summaries_by_chunk_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = Database(tmp_path / "reverserx.sqlite3")
    database.initialize()
    project = database.create_project(Project(slug="fixture", name="Fixture"))
    source = tmp_path / "projects" / project.id / "sources"
    source.mkdir(parents=True)
    repository = ContextRepository(database)
    overloads = (
        SourceChunk(
            language=SourceLanguage.JAVA,
            kind=ChunkKind.METHOD,
            path="com/example/Crypto.java",
            symbol="Crypto.encrypt",
            start_line=2,
            end_line=2,
            content="String encrypt(String data) { return data; }",
        ),
        SourceChunk(
            language=SourceLanguage.JAVA,
            kind=ChunkKind.METHOD,
            path="com/example/Crypto.java",
            symbol="Crypto.encrypt",
            start_line=6,
            end_line=6,
            content="byte[] encrypt(byte[] data) { return data; }",
        ),
    )
    index = repository.replace_index(
        project_id=project.id,
        source_root=source,
        chunks=overloads,
    )
    repository.save_summaries(
        tuple(
            ContextSummary(
                index_id=index.id,
                level="method",
                scope=chunk.id,
                source_fingerprint=index.source_fingerprint,
                content=summary,
            )
            for chunk, summary in zip(
                overloads,
                ("string overload summary", "byte-array overload summary"),
                strict=True,
            )
        )
    )
    repository.save_vector_metadata(
        VectorIndexMetadata(
            index_id=index.id,
            backend="memory",
            collection_name=memory_collection_name(
                index.id, index.source_fingerprint, "local-hashing-v1"
            ),
            embedding_provider="local-hashing-v1",
            dimensions=384,
            document_count=len(overloads),
        )
    )
    captured: dict[str, str | None] = {}

    def record_candidates(
        candidates: Iterable[RankedChunk],
        *,
        token_budget: int,
        allow_summary_fallback: bool = True,
        per_item_overhead_tokens: int = 0,
    ) -> PackedContext:
        ranked = tuple(candidates)
        captured.update({candidate.chunk.id: candidate.summary for candidate in ranked})
        return pack_context(
            (),
            token_budget=token_budget,
            allow_summary_fallback=allow_summary_fallback,
            per_item_overhead_tokens=per_item_overhead_tokens,
        )

    monkeypatch.setattr(context_service_module, "pack_context", record_candidates)

    result = ContextService(repository, tmp_path / "vectors").query(
        project_id=project.id,
        query="encrypt",
        token_budget=1_000,
        limit=20,
        vector_backend="memory",
        known_paths=("com/example/",),
    )

    assert {match.chunk_id for match in result.matches} == {
        chunk.id for chunk in overloads
    }
    assert captured == {
        overloads[0].id: "string overload summary",
        overloads[1].id: "byte-array overload summary",
    }


def test_context_service_rejects_source_root_outside_project_area(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "reverserx.sqlite3")
    database.initialize()
    project = database.create_project(Project(slug="fixture", name="Fixture"))
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "Source.java").write_text("class Source {}", encoding="utf-8")
    service = ContextService(ContextRepository(database), tmp_path / "vectors")

    with pytest.raises(ContextIsolationError, match="inside the project area"):
        service.build(
            project_id=project.id,
            source_root=outside,
            vector_backend="memory",
        )


def test_context_service_rejects_cross_project_artifact_and_root(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "reverserx.sqlite3")
    database.initialize()
    owner = database.create_project(Project(slug="owner", name="Owner"))
    other = database.create_project(Project(slug="other", name="Other"))
    foreign_artifact = database.save_artifact(
        Artifact(
            project_id=other.id,
            sha256="d" * 64,
            original_name="foreign.apk",
            size_bytes=10,
            stored_path="other/foreign",
        )
    )
    owner_root = tmp_path / "projects" / owner.id / "sources"
    other_root = tmp_path / "projects" / other.id / "sources"
    owner_root.mkdir(parents=True)
    other_root.mkdir(parents=True)
    (owner_root / "Owner.java").write_text("class Owner {}", encoding="utf-8")
    (other_root / "Other.java").write_text("class Other {}", encoding="utf-8")
    service = ContextService(ContextRepository(database), tmp_path / "vectors")

    with pytest.raises(NotFoundError, match="artifact not found"):
        service.build(
            project_id=owner.id,
            artifact_id=foreign_artifact.id,
            source_root=owner_root,
            vector_backend="memory",
        )
    with pytest.raises(ContextIsolationError, match="inside the project area"):
        service.build(
            project_id=owner.id,
            source_root=other_root,
            vector_backend="memory",
        )
