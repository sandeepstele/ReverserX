import sqlite3
from pathlib import Path

import pytest

import reverserx.storage.context as context_storage
from reverserx.context.chunking import ChunkKind, SourceChunk, SourceLanguage
from reverserx.context.summarize import build_hierarchical_summaries
from reverserx.core.models import Artifact, Project
from reverserx.storage import Database, NotFoundError
from reverserx.storage.context import ContextRepository


def _chunks() -> tuple[SourceChunk, ...]:
    return (
        SourceChunk(
            language=SourceLanguage.JAVA,
            kind=ChunkKind.TYPE,
            path="com/example/Crypto.java",
            symbol="Crypto",
            start_line=1,
            end_line=5,
            content="class Crypto {\n  byte[] encrypt(byte[] data) { return data; }\n}\n",
        ),
        SourceChunk(
            language=SourceLanguage.JAVA,
            kind=ChunkKind.METHOD,
            path="com/example/Crypto.java",
            symbol="Crypto.encrypt",
            start_line=2,
            end_line=2,
            content="byte[] encrypt(byte[] data) { return data; }",
        ),
    )


def test_context_index_round_trip_and_replacement(tmp_path: Path) -> None:
    database = Database(tmp_path / "reverserx.sqlite3")
    database.initialize()
    project = database.create_project(Project(slug="fixture", name="Fixture"))
    artifact = database.save_artifact(
        Artifact(
            project_id=project.id,
            sha256="a" * 64,
            original_name="base.apk",
            size_bytes=10,
            stored_path="fixture/blob",
        )
    )
    repository = ContextRepository(database)
    root = tmp_path / "sources"
    root.mkdir()

    first = repository.replace_index(
        project_id=project.id,
        artifact_id=artifact.id,
        source_root=root,
        chunks=_chunks(),
    )
    second = repository.replace_index(
        project_id=project.id,
        artifact_id=artifact.id,
        source_root=root,
        chunks=_chunks(),
    )

    assert first.id == second.id
    assert first.source_fingerprint == second.source_fingerprint
    assert second.chunker_version == "1.1.0"
    assert second.chunk_count == 2
    assert repository.latest_index(project.id).id == first.id
    assert repository.list_chunks(first.id) == _chunks()

    legacy = repository.replace_index(
        project_id=project.id,
        artifact_id=artifact.id,
        source_root=root,
        chunks=_chunks(),
        chunker_version="1.0.0",
    )
    assert legacy.id == second.id
    assert legacy.source_fingerprint != second.source_fingerprint


def test_context_chunks_are_converted_lazily_while_iterating(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = Database(tmp_path / "reverserx.sqlite3")
    database.initialize()
    project = database.create_project(Project(slug="fixture", name="Fixture"))
    repository = ContextRepository(database)
    root = tmp_path / "sources"
    root.mkdir()
    chunks = _chunks()
    index = repository.replace_index(
        project_id=project.id,
        source_root=root,
        chunks=chunks,
    )
    converted_ids: list[str] = []
    original_converter = context_storage._chunk_from_row

    def track_conversion(row: sqlite3.Row) -> SourceChunk:
        converted_ids.append(str(row["id"]))
        return original_converter(row)

    monkeypatch.setattr(context_storage, "_chunk_from_row", track_conversion)

    stream = repository.iter_chunks(index.id, batch_size=1)

    assert converted_ids == []
    assert next(stream) == chunks[0]
    assert converted_ids == [chunks[0].id]
    assert tuple(stream) == chunks[1:]
    assert converted_ids == [chunk.id for chunk in chunks]

    with pytest.raises(ValueError, match="batch_size"):
        next(repository.iter_chunks(index.id, batch_size=0))


def test_hierarchical_summaries_are_deterministic_and_persisted(tmp_path: Path) -> None:
    database = Database(tmp_path / "reverserx.sqlite3")
    database.initialize()
    project = database.create_project(Project(slug="fixture", name="Fixture"))
    repository = ContextRepository(database)
    root = tmp_path / "sources"
    root.mkdir()
    index = repository.replace_index(
        project_id=project.id,
        source_root=root,
        chunks=_chunks(),
    )

    summaries = build_hierarchical_summaries(index, _chunks())
    repository.save_summaries(summaries)
    saved = repository.list_summaries(index.id)

    assert {summary.id: summary for summary in saved} == {
        summary.id: summary for summary in summaries
    }
    assert {summary.level for summary in saved} == {
        "method",
        "class",
        "package",
        "project",
    }
    assert all(
        summary.source_fingerprint == index.source_fingerprint for summary in saved
    )


def test_overloaded_method_summaries_use_distinct_chunk_id_scopes(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "reverserx.sqlite3")
    database.initialize()
    project = database.create_project(Project(slug="fixture", name="Fixture"))
    repository = ContextRepository(database)
    root = tmp_path / "sources"
    root.mkdir()
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
        source_root=root,
        chunks=overloads,
    )

    summaries = build_hierarchical_summaries(index, overloads)
    method_summaries = tuple(
        summary for summary in summaries if summary.level == "method"
    )
    repository.save_summaries(summaries)
    saved_method_summaries = tuple(
        summary
        for summary in repository.list_summaries(index.id)
        if summary.level == "method"
    )

    assert {summary.scope for summary in method_summaries} == {
        chunk.id for chunk in overloads
    }
    assert len({summary.id for summary in method_summaries}) == 2
    assert {summary.scope for summary in saved_method_summaries} == {
        chunk.id for chunk in overloads
    }


def test_index_identity_separates_artifacts_at_the_same_source_root(
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
    root = tmp_path / "sources"
    root.mkdir()
    alternate_root = tmp_path / "alternate-sources"
    alternate_root.mkdir()
    repository = ContextRepository(database)

    first = repository.replace_index(
        project_id=project.id,
        artifact_id=first_artifact.id,
        source_root=root,
        chunks=_chunks(),
    )
    second = repository.replace_index(
        project_id=project.id,
        artifact_id=second_artifact.id,
        source_root=root,
        chunks=_chunks(),
    )
    without_artifact = repository.replace_index(
        project_id=project.id,
        source_root=root,
        chunks=_chunks(),
    )
    repeated_without_artifact = repository.replace_index(
        project_id=project.id,
        source_root=root,
        chunks=_chunks(),
    )
    same_artifact_alternate_root = repository.replace_index(
        project_id=project.id,
        artifact_id=first_artifact.id,
        source_root=alternate_root,
        chunks=_chunks(),
    )

    assert len({first.id, second.id, without_artifact.id}) == 3
    assert repeated_without_artifact.id == without_artifact.id
    assert same_artifact_alternate_root.id != first.id
    assert repository.get_index(first.id).artifact_id == first_artifact.id
    assert repository.get_index(second.id).artifact_id == second_artifact.id
    assert repository.get_index(without_artifact.id).artifact_id is None
    assert repository.list_chunks(first.id) == _chunks()
    assert repository.list_chunks(second.id) == _chunks()


def test_context_repository_rejects_foreign_or_missing_artifact(tmp_path: Path) -> None:
    database = Database(tmp_path / "reverserx.sqlite3")
    database.initialize()
    owner = database.create_project(Project(slug="owner", name="Owner"))
    other = database.create_project(Project(slug="other", name="Other"))
    foreign_artifact = database.save_artifact(
        Artifact(
            project_id=other.id,
            sha256="c" * 64,
            original_name="foreign.apk",
            size_bytes=10,
            stored_path="other/foreign",
        )
    )
    root = tmp_path / "sources"
    root.mkdir()
    repository = ContextRepository(database)

    with pytest.raises(NotFoundError, match="artifact not found"):
        repository.replace_index(
            project_id=owner.id,
            artifact_id=foreign_artifact.id,
            source_root=root,
            chunks=_chunks(),
        )
    with pytest.raises(NotFoundError, match="artifact not found"):
        repository.replace_index(
            project_id=owner.id,
            artifact_id="art_missing",
            source_root=root,
            chunks=_chunks(),
        )
