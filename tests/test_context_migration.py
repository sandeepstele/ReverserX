from pathlib import Path

from reverserx.context.chunking import ChunkKind, SourceChunk, SourceLanguage
from reverserx.context.summarize import build_hierarchical_summaries
from reverserx.core.models import Artifact, Project
from reverserx.storage.context import ContextRepository, VectorIndexMetadata
from reverserx.storage.database import MIGRATIONS, Database


def _initialize_through_v2(database: Database) -> None:
    with database.connect() as connection:
        connection.execute(
            """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        for version, sql in MIGRATIONS:
            if version > 2:
                break
            connection.executescript(sql)
            connection.execute(
                "INSERT INTO schema_migrations(version) VALUES (?)", (version,)
            )


def _migration_chunks() -> tuple[SourceChunk, ...]:
    return (
        SourceChunk(
            language=SourceLanguage.JAVA,
            kind=ChunkKind.METHOD,
            path="fixture/Crypto.java",
            symbol="Crypto.encrypt",
            start_line=1,
            end_line=1,
            content="byte[] encrypt(byte[] value) { return value; }\n",
        ),
    )


def test_v3_migration_preserves_context_children_and_allows_shared_chunks(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "reverserx.sqlite3")
    _initialize_through_v2(database)
    assert database.schema_version() == 2
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
    source_root = tmp_path / "sources"
    source_root.mkdir()
    chunks = _migration_chunks()
    repository = ContextRepository(database)
    original = repository.replace_index(
        project_id=project.id,
        artifact_id=first_artifact.id,
        source_root=source_root,
        chunks=chunks,
    )
    summaries = build_hierarchical_summaries(original, chunks)
    repository.save_summaries(summaries)
    repository.save_vector_metadata(
        VectorIndexMetadata(
            index_id=original.id,
            backend="memory",
            collection_name=f"memory:{original.id}",
            embedding_provider="local-hashing-v1",
            dimensions=384,
            document_count=1,
        )
    )

    database.initialize()

    assert database.schema_version() == 3
    assert repository.get_index(original.id) == original
    assert repository.list_chunks(original.id) == chunks
    assert {
        summary.id: summary for summary in repository.list_summaries(original.id)
    } == {summary.id: summary for summary in summaries}
    with database.connect() as connection:
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        vector_count = connection.execute(
            "SELECT COUNT(*) AS count FROM vector_indexes WHERE index_id = ?",
            (original.id,),
        ).fetchone()["count"]
    assert vector_count == 1

    reindexed_original = repository.replace_index(
        project_id=project.id,
        artifact_id=first_artifact.id,
        source_root=source_root,
        chunks=chunks,
    )
    second = repository.replace_index(
        project_id=project.id,
        artifact_id=second_artifact.id,
        source_root=source_root,
        chunks=chunks,
    )

    assert reindexed_original.id == original.id
    assert second.id != original.id
    assert repository.get_index(original.id).artifact_id == first_artifact.id
    assert repository.get_index(second.id).artifact_id == second_artifact.id
    assert repository.list_chunks(original.id) == chunks
    assert repository.list_chunks(second.id) == chunks
    with database.connect() as connection:
        shared_chunk_rows = connection.execute(
            "SELECT COUNT(*) AS count FROM source_chunks WHERE id = ?",
            (chunks[0].id,),
        ).fetchone()["count"]
    assert shared_chunk_rows == 2

    with database.connect() as connection:
        connection.execute("DELETE FROM projects WHERE id = ?", (project.id,))
        remaining_indexes = connection.execute(
            "SELECT COUNT(*) AS count FROM analysis_indexes"
        ).fetchone()["count"]
        remaining_chunks = connection.execute(
            "SELECT COUNT(*) AS count FROM source_chunks"
        ).fetchone()["count"]
        remaining_vectors = connection.execute(
            "SELECT COUNT(*) AS count FROM vector_indexes"
        ).fetchone()["count"]
        remaining_summaries = connection.execute(
            "SELECT COUNT(*) AS count FROM context_summaries"
        ).fetchone()["count"]
    assert (
        remaining_indexes,
        remaining_chunks,
        remaining_vectors,
        remaining_summaries,
    ) == (0, 0, 0, 0)
