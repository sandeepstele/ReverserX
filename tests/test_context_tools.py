from pathlib import Path

import pytest

from reverserx.context.chunking import ChunkKind, SourceChunk, SourceLanguage
from reverserx.core.models import Artifact, Project
from reverserx.storage import Database
from reverserx.storage.context import ContextRepository
from reverserx.tools.base import ToolContext
from reverserx.tools.static.context import (
    ContextToolError,
    SourceIndexInput,
    SourceIndexTool,
    SourceSearchInput,
    SourceSearchTool,
    VectorBackend,
)


def _write_source(root: Path, name: str) -> None:
    root.mkdir(parents=True)
    (root / f"{name}.java").write_text(
        f"class {name} {{ void run() {{}} }}\n", encoding="utf-8"
    )


def test_source_index_tool_confines_roots_to_active_project(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    database = Database(data_dir / "reverserx.sqlite3")
    database.initialize()
    owner = database.create_project(Project(slug="owner", name="Owner"))
    other = database.create_project(Project(slug="other", name="Other"))
    shared_root = data_dir / "shared-sources"
    other_root = data_dir / "projects" / other.id / "sources"
    _write_source(shared_root, "Shared")
    _write_source(other_root, "Other")
    context = ToolContext(
        project_id=owner.id,
        data_dir=data_dir,
        database_path=database.path,
    )
    tool = SourceIndexTool()

    with pytest.raises(ContextToolError, match="inside the project area"):
        tool.execute(
            context,
            SourceIndexInput(
                source_root=shared_root,
                vector_backend=VectorBackend.MEMORY,
            ),
        )
    with pytest.raises(ContextToolError, match="inside the project area"):
        tool.execute(
            context,
            SourceIndexInput(
                source_root=other_root,
                vector_backend=VectorBackend.MEMORY,
            ),
        )


def test_source_index_tool_rejects_foreign_artifact_and_accepts_owned_one(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    database = Database(data_dir / "reverserx.sqlite3")
    database.initialize()
    owner = database.create_project(Project(slug="owner", name="Owner"))
    other = database.create_project(Project(slug="other", name="Other"))
    owned_artifact = database.save_artifact(
        Artifact(
            project_id=owner.id,
            sha256="a" * 64,
            original_name="owned.apk",
            size_bytes=10,
            stored_path="owner/owned",
        )
    )
    foreign_artifact = database.save_artifact(
        Artifact(
            project_id=other.id,
            sha256="b" * 64,
            original_name="foreign.apk",
            size_bytes=10,
            stored_path="other/foreign",
        )
    )
    source_root = data_dir / "projects" / owner.id / "sources"
    _write_source(source_root, "Owner")
    context = ToolContext(
        project_id=owner.id,
        data_dir=data_dir,
        database_path=database.path,
    )
    tool = SourceIndexTool()

    for unavailable_id in (foreign_artifact.id, "art_missing"):
        with pytest.raises(
            ContextToolError, match="not available to the active project"
        ):
            tool.execute(
                context,
                SourceIndexInput(
                    source_root=source_root,
                    artifact_id=unavailable_id,
                    vector_backend=VectorBackend.MEMORY,
                ),
            )

    execution = tool.execute(
        context,
        SourceIndexInput(
            source_root=source_root,
            artifact_id=owned_artifact.sha256,
            vector_backend=VectorBackend.MEMORY,
        ),
    )

    assert execution.output["index"]["project_id"] == owner.id
    assert execution.output["index"]["artifact_id"] == owned_artifact.id
    assert execution.output["source_file_count"] == 1


def test_source_search_tool_streams_persisted_chunks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "data"
    database = Database(data_dir / "reverserx.sqlite3")
    database.initialize()
    project = database.create_project(Project(slug="fixture", name="Fixture"))
    source_root = data_dir / "projects" / project.id / "sources"
    source_root.mkdir(parents=True)
    chunk = SourceChunk(
        language=SourceLanguage.JAVA,
        kind=ChunkKind.METHOD,
        path="src/Crypto.java",
        symbol="Crypto.encrypt",
        start_line=30,
        end_line=31,
        content="Cipher cipher\nreturn cipher;\n",
    )
    index = ContextRepository(database).replace_index(
        project_id=project.id,
        source_root=source_root,
        chunks=(chunk,),
    )

    def reject_materialized_chunks(
        _repository: ContextRepository,
        _index_id: str,
    ) -> tuple[SourceChunk, ...]:
        raise AssertionError("source_search must not materialize all chunks")

    monkeypatch.setattr(ContextRepository, "list_chunks", reject_materialized_chunks)
    execution = SourceSearchTool().execute(
        ToolContext(
            project_id=project.id,
            data_dir=data_dir,
            database_path=database.path,
        ),
        SourceSearchInput(query="cipher", context_lines=0),
    )

    assert execution.output["index_id"] == index.id
    assert execution.output["hits"] == [
        {
            "schema_version": "1.1",
            "chunk_id": chunk.id,
            "language": "java",
            "kind": "method",
            "path": "src/Crypto.java",
            "symbol": "Crypto.encrypt",
            "start_line": 30,
            "end_line": 31,
            "start_instruction": None,
            "end_instruction": None,
            "match_count": 3,
            "distinct_match_line_count": 2,
            "match_lines": [30, 31],
            "match_lines_truncated": False,
            "excerpt": "Cipher cipher\n",
            "excerpt_start_line": 30,
            "excerpt_end_line": 30,
        }
    ]
