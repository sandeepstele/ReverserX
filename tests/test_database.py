from pathlib import Path

import pytest

from reverserx.core.models import (
    AnalysisSession,
    Artifact,
    Project,
    ToolRun,
    ToolRunStatus,
)
from reverserx.storage import ConflictError, Database


def test_database_migrations_are_repeatable(tmp_path: Path) -> None:
    database = Database(tmp_path / "state" / "reverserx.sqlite3")

    database.initialize()
    database.initialize()

    assert database.schema_version() == 3


def test_project_session_artifact_and_tool_run_round_trip(tmp_path: Path) -> None:
    database = Database(tmp_path / "reverserx.sqlite3")
    database.initialize()
    project = database.create_project(Project(slug="demo", name="Demo"))
    session = database.create_session(
        AnalysisSession(project_id=project.id, goal="Locate request encryption")
    )
    artifact = database.save_artifact(
        Artifact(
            project_id=project.id,
            sha256="a" * 64,
            original_name="fixture.apk",
            size_bytes=123,
            stored_path=f"{project.id}/aa/{'a' * 64}/blob",
        )
    )
    duplicate = database.save_artifact(
        artifact.model_copy(update={"id": "art_duplicate"})
    )
    tool_run = database.record_tool_run(
        ToolRun(
            project_id=project.id,
            session_id=session.id,
            tool_name="echo",
            tool_version="1.0.0",
            status=ToolRunStatus.SUCCEEDED,
            input_data={"message": "hello"},
            output_data={"message": "hello"},
        )
    )

    assert database.get_project("demo") == project
    assert database.get_project(project.id) == project
    assert database.list_projects() == [project]
    assert duplicate.id == artifact.id
    assert database.find_artifact(project.id, artifact.sha256) == artifact
    assert database.list_tool_runs(project.id) == [tool_run]


def test_duplicate_project_slug_is_a_conflict(tmp_path: Path) -> None:
    database = Database(tmp_path / "reverserx.sqlite3")
    database.initialize()
    database.create_project(Project(slug="demo", name="First"))

    with pytest.raises(ConflictError, match="already exists"):
        database.create_project(Project(slug="demo", name="Second"))
