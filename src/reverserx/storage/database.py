"""SQLite persistence with explicit, forward-only schema migrations."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from reverserx.core.models import AnalysisSession, Artifact, Project, ToolRun


class NotFoundError(LookupError):
    """Raised when a requested persisted object does not exist."""


class ConflictError(ValueError):
    """Raised when a unique persisted object already exists."""


MIGRATIONS: tuple[tuple[int, str], ...] = (
    (
        1,
        """
        CREATE TABLE projects (
            id TEXT PRIMARY KEY,
            schema_version TEXT NOT NULL,
            slug TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            scope_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE sessions (
            id TEXT PRIMARY KEY,
            schema_version TEXT NOT NULL,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            goal TEXT NOT NULL,
            status TEXT NOT NULL,
            state_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE artifacts (
            id TEXT PRIMARY KEY,
            schema_version TEXT NOT NULL,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            sha256 TEXT NOT NULL,
            original_name TEXT NOT NULL,
            media_type TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            stored_path TEXT NOT NULL,
            imported_at TEXT NOT NULL,
            UNIQUE(project_id, sha256)
        );

        CREATE TABLE tool_runs (
            id TEXT PRIMARY KEY,
            schema_version TEXT NOT NULL,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            session_id TEXT REFERENCES sessions(id) ON DELETE SET NULL,
            tool_name TEXT NOT NULL,
            tool_version TEXT NOT NULL,
            status TEXT NOT NULL,
            input_json TEXT NOT NULL,
            output_json TEXT NOT NULL,
            error TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT
        );

        CREATE TABLE evidence (
            id TEXT PRIMARY KEY,
            schema_version TEXT NOT NULL,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            tool_run_id TEXT REFERENCES tool_runs(id) ON DELETE SET NULL,
            artifact_id TEXT REFERENCES artifacts(id) ON DELETE SET NULL,
            kind TEXT NOT NULL,
            locator TEXT NOT NULL,
            summary TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            observed_at TEXT NOT NULL
        );

        CREATE TABLE findings (
            id TEXT PRIMARY KEY,
            schema_version TEXT NOT NULL,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            evidence_ids_json TEXT NOT NULL,
            inference INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE plan_steps (
            id TEXT PRIMARY KEY,
            schema_version TEXT NOT NULL,
            session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            sequence INTEGER NOT NULL,
            objective TEXT NOT NULL,
            tool_name TEXT,
            arguments_json TEXT NOT NULL,
            status TEXT NOT NULL,
            depends_on_json TEXT NOT NULL,
            UNIQUE(session_id, sequence)
        );

        CREATE TABLE model_usage (
            id TEXT PRIMARY KEY,
            schema_version TEXT NOT NULL,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            session_id TEXT REFERENCES sessions(id) ON DELETE SET NULL,
            provider TEXT NOT NULL,
            model TEXT NOT NULL,
            task_type TEXT NOT NULL,
            input_tokens INTEGER NOT NULL,
            output_tokens INTEGER NOT NULL,
            estimated_cost_usd REAL NOT NULL,
            actual_cost_usd REAL,
            created_at TEXT NOT NULL
        );

        CREATE INDEX idx_sessions_project ON sessions(project_id);
        CREATE INDEX idx_artifacts_project ON artifacts(project_id);
        CREATE INDEX idx_tool_runs_project ON tool_runs(project_id);
        CREATE INDEX idx_evidence_project ON evidence(project_id);
        CREATE INDEX idx_findings_project ON findings(project_id);
        """,
    ),
)


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            applied = {
                row["version"]
                for row in connection.execute("SELECT version FROM schema_migrations")
            }
            for version, sql in MIGRATIONS:
                if version in applied:
                    continue
                connection.executescript(sql)
                connection.execute(
                    "INSERT INTO schema_migrations(version) VALUES (?)", (version,)
                )

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def schema_version(self) -> int:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations"
            ).fetchone()
        return int(row["version"]) if row else 0

    def create_project(self, project: Project) -> Project:
        data = project.model_dump(mode="json")
        try:
            with self.connect() as connection:
                connection.execute(
                    """
                    INSERT INTO projects(
                        id, schema_version, slug, name, description, scope_json,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        data["id"],
                        data["schema_version"],
                        data["slug"],
                        data["name"],
                        data["description"],
                        _json(data["scope"]),
                        data["created_at"],
                        data["updated_at"],
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(f"project slug already exists: {project.slug}") from exc
        return project

    def get_project(self, reference: str) -> Project:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM projects WHERE id = ? OR slug = ?",
                (reference, reference),
            ).fetchone()
        if row is None:
            raise NotFoundError(f"project not found: {reference}")
        return _project_from_row(row)

    def list_projects(self) -> list[Project]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM projects ORDER BY created_at, slug"
            ).fetchall()
        return [_project_from_row(row) for row in rows]

    def create_session(self, session: AnalysisSession) -> AnalysisSession:
        data = session.model_dump(mode="json")
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO sessions(
                    id, schema_version, project_id, goal, status, state_json,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["id"],
                    data["schema_version"],
                    data["project_id"],
                    data["goal"],
                    data["status"],
                    _json(data["state"]),
                    data["created_at"],
                    data["updated_at"],
                ),
            )
        return session

    def save_artifact(self, artifact: Artifact) -> Artifact:
        existing = self.find_artifact(artifact.project_id, artifact.sha256)
        if existing is not None:
            return existing
        data = artifact.model_dump(mode="json")
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO artifacts(
                    id, schema_version, project_id, sha256, original_name,
                    media_type, size_bytes, stored_path, imported_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["id"],
                    data["schema_version"],
                    data["project_id"],
                    data["sha256"],
                    data["original_name"],
                    data["media_type"],
                    data["size_bytes"],
                    data["stored_path"],
                    data["imported_at"],
                ),
            )
        return artifact

    def find_artifact(self, project_id: str, sha256: str) -> Artifact | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM artifacts WHERE project_id = ? AND sha256 = ?",
                (project_id, sha256),
            ).fetchone()
        return _artifact_from_row(row) if row is not None else None

    def record_tool_run(self, tool_run: ToolRun) -> ToolRun:
        data = tool_run.model_dump(mode="json")
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO tool_runs(
                    id, schema_version, project_id, session_id, tool_name,
                    tool_version, status, input_json, output_json, error,
                    started_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["id"],
                    data["schema_version"],
                    data["project_id"],
                    data["session_id"],
                    data["tool_name"],
                    data["tool_version"],
                    data["status"],
                    _json(data["input_data"]),
                    _json(data["output_data"]),
                    data["error"],
                    data["started_at"],
                    data["completed_at"],
                ),
            )
        return tool_run

    def list_tool_runs(self, project_id: str) -> list[ToolRun]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM tool_runs WHERE project_id = ? ORDER BY started_at",
                (project_id,),
            ).fetchall()
        return [_tool_run_from_row(row) for row in rows]


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _project_from_row(row: sqlite3.Row) -> Project:
    return Project.model_validate(
        {
            "id": row["id"],
            "schema_version": row["schema_version"],
            "slug": row["slug"],
            "name": row["name"],
            "description": row["description"],
            "scope": json.loads(row["scope_json"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
    )


def _artifact_from_row(row: sqlite3.Row) -> Artifact:
    return Artifact.model_validate(
        {
            "id": row["id"],
            "schema_version": row["schema_version"],
            "project_id": row["project_id"],
            "sha256": row["sha256"],
            "original_name": row["original_name"],
            "media_type": row["media_type"],
            "size_bytes": row["size_bytes"],
            "stored_path": row["stored_path"],
            "imported_at": row["imported_at"],
        }
    )


def _tool_run_from_row(row: sqlite3.Row) -> ToolRun:
    return ToolRun.model_validate(
        {
            "id": row["id"],
            "schema_version": row["schema_version"],
            "project_id": row["project_id"],
            "session_id": row["session_id"],
            "tool_name": row["tool_name"],
            "tool_version": row["tool_version"],
            "status": row["status"],
            "input_data": json.loads(row["input_json"]),
            "output_data": json.loads(row["output_json"]),
            "error": row["error"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
        }
    )
