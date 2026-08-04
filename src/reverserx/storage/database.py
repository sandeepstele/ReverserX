"""SQLite persistence with explicit, forward-only schema migrations."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from reverserx.core.correlation import CorrelationRecord
from reverserx.core.models import (
    AgentCheckpoint,
    AnalysisSession,
    Artifact,
    Evidence,
    Finding,
    ModelUsage,
    PlanAttempt,
    PlanStep,
    Project,
    ToolRun,
)


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
    (
        2,
        """
        CREATE TABLE analysis_indexes (
            id TEXT PRIMARY KEY,
            schema_version TEXT NOT NULL,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            artifact_id TEXT REFERENCES artifacts(id) ON DELETE SET NULL,
            source_root TEXT NOT NULL,
            source_fingerprint TEXT NOT NULL,
            chunker_version TEXT NOT NULL,
            chunk_count INTEGER NOT NULL,
            metadata_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(project_id, source_root)
        );

        CREATE TABLE source_chunks (
            id TEXT PRIMARY KEY,
            schema_version TEXT NOT NULL,
            index_id TEXT NOT NULL REFERENCES analysis_indexes(id) ON DELETE CASCADE,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            artifact_id TEXT REFERENCES artifacts(id) ON DELETE SET NULL,
            content_sha256 TEXT NOT NULL,
            language TEXT NOT NULL,
            kind TEXT NOT NULL,
            relative_path TEXT NOT NULL,
            symbol TEXT,
            start_line INTEGER NOT NULL,
            end_line INTEGER NOT NULL,
            start_instruction INTEGER,
            end_instruction INTEGER,
            content TEXT NOT NULL,
            summary TEXT,
            metadata_json TEXT NOT NULL
        );

        CREATE TABLE vector_indexes (
            index_id TEXT PRIMARY KEY REFERENCES analysis_indexes(id) ON DELETE CASCADE,
            backend TEXT NOT NULL,
            collection_name TEXT NOT NULL,
            embedding_provider TEXT NOT NULL,
            dimensions INTEGER NOT NULL,
            document_count INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE context_summaries (
            id TEXT PRIMARY KEY,
            index_id TEXT NOT NULL REFERENCES analysis_indexes(id) ON DELETE CASCADE,
            level TEXT NOT NULL,
            scope TEXT NOT NULL,
            source_fingerprint TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(index_id, level, scope)
        );

        CREATE INDEX idx_analysis_indexes_project ON analysis_indexes(project_id);
        CREATE INDEX idx_source_chunks_index ON source_chunks(index_id);
        CREATE INDEX idx_source_chunks_project ON source_chunks(project_id);
        CREATE INDEX idx_source_chunks_path ON source_chunks(project_id, relative_path);
        CREATE INDEX idx_context_summaries_index ON context_summaries(index_id);
        """,
    ),
    (
        3,
        """
        PRAGMA foreign_keys = OFF;
        BEGIN IMMEDIATE;

        CREATE TABLE analysis_indexes_v3 (
            id TEXT PRIMARY KEY,
            schema_version TEXT NOT NULL,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            artifact_id TEXT REFERENCES artifacts(id) ON DELETE SET NULL,
            source_root TEXT NOT NULL,
            source_fingerprint TEXT NOT NULL,
            chunker_version TEXT NOT NULL,
            chunk_count INTEGER NOT NULL,
            metadata_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        INSERT INTO analysis_indexes_v3(
            id, schema_version, project_id, artifact_id, source_root,
            source_fingerprint, chunker_version, chunk_count,
            metadata_json, created_at, updated_at
        )
        SELECT
            id, schema_version, project_id, artifact_id, source_root,
            source_fingerprint, chunker_version, chunk_count,
            metadata_json, created_at, updated_at
        FROM analysis_indexes;

        CREATE TABLE source_chunks_v3 (
            id TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            index_id TEXT NOT NULL REFERENCES analysis_indexes(id) ON DELETE CASCADE,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            artifact_id TEXT REFERENCES artifacts(id) ON DELETE SET NULL,
            content_sha256 TEXT NOT NULL,
            language TEXT NOT NULL,
            kind TEXT NOT NULL,
            relative_path TEXT NOT NULL,
            symbol TEXT,
            start_line INTEGER NOT NULL,
            end_line INTEGER NOT NULL,
            start_instruction INTEGER,
            end_instruction INTEGER,
            content TEXT NOT NULL,
            summary TEXT,
            metadata_json TEXT NOT NULL,
            PRIMARY KEY(index_id, id)
        );

        INSERT INTO source_chunks_v3(
            id, schema_version, index_id, project_id, artifact_id,
            content_sha256, language, kind, relative_path, symbol,
            start_line, end_line, start_instruction, end_instruction,
            content, summary, metadata_json
        )
        SELECT
            id, schema_version, index_id, project_id, artifact_id,
            content_sha256, language, kind, relative_path, symbol,
            start_line, end_line, start_instruction, end_instruction,
            content, summary, metadata_json
        FROM source_chunks;

        DROP TABLE source_chunks;
        DROP TABLE analysis_indexes;
        ALTER TABLE analysis_indexes_v3 RENAME TO analysis_indexes;
        ALTER TABLE source_chunks_v3 RENAME TO source_chunks;

        CREATE INDEX idx_analysis_indexes_project
            ON analysis_indexes(project_id);
        CREATE INDEX idx_analysis_indexes_project_root
            ON analysis_indexes(project_id, source_root);
        CREATE INDEX idx_source_chunks_index ON source_chunks(index_id);
        CREATE INDEX idx_source_chunks_project ON source_chunks(project_id);
        CREATE INDEX idx_source_chunks_path
            ON source_chunks(project_id, relative_path);

        COMMIT;
        PRAGMA foreign_keys = ON;
        """,
    ),
    (
        4,
        """
        ALTER TABLE plan_steps ADD COLUMN tool_run_id TEXT;
        ALTER TABLE plan_steps ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE plan_steps ADD COLUMN last_error TEXT;
        ALTER TABLE model_usage ADD COLUMN input_image_count INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE model_usage ADD COLUMN request_id TEXT;

        CREATE TABLE agent_checkpoints (
            id TEXT PRIMARY KEY,
            schema_version TEXT NOT NULL,
            session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            sequence INTEGER NOT NULL,
            state_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(session_id, sequence)
        );

        CREATE INDEX idx_plan_steps_session ON plan_steps(session_id);
        CREATE INDEX idx_model_usage_session ON model_usage(session_id);
        CREATE INDEX idx_checkpoints_session ON agent_checkpoints(session_id);
        """,
    ),
    (
        5,
        """
        CREATE TABLE plan_attempts (
            id TEXT PRIMARY KEY,
            schema_version TEXT NOT NULL,
            session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            attempt INTEGER NOT NULL,
            response_json TEXT,
            raw_text TEXT NOT NULL,
            valid INTEGER NOT NULL,
            validation_error TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(session_id, attempt)
        );

        CREATE INDEX idx_plan_attempts_session ON plan_attempts(session_id);
        """,
    ),
    (
        6,
        """
        CREATE TABLE correlation_records (
            id TEXT PRIMARY KEY,
            schema_version TEXT NOT NULL,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            session_id TEXT REFERENCES sessions(id) ON DELETE SET NULL,
            source_evidence_id TEXT,
            runtime_evidence_id TEXT,
            network_evidence_id TEXT,
            relationship TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 0.5,
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE INDEX idx_correlation_records_project ON correlation_records(project_id);
        CREATE INDEX idx_correlation_records_session ON correlation_records(session_id);
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

    def get_session(self, session_id: str) -> AnalysisSession:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sessions WHERE id = ?", (session_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError(f"session not found: {session_id}")
        return _session_from_row(row)

    def list_sessions(self, project_id: str) -> list[AnalysisSession]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM sessions WHERE project_id = ? ORDER BY created_at, id",
                (project_id,),
            ).fetchall()
        return [_session_from_row(row) for row in rows]

    def update_session(self, session: AnalysisSession) -> AnalysisSession:
        data = session.model_dump(mode="json")
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE sessions SET status = ?, state_json = ?, updated_at = ?
                WHERE id = ? AND project_id = ?
                """,
                (
                    data["status"],
                    _json(data["state"]),
                    data["updated_at"],
                    data["id"],
                    data["project_id"],
                ),
            )
        if cursor.rowcount != 1:
            raise NotFoundError(f"session not found: {session.id}")
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

    def get_artifact(self, project_id: str, reference: str) -> Artifact:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM artifacts
                WHERE project_id = ? AND (id = ? OR sha256 = ?)
                """,
                (project_id, reference, reference),
            ).fetchone()
        if row is None:
            raise NotFoundError(f"artifact not found: {reference}")
        return _artifact_from_row(row)

    def list_artifacts(self, project_id: str) -> list[Artifact]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM artifacts WHERE project_id = ? ORDER BY imported_at, id",
                (project_id,),
            ).fetchall()
        return [_artifact_from_row(row) for row in rows]

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

    def save_plan_step(self, step: PlanStep) -> PlanStep:
        data = step.model_dump(mode="json")
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO plan_steps(
                    id, schema_version, session_id, sequence, objective, tool_name,
                    arguments_json, status, depends_on_json, tool_run_id, attempts,
                    last_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["id"],
                    data["schema_version"],
                    data["session_id"],
                    data["sequence"],
                    data["objective"],
                    data["tool_name"],
                    _json(data["arguments"]),
                    data["status"],
                    _json(data["depends_on"]),
                    data["tool_run_id"],
                    data["attempts"],
                    data["last_error"],
                ),
            )
        return step

    def update_plan_step(self, step: PlanStep) -> PlanStep:
        data = step.model_dump(mode="json")
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE plan_steps SET objective = ?, tool_name = ?,
                    arguments_json = ?, status = ?, depends_on_json = ?,
                    tool_run_id = ?, attempts = ?, last_error = ?
                WHERE id = ? AND session_id = ?
                """,
                (
                    data["objective"],
                    data["tool_name"],
                    _json(data["arguments"]),
                    data["status"],
                    _json(data["depends_on"]),
                    data["tool_run_id"],
                    data["attempts"],
                    data["last_error"],
                    data["id"],
                    data["session_id"],
                ),
            )
        if cursor.rowcount != 1:
            raise NotFoundError(f"plan step not found: {step.id}")
        return step

    def list_plan_steps(self, session_id: str) -> list[PlanStep]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM plan_steps WHERE session_id = ? ORDER BY sequence, id",
                (session_id,),
            ).fetchall()
        return [_plan_step_from_row(row) for row in rows]

    def save_plan_attempt(self, attempt: PlanAttempt) -> PlanAttempt:
        data = attempt.model_dump(mode="json")
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO plan_attempts(
                    id, schema_version, session_id, attempt, response_json,
                    raw_text, valid, validation_error, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["id"],
                    data["schema_version"],
                    data["session_id"],
                    data["attempt"],
                    _json(data["response"]) if data["response"] is not None else None,
                    data["raw_text"],
                    int(data["valid"]),
                    data["validation_error"],
                    data["created_at"],
                ),
            )
        return attempt

    def list_plan_attempts(self, session_id: str) -> list[PlanAttempt]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM plan_attempts WHERE session_id = ? ORDER BY attempt, id",
                (session_id,),
            ).fetchall()
        return [_plan_attempt_from_row(row) for row in rows]

    def save_evidence(self, evidence: Evidence) -> Evidence:
        data = evidence.model_dump(mode="json")
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO evidence(
                    id, schema_version, project_id, tool_run_id, artifact_id,
                    kind, locator, summary, metadata_json, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["id"],
                    data["schema_version"],
                    data["project_id"],
                    data["tool_run_id"],
                    data["artifact_id"],
                    data["kind"],
                    data["locator"],
                    data["summary"],
                    _json(data["metadata"]),
                    data["observed_at"],
                ),
            )
        return evidence

    def list_evidence(self, project_id: str) -> list[Evidence]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM evidence WHERE project_id = ? ORDER BY observed_at, id",
                (project_id,),
            ).fetchall()
        return [_evidence_from_row(row) for row in rows]

    def save_finding(self, finding: Finding) -> Finding:
        data = finding.model_dump(mode="json")
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO findings(
                    id, schema_version, project_id, title, description, status,
                    severity, confidence, evidence_ids_json, inference,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["id"],
                    data["schema_version"],
                    data["project_id"],
                    data["title"],
                    data["description"],
                    data["status"],
                    data["severity"],
                    data["confidence"],
                    _json(data["evidence_ids"]),
                    int(data["inference"]),
                    data["created_at"],
                    data["updated_at"],
                ),
            )
        return finding

    def list_findings(self, project_id: str) -> list[Finding]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM findings WHERE project_id = ? ORDER BY created_at, id",
                (project_id,),
            ).fetchall()
        return [_finding_from_row(row) for row in rows]

    def record_model_usage(self, usage: ModelUsage) -> ModelUsage:
        data = usage.model_dump(mode="json")
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO model_usage(
                    id, schema_version, project_id, session_id, provider, model,
                    task_type, input_tokens, output_tokens, input_image_count,
                    estimated_cost_usd, actual_cost_usd, request_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["id"],
                    data["schema_version"],
                    data["project_id"],
                    data["session_id"],
                    data["provider"],
                    data["model"],
                    data["task_type"],
                    data["input_tokens"],
                    data["output_tokens"],
                    data["input_image_count"],
                    data["estimated_cost_usd"],
                    data["actual_cost_usd"],
                    data["request_id"],
                    data["created_at"],
                ),
            )
        return usage

    def list_model_usage(self, session_id: str) -> list[ModelUsage]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM model_usage WHERE session_id = ? ORDER BY created_at, id",
                (session_id,),
            ).fetchall()
        return [_model_usage_from_row(row) for row in rows]

    def save_checkpoint(self, checkpoint: AgentCheckpoint) -> AgentCheckpoint:
        data = checkpoint.model_dump(mode="json")
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO agent_checkpoints(
                    id, schema_version, session_id, sequence, state_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    data["id"],
                    data["schema_version"],
                    data["session_id"],
                    data["sequence"],
                    _json(data["state"]),
                    data["created_at"],
                ),
            )
        return checkpoint

    def latest_checkpoint(self, session_id: str) -> AgentCheckpoint | None:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM agent_checkpoints WHERE session_id = ?
                ORDER BY sequence DESC LIMIT 1
                """,
                (session_id,),
            ).fetchone()
        return _checkpoint_from_row(row) if row is not None else None


    # --- Correlation Records (Phase 3) ---

    def create_correlation(self, record: CorrelationRecord) -> CorrelationRecord:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO correlation_records
                (id, schema_version, project_id, session_id, source_evidence_id,
                 runtime_evidence_id, network_evidence_id, relationship, confidence,
                 description, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.id,
                    "1.0",
                    record.project_id,
                    record.session_id,
                    record.source_evidence_id,
                    record.runtime_evidence_id,
                    record.network_evidence_id,
                    record.relationship,
                    record.confidence,
                    record.description,
                    record.created_at.isoformat(),
                ),
            )
        return record

    def list_correlations(self, project_id: str) -> list[CorrelationRecord]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM correlation_records WHERE project_id = ? ORDER BY created_at DESC",
                (project_id,),
            ).fetchall()
        return [_correlation_from_row(row) for row in rows]

    def list_correlations_for_session(self, session_id: str) -> list[CorrelationRecord]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM correlation_records WHERE session_id = ? ORDER BY created_at",
                (session_id,),
            ).fetchall()
        return [_correlation_from_row(row) for row in rows]


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


def _session_from_row(row: sqlite3.Row) -> AnalysisSession:
    return AnalysisSession.model_validate(
        {
            "id": row["id"],
            "schema_version": row["schema_version"],
            "project_id": row["project_id"],
            "goal": row["goal"],
            "status": row["status"],
            "state": json.loads(row["state_json"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
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


def _plan_step_from_row(row: sqlite3.Row) -> PlanStep:
    return PlanStep.model_validate(
        {
            "id": row["id"],
            "schema_version": row["schema_version"],
            "session_id": row["session_id"],
            "sequence": row["sequence"],
            "objective": row["objective"],
            "tool_name": row["tool_name"],
            "arguments": json.loads(row["arguments_json"]),
            "status": row["status"],
            "depends_on": json.loads(row["depends_on_json"]),
            "tool_run_id": row["tool_run_id"],
            "attempts": row["attempts"],
            "last_error": row["last_error"],
        }
    )


def _plan_attempt_from_row(row: sqlite3.Row) -> PlanAttempt:
    return PlanAttempt.model_validate(
        {
            "id": row["id"],
            "schema_version": row["schema_version"],
            "session_id": row["session_id"],
            "attempt": row["attempt"],
            "response": (
                json.loads(row["response_json"])
                if row["response_json"] is not None
                else None
            ),
            "raw_text": row["raw_text"],
            "valid": bool(row["valid"]),
            "validation_error": row["validation_error"],
            "created_at": row["created_at"],
        }
    )


def _evidence_from_row(row: sqlite3.Row) -> Evidence:
    return Evidence.model_validate(
        {
            "id": row["id"],
            "schema_version": row["schema_version"],
            "project_id": row["project_id"],
            "tool_run_id": row["tool_run_id"],
            "artifact_id": row["artifact_id"],
            "kind": row["kind"],
            "locator": row["locator"],
            "summary": row["summary"],
            "metadata": json.loads(row["metadata_json"]),
            "observed_at": row["observed_at"],
        }
    )


def _finding_from_row(row: sqlite3.Row) -> Finding:
    return Finding.model_validate(
        {
            "id": row["id"],
            "schema_version": row["schema_version"],
            "project_id": row["project_id"],
            "title": row["title"],
            "description": row["description"],
            "status": row["status"],
            "severity": row["severity"],
            "confidence": row["confidence"],
            "evidence_ids": json.loads(row["evidence_ids_json"]),
            "inference": bool(row["inference"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
    )


def _model_usage_from_row(row: sqlite3.Row) -> ModelUsage:
    return ModelUsage.model_validate(
        {
            "id": row["id"],
            "schema_version": row["schema_version"],
            "project_id": row["project_id"],
            "session_id": row["session_id"],
            "provider": row["provider"],
            "model": row["model"],
            "task_type": row["task_type"],
            "input_tokens": row["input_tokens"],
            "output_tokens": row["output_tokens"],
            "input_image_count": row["input_image_count"],
            "estimated_cost_usd": row["estimated_cost_usd"],
            "actual_cost_usd": row["actual_cost_usd"],
            "request_id": row["request_id"],
            "created_at": row["created_at"],
        }
    )


def _checkpoint_from_row(row: sqlite3.Row) -> AgentCheckpoint:
    return AgentCheckpoint.model_validate(
        {
            "id": row["id"],
            "schema_version": row["schema_version"],
            "session_id": row["session_id"],
            "sequence": row["sequence"],
            "state": json.loads(row["state_json"]),
            "created_at": row["created_at"],
        }
    )


def _correlation_from_row(row: sqlite3.Row) -> CorrelationRecord:
    return CorrelationRecord.model_validate(
        {
            "id": row["id"],
            "project_id": row["project_id"],
            "session_id": row["session_id"],
            "source_evidence_id": row["source_evidence_id"],
            "runtime_evidence_id": row["runtime_evidence_id"],
            "network_evidence_id": row["network_evidence_id"],
            "relationship": row["relationship"],
            "confidence": row["confidence"],
            "description": row["description"],
            "created_at": row["created_at"],
        }
    )
