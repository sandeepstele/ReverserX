"""Tool adapters for persistent source indexing and retrieval."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

from reverserx.context.search import (
    DEFAULT_MAX_MATCH_LINES,
    DEFAULT_REGEX_TIMEOUT_SECONDS,
    MAX_MATCH_LINES,
    MAX_REGEX_TIMEOUT_SECONDS,
    SearchMode,
    lexical_search,
)
from reverserx.context.service import ContextService
from reverserx.storage import Database, NotFoundError
from reverserx.storage.context import ContextRepository
from reverserx.tools.base import BaseTool, ToolContext, ToolExecution


class ContextToolError(ValueError):
    """Raised when a context tool violates project or storage boundaries."""


class VectorBackend(StrEnum):
    CHROMA = "chroma"
    MEMORY = "memory"


class EmbeddingBackend(StrEnum):
    HASHING = "hashing"
    OLLAMA = "ollama"


class SourceIndexInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_root: Path
    artifact_id: str | None = None
    vector_backend: VectorBackend = VectorBackend.CHROMA
    embedding_provider: EmbeddingBackend = EmbeddingBackend.HASHING

    @field_validator("source_root", mode="before")
    @classmethod
    def parse_path(cls, value: object) -> object:
        return Path(value) if isinstance(value, str) else value


class SourceSearchInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=4_096)
    mode: SearchMode = SearchMode.EXACT
    case_sensitive: bool = False
    max_results: int = Field(default=50, ge=1, le=1_000)
    context_lines: int = Field(default=2, ge=0, le=50)
    max_match_lines: int = Field(
        default=DEFAULT_MAX_MATCH_LINES,
        ge=1,
        le=MAX_MATCH_LINES,
    )
    regex_timeout_seconds: float = Field(
        default=DEFAULT_REGEX_TIMEOUT_SECONDS,
        gt=0,
        le=MAX_REGEX_TIMEOUT_SECONDS,
    )


class ContextQueryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=10_000)
    token_budget: int = Field(default=60_000, ge=100, le=2_000_000)
    limit: int = Field(default=20, ge=1, le=1_000)
    vector_backend: VectorBackend = VectorBackend.CHROMA
    embedding_provider: EmbeddingBackend = EmbeddingBackend.HASHING
    known_paths: tuple[str, ...] = ()


class SourceIndexTool(BaseTool[SourceIndexInput]):
    name = "source_index"
    description = (
        "Chunk, persist, summarize, and vector-index a decompiled source tree."
    )
    version = "1.1.0"
    input_model = SourceIndexInput

    def execute(
        self, context: ToolContext, arguments: SourceIndexInput
    ) -> ToolExecution:
        database = _database(context)
        project = database.get_project(context.project_id)
        if project.id != context.project_id:
            raise ContextToolError(f"project not found: {context.project_id}")
        artifact_id: str | None = None
        if arguments.artifact_id is not None:
            try:
                artifact_id = database.get_artifact(
                    context.project_id, arguments.artifact_id
                ).id
            except NotFoundError as exc:
                raise ContextToolError(
                    "artifact is not available to the active project: "
                    f"{arguments.artifact_id}"
                ) from exc

        source_root = arguments.source_root.expanduser().resolve(strict=True)
        _require_within(source_root, _project_root(context))
        result = ContextService(
            ContextRepository(database),
            context.data_dir / "vectors",
            data_dir=context.data_dir,
        ).build(
            project_id=context.project_id,
            artifact_id=artifact_id,
            source_root=source_root,
            vector_backend=arguments.vector_backend.value,
            embedding_provider=arguments.embedding_provider.value,
        )
        return ToolExecution(output=result.model_dump(mode="json"))


class SourceSearchTool(BaseTool[SourceSearchInput]):
    name = "source_search"
    description = (
        "Search the project's latest persisted source index using exact text or a "
        "regular expression; no source path/root argument is needed or accepted."
    )
    version = "1.1.0"
    input_model = SourceSearchInput

    def execute(
        self, context: ToolContext, arguments: SourceSearchInput
    ) -> ToolExecution:
        repository = ContextRepository(_database(context))
        index = repository.latest_index(context.project_id)
        hits = lexical_search(
            repository.iter_chunks(index.id),
            arguments.query,
            mode=arguments.mode,
            case_sensitive=arguments.case_sensitive,
            max_results=arguments.max_results,
            context_lines=arguments.context_lines,
            max_match_lines=arguments.max_match_lines,
            regex_timeout_seconds=arguments.regex_timeout_seconds,
        )
        return ToolExecution(
            output={
                "index_id": index.id,
                "query": arguments.query,
                "mode": arguments.mode.value,
                "hits": [hit.model_dump(mode="json") for hit in hits],
            }
        )


class ContextQueryTool(BaseTool[ContextQueryInput]):
    name = "context_query"
    description = (
        "Retrieve and token-budget source context from the project's latest persisted "
        "index; optional known_paths are ranking hints, not a source root."
    )
    version = "1.0.0"
    input_model = ContextQueryInput

    def execute(
        self, context: ToolContext, arguments: ContextQueryInput
    ) -> ToolExecution:
        result = ContextService(
            ContextRepository(_database(context)),
            context.data_dir / "vectors",
            data_dir=context.data_dir,
        ).query(
            project_id=context.project_id,
            query=arguments.query,
            token_budget=arguments.token_budget,
            limit=arguments.limit,
            vector_backend=arguments.vector_backend.value,
            embedding_provider=arguments.embedding_provider.value,
            known_paths=arguments.known_paths,
        )
        return ToolExecution(output=result.model_dump(mode="json"))


def _database(context: ToolContext) -> Database:
    database = Database(context.database_path or context.data_dir / "reverserx.sqlite3")
    database.initialize()
    return database


def _require_within(path: Path, root: Path) -> None:
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ContextToolError(
            f"source root must be inside the project area: {root}"
        ) from exc


def _project_root(context: ToolContext) -> Path:
    data_root = context.data_dir.expanduser().resolve()
    projects_root = (data_root / "projects").resolve()
    project_root = (projects_root / context.project_id).resolve()
    try:
        project_root.relative_to(projects_root)
    except ValueError as exc:
        raise ContextToolError("project area escapes the data directory") from exc
    return project_root
