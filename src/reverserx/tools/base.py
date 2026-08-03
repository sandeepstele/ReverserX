"""Provider-independent interface implemented by every ReverserX tool."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, ClassVar, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field


class EmptyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ToolContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    project_id: str
    data_dir: Path
    database_path: Path | None = None
    artifact_root: Path | None = None
    session_id: str | None = None


class ToolExecution(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    output: dict[str, Any] = Field(default_factory=dict)
    notices: tuple[str, ...] = ()


InputT = TypeVar("InputT", bound=BaseModel)


class BaseTool(ABC, Generic[InputT]):
    name: ClassVar[str]
    description: ClassVar[str]
    version: ClassVar[str] = "1.0.0"
    input_model: ClassVar[type[BaseModel]] = EmptyInput

    @abstractmethod
    def execute(self, context: ToolContext, arguments: InputT) -> ToolExecution:
        """Execute validated arguments in a project context."""

    @classmethod
    def schema(cls) -> dict[str, Any]:
        return {
            "name": cls.name,
            "description": cls.description,
            "version": cls.version,
            "input_schema": cls.input_model.model_json_schema(),
        }
