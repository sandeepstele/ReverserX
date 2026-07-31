"""Explicit allowlist and validation boundary for tool invocation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from reverserx.tools.base import BaseTool, ToolContext, ToolExecution
from reverserx.tools.example import EchoTool


class ToolRegistryError(ValueError):
    """Base error for registration and lookup failures."""


class ToolValidationError(ToolRegistryError):
    """Raised when untrusted tool arguments do not match the declared schema."""


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, BaseTool[Any]] = {}

    def register(self, tool: BaseTool[Any]) -> None:
        if not tool.name or tool.name in self._tools:
            raise ToolRegistryError(
                f"tool name is empty or already registered: {tool.name}"
            )
        self._tools[tool.name] = tool

    def get(self, name: str) -> BaseTool[Any]:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ToolRegistryError(f"unknown tool: {name}") from exc

    def list_schemas(self) -> list[dict[str, Any]]:
        return [self._tools[name].schema() for name in sorted(self._tools)]

    def execute(
        self,
        name: str,
        context: ToolContext,
        arguments: Mapping[str, Any],
    ) -> ToolExecution:
        tool = self.get(name)
        try:
            validated = tool.input_model.model_validate(dict(arguments))
        except ValidationError as exc:
            raise ToolValidationError(f"invalid arguments for {name}: {exc}") from exc
        return tool.execute(context, validated)


def build_default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(EchoTool())
    return registry
