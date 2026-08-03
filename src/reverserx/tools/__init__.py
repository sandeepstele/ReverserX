"""Typed tool contracts with cycle-safe lazy registry exports."""

from typing import TYPE_CHECKING

from reverserx.tools.base import BaseTool, ToolContext, ToolExecution

if TYPE_CHECKING:
    from reverserx.tools.registry import ToolRegistry, build_default_registry

__all__ = [
    "BaseTool",
    "ToolContext",
    "ToolExecution",
    "ToolRegistry",
    "build_default_registry",
]


def __getattr__(name: str) -> object:
    if name in {"ToolRegistry", "build_default_registry"}:
        from reverserx.tools.registry import ToolRegistry, build_default_registry

        exports = {
            "ToolRegistry": ToolRegistry,
            "build_default_registry": build_default_registry,
        }
        return exports[name]
    raise AttributeError(name)
