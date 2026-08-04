"""Explicit allowlist and validation boundary for tool invocation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ValidationError

from reverserx.reporting import AgentReportTool, StaticReportTool
from reverserx.tools.base import BaseTool, ToolContext, ToolExecution
from reverserx.tools.dynamic import (
    AdbDeviceInfoTool,
    AdbDeviceListTool,
    AdbLogcatTool,
    AdbShellTool,
    CertSetupTool,
    CorrelateEvidenceTool,
    FridaHookListTool,
    FridaInjectTool,
    FridaPsTool,
    InteractionWaitTool,
    LiveCaptureTool,
    NetworkFlowSearchTool,
    ProxyCaptureImportTool,
    ProxyFlowListTool,
    ProxyStartTool,
    ProxyStopTool,
)
from reverserx.tools.example import EchoTool
from reverserx.tools.static import (
    ApkBundleImportTool,
    ApkInspectTool,
    ApkMetadataTool,
    ContextQueryTool,
    JadxTool,
    ManifestAnalyzeTool,
    ObfuscationDetectTool,
    SourceIndexTool,
    SourceSearchTool,
)


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
        validated = self.validate_arguments(name, arguments)
        return tool.execute(context, validated)

    def validate_arguments(self, name: str, arguments: Mapping[str, Any]) -> BaseModel:
        """Validate untrusted arguments without executing a tool."""

        tool = self.get(name)
        try:
            return tool.input_model.model_validate(dict(arguments))
        except ValidationError as exc:
            raise ToolValidationError(f"invalid arguments for {name}: {exc}") from exc


def build_default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(EchoTool())
    registry.register(ApkInspectTool())
    registry.register(ApkBundleImportTool())
    registry.register(JadxTool())
    registry.register(ManifestAnalyzeTool())
    registry.register(ApkMetadataTool())
    registry.register(ObfuscationDetectTool())
    registry.register(SourceIndexTool())
    registry.register(SourceSearchTool())
    registry.register(ContextQueryTool())
    registry.register(StaticReportTool())
    registry.register(AgentReportTool())
    # Phase 3 — Dynamic analysis tools
    registry.register(AdbDeviceListTool())
    registry.register(CertSetupTool())
    registry.register(AdbDeviceInfoTool())
    registry.register(AdbShellTool())
    registry.register(AdbLogcatTool())
    registry.register(FridaPsTool())
    registry.register(FridaHookListTool())
    registry.register(FridaInjectTool())
    registry.register(ProxyStartTool())
    registry.register(ProxyStopTool())
    registry.register(ProxyCaptureImportTool())
    registry.register(ProxyFlowListTool())
    registry.register(LiveCaptureTool())
    registry.register(NetworkFlowSearchTool())
    registry.register(InteractionWaitTool())
    registry.register(CorrelateEvidenceTool())
    return registry
