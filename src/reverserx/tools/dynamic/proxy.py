"""mitmproxy lifecycle tools — start, stop, import, and list captured flows."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from reverserx.tools.base import BaseTool, EmptyInput, ToolContext, ToolExecution
from reverserx.utils.proxy import (
    ProxyError,
    group_endpoints,
    parse_har,
    proxy_status,
    start_mitmproxy,
    stop_mitmproxy,
)


class ProxyPortInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    port: int = Field(default=8080, ge=1024, le=65535)


class HarImportInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    har_path: str = Field(min_length=1)
    scope_filter: bool = True

    @classmethod
    def _validate_path(cls, value: object) -> object:
        if isinstance(value, str):
            return Path(value)
        return value


class ProxyStartTool(BaseTool[ProxyPortInput]):
    name = "proxy_start"
    description = "Start mitmproxy capture on the configured port."
    version = "1.0.0"
    input_model = ProxyPortInput

    def execute(self, context: ToolContext, arguments: ProxyPortInput) -> ToolExecution:
        try:
            meta = start_mitmproxy(arguments.port)
        except ProxyError as exc:
            return ToolExecution(
                output={"status": "error", "error": str(exc), "port": arguments.port},
                notices=(f"Proxy error: {exc}",),
            )
        return ToolExecution(
            output=meta,
            notices=(
                f"mitmdump running (PID {meta.get('pid')}). "
                "Set device proxy to 127.0.0.1:{arguments.port} via WiFi settings. "
                "For emulator: run 'adb reverse tcp:{port} tcp:{port}'. "
                "For HTTPS: install mitmproxy CA cert on the device (http://mitm.it). "
                f"Flows saved to: {meta.get('har_path')}",
            ),
        )


class ProxyStopTool(BaseTool[EmptyInput]):
    name = "proxy_stop"
    description = "Stop the running mitmproxy and collect captured flows."
    version = "1.0.0"
    input_model = EmptyInput

    def execute(self, context: ToolContext, arguments: EmptyInput) -> ToolExecution:
        result = stop_mitmproxy(8080)
        return ToolExecution(
            output=result,
            notices=(
                f"mitmdump stopped (port {result.get('port')}). "
                "Use 'reverserx proxy import <har_file>' to load captured flows.",
            ),
        )


class ProxyCaptureImportTool(BaseTool[HarImportInput]):
    name = "proxy_capture_import"
    description = "Import a HAR file and normalize captured API flows."
    version = "1.0.0"
    input_model = HarImportInput

    def execute(self, context: ToolContext, arguments: HarImportInput) -> ToolExecution:
        har_path = Path(arguments.har_path)
        if not har_path.is_file():
            return ToolExecution(
                output={"error": f"HAR file not found: {har_path}"},
            )
        try:
            flows = parse_har(har_path)
        except (OSError, ValueError, ProxyError) as exc:
            return ToolExecution(
                output={"error": str(exc)},
                notices=(f"HAR parse error: {exc}",),
            )
        endpoints = group_endpoints(flows)
        return ToolExecution(
            output={
                "flows_imported": len(flows),
                "endpoints": [
                    {
                        "pattern": e.pattern,
                        "method": e.method,
                        "host": e.host,
                        "flow_count": e.flow_count,
                        "example_urls": e.raw_urls[:3],
                    }
                    for e in endpoints[:50]
                ],
                "endpoint_count": len(endpoints),
            },
            notices=(
                f"Imported {len(flows)} flows across {len(endpoints)} endpoint patterns. "
                "Request/response headers have been redacted for secrets.",
            ),
        )


class ProxyFlowListTool(BaseTool[EmptyInput]):
    name = "proxy_flow_list"
    description = "List captured API flows with URL, method, status, and timing."
    version = "1.0.0"
    input_model = EmptyInput

    def execute(self, context: ToolContext, arguments: EmptyInput) -> ToolExecution:
        # For MVP: return guidance. Full implementation reads from persisted
        # network_flows table once proxy capture is integrated.
        return ToolExecution(
            output={
                "flows": [],
                "count": 0,
            },
            notices=(
                "Use proxy_capture_import to import HAR files first. "
                "Live flow listing will be available in a future update.",
            ),
        )
