"""mitmproxy lifecycle tools — start, stop, import, and list captured flows."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from reverserx.tools.base import BaseTool, EmptyInput, ToolContext, ToolExecution
from reverserx.utils.proxy import (
    CapturedFlow,
    ProxyError,
    group_endpoints,
    normalize_url,
    parse_har,
    proxy_status,
    redact_secrets,
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


class LiveCaptureInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    port: int = Field(default=8080, ge=1024, le=65535)
    duration_seconds: float = Field(default=60, gt=0, le=3600)
    index_flows: bool = Field(default=True, description="Index captured flows into ChromaDB")


class LiveCaptureTool(BaseTool[LiveCaptureInput]):
    name = "proxy_live_capture"
    description = (
        "Start mitmproxy, capture HTTP flows live, index into ChromaDB, "
        "and display traffic in real-time. Like HTTP Toolkit built into ReverserX."
    )
    version = "1.0.0"
    input_model = LiveCaptureInput

    def execute(self, context: ToolContext, arguments: LiveCaptureInput) -> ToolExecution:
        import threading
        import time as _time

        # 1. Start proxy
        try:
            meta = start_mitmproxy(arguments.port)
        except ProxyError as exc:
            return ToolExecution(
                output={"status": "error", "error": str(exc)},
                notices=(f"Proxy start failed: {exc}",),
            )

        har_path = Path(meta["har_path"])
        flows_before: set[str] = set()

        # 2. Wait for capture duration, polling for new flows
        deadline = _time.monotonic() + arguments.duration_seconds
        all_flows: list[dict[str, Any]] = []
        last_check = 0

        while _time.monotonic() < deadline:
            _time.sleep(2)  # Poll every 2 seconds
            if har_path.exists():
                mtime = har_path.stat().st_mtime
                if mtime > last_check:
                    last_check = mtime
                    try:
                        new_flows = parse_har(har_path)
                        for f in new_flows:
                            if f.id not in flows_before:
                                flows_before.add(f.id)
                                all_flows.append({
                                    "id": f.id,
                                    "method": f.method,
                                    "url": f.url,
                                    "normalized_url": normalize_url(f.url),
                                    "status": f.status,
                                    "duration_ms": f.duration_ms,
                                    "request_headers": redact_secrets(f.request_headers),
                                    "response_headers": redact_secrets(f.response_headers),
                                    "request_body_hash": f.request_body_hash,
                                    "response_body_hash": f.response_body_hash,
                                })
                    except Exception:
                        pass

        # 3. Stop proxy
        stop_result = stop_mitmproxy(arguments.port)

        # 4. Index flows into ChromaDB
        index_result: dict[str, Any] = {"indexed": 0}
        if arguments.index_flows and all_flows:
            try:
                from reverserx.tools.dynamic.network_indexer import index_flows_to_chroma
                from reverserx.utils.proxy import CapturedFlow

                flow_objects = [
                    CapturedFlow(
                        id=f["id"],
                        url=f["url"],
                        method=f["method"],
                        status=f["status"],
                        request_headers=f["request_headers"],
                        response_headers=f["response_headers"],
                        request_body_hash=f.get("request_body_hash", ""),
                        response_body_hash=f.get("response_body_hash", ""),
                        duration_ms=f.get("duration_ms", 0),
                        timestamp=f.get("timestamp", _time.time()),
                    )
                    for f in all_flows
                ]
                collection = f"network_flows_{context.project_id}"
                persist = str(context.data_dir / "chroma")
                index_result = index_flows_to_chroma(flow_objects, collection, persist)
            except Exception as exc:
                index_result = {"error": str(exc), "indexed": 0}

        # 5. Display results
        endpoints = group_endpoints(
            [CapturedFlow(
                id=f["id"], url=f["url"], method=f["method"], status=f["status"],
                request_headers=f.get("request_headers", {}),
                response_headers=f.get("response_headers", {}),
                duration_ms=f.get("duration_ms", 0),
            ) for f in all_flows]
        ) if all_flows else []

        return ToolExecution(
            output={
                "status": "complete",
                "duration": arguments.duration_seconds,
                "flows_captured": len(all_flows),
                "indexed_chunks": index_result.get("indexed", 0),
                "endpoints": [
                    {"pattern": e.pattern, "method": e.method, "host": e.host, "count": e.flow_count}
                    for e in endpoints[:30]
                ],
                "flows": all_flows[:100],  # First 100 flows in detail
                "har_path": meta["har_path"],
            },
            notices=(
                f"Captured {len(all_flows)} flows across {len(endpoints)} endpoints "
                f"in {arguments.duration_seconds}s. "
                f"Indexed {index_result.get('indexed', 0)} chunks into ChromaDB. "
                f"Use 'reverserx context query testapp \"API request patterns\"' "
                f"to search captured traffic alongside source code.",
            ),
        )


class NetworkFlowSearchInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=2_000)
    limit: int = Field(default=20, ge=1, le=100)


class NetworkFlowSearchTool(BaseTool[NetworkFlowSearchInput]):
    name = "network_flow_search"
    description = (
        "Search indexed network traffic by natural language query. "
        "Returns captured HTTP flows matching the query from ChromaDB."
    )
    version = "1.0.0"
    input_model = NetworkFlowSearchInput

    def execute(self, context: ToolContext, arguments: NetworkFlowSearchInput) -> ToolExecution:
        try:
            from reverserx.tools.dynamic.network_indexer import search_flows
        except ImportError:
            return ToolExecution(output={"hits": [], "error": "chromadb not installed"})

        collection = f"network_flows_{context.project_id}"
        persist = str(context.data_dir / "chroma")
        hits = search_flows(arguments.query, collection, persist, limit=arguments.limit)

        return ToolExecution(
            output={
                "query": arguments.query,
                "hits": hits,
                "count": len(hits),
            },
            notices=(
                f"Found {len(hits)} network flow matches for '{arguments.query}'. "
                "Use context_query for combined source+network search.",
            ),
        )
