"""mitmproxy lifecycle tools — start, stop, import, live capture, and flow search."""

from __future__ import annotations

import time as _time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from reverserx.tools.base import BaseTool, EmptyInput, ToolContext, ToolExecution
from reverserx.utils.proxy import (
    CapturedFlow,
    ProxyError,
    group_endpoints,
    normalize_url,
    parse_har,
    redact_secrets,
)
from reverserx.utils.proxy_server import ReverserXProxyServer, ProxyServerError

# Module-level proxy server — survives across tool calls
_active_proxy: ReverserXProxyServer | None = None
_active_proxy_lock = __import__("threading").Lock()


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
        global _active_proxy
        with _active_proxy_lock:
            if _active_proxy is not None and _active_proxy._running:
                return ToolExecution(
                    output={"status": "already_running", "port": _active_proxy.port},
                    notices=("Proxy is already running. Use proxy_stop first.",),
                )

            try:
                _active_proxy = ReverserXProxyServer(
                    port=arguments.port,
                    project_id=context.project_id,
                    data_dir=context.data_dir,
                    capture_bodies=True,
                    auto_index=True,
                )
                _active_proxy.start()
            except ProxyServerError as exc:
                _active_proxy = None
                return ToolExecution(
                    output={"status": "error", "error": str(exc), "port": arguments.port},
                    notices=(f"Proxy start failed: {exc}",),
                )

        return ToolExecution(
            output={
                "status": "running",
                "port": arguments.port,
                "flows_captured": 0,
                "proxy_url": f"http://127.0.0.1:{arguments.port}",
            },
            notices=(
                "Real-time proxy running with body capture and auto-indexing. "
                f"Set device proxy to 127.0.0.1:{arguments.port}. "
                f"For emulator: 'adb reverse tcp:{arguments.port} tcp:{arguments.port}'. "
                "For HTTPS: install mitmproxy CA cert (http://mitm.it). "
                "Use 'proxy flows' to see live traffic or 'proxy live' for monitoring.",
            ),
        )


class ProxyStopTool(BaseTool[EmptyInput]):
    name = "proxy_stop"
    description = "Stop the running mitmproxy and collect captured flows."
    version = "1.0.0"
    input_model = EmptyInput

    def execute(self, context: ToolContext, arguments: EmptyInput) -> ToolExecution:
        global _active_proxy
        with _active_proxy_lock:
            if _active_proxy is None:
                return ToolExecution(
                    output={"status": "not_running", "flows_captured": 0},
                    notices=("No proxy is running.",),
                )
            result = _active_proxy.stop()
            _active_proxy = None

        return ToolExecution(
            output=result,
            notices=(
                f"Proxy stopped. {result['flows_captured']} flows captured "
                f"across {result['endpoint_count']} endpoints. "
                f"{result['total_request_bytes'] + result['total_response_bytes']} total bytes. "
                "Use 'proxy flows' to inspect or 'network_flow_search' to query indexed traffic.",
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


class ProxyFlowsInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    limit: int = Field(default=50, ge=1, le=500)
    include_bodies: bool = False


class ProxyFlowListTool(BaseTool[ProxyFlowsInput]):
    name = "proxy_flow_list"
    description = "List captured API flows with URL, method, status, timing, and optional bodies."
    version = "1.1.0"
    input_model = ProxyFlowsInput

    def execute(self, context: ToolContext, arguments: ProxyFlowsInput) -> ToolExecution:
        global _active_proxy
        with _active_proxy_lock:
            if _active_proxy is None or not _active_proxy._running:
                return ToolExecution(
                    output={"flows": [], "count": 0, "status": "no_proxy_running"},
                    notices=("No proxy is running. Start one with proxy_start.",),
                )
            flows = _active_proxy.list_flows(limit=arguments.limit, include_bodies=arguments.include_bodies)
            endpoints = _active_proxy.get_endpoints()

        return ToolExecution(
            output={
                "flows": flows,
                "count": len(flows),
                "total_captured": len(_active_proxy.flows) if _active_proxy else 0,
                "endpoints": endpoints[:30],
                "status": "running",
            },
            notices=(
                f"Showing {len(flows)} of {len(_active_proxy.flows) if _active_proxy else 0} captured flows. "
                "Set include_bodies=true for request/response body content.",
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
        "Real-time HTTP/HTTPS traffic capture using mitmproxy Python API. "
        "Streams flows live with full body capture, auto-indexes into ChromaDB, "
        "and displays endpoint patterns. No polling delay."
    )
    version = "2.0.0"
    input_model = LiveCaptureInput

    def execute(self, context: ToolContext, arguments: LiveCaptureInput) -> ToolExecution:
        global _active_proxy

        with _active_proxy_lock:
            # Start proxy if not already running
            if _active_proxy is None or not _active_proxy._running:
                try:
                    _active_proxy = ReverserXProxyServer(
                        port=arguments.port,
                        project_id=context.project_id,
                        data_dir=context.data_dir,
                        capture_bodies=True,
                        auto_index=arguments.index_flows,
                    )
                    _active_proxy.start()
                except ProxyServerError as exc:
                    return ToolExecution(
                        output={"status": "error", "error": str(exc)},
                        notices=(f"Proxy start failed: {exc}",),
                    )
            proxy = _active_proxy

        # Capture for duration
        start_count = len(proxy.flows)
        deadline = _time.monotonic() + arguments.duration_seconds

        # Report progress periodically
        while _time.monotonic() < deadline:
            _time.sleep(5)
            current = len(proxy.flows)
            if current > start_count:
                # Got new flows
                pass

        # Collect results
        flows = proxy.list_flows(limit=500, include_bodies=False)
        endpoints = proxy.get_endpoints()

        # Index if requested (already done via auto_index, but do final batch)
        index_result: dict[str, Any] = {"indexed": 0}
        if arguments.index_flows:
            try:
                from reverserx.tools.dynamic.network_indexer import index_flows_to_chroma
                cf_list = [f.to_captured_flow() for f in proxy.flows]
                collection = f"network_flows_{context.project_id}"
                persist = str(context.data_dir / "chroma")
                index_result = index_flows_to_chroma(cf_list, collection, persist)
            except Exception as exc:
                index_result = {"error": str(exc), "indexed": 0}

        return ToolExecution(
            output={
                "status": "capturing" if proxy._running else "stopped",
                "duration": arguments.duration_seconds,
                "flows_captured": len(flows),
                "total_flows": len(proxy.flows),
                "indexed_chunks": index_result.get("indexed", 0),
                "endpoints": endpoints[:50],
                "flows": flows[:100],
                "proxy_port": arguments.port,
            },
            notices=(
                f"Real-time capture: {len(flows)} flows, {len(endpoints)} endpoints "
                f"in {arguments.duration_seconds}s. "
                f"Indexed {index_result.get('indexed', 0)} chunks into ChromaDB. "
                f"Proxy still running — use 'proxy flows' to see more, "
                f"'proxy stop' to end capture. "
                f"Search traffic: 'reverserx tool run testapp network_flow_search -a {{\"query\":\"auth\"}}'",
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
        # First try live proxy search (in-memory, instant, includes bodies)
        global _active_proxy
        live_hits: list[dict[str, Any]] = []
        with _active_proxy_lock:
            if _active_proxy is not None and _active_proxy._running:
                live_hits = _active_proxy.search_flows(arguments.query, limit=arguments.limit)

        # Also try ChromaDB for indexed historical flows
        chroma_hits: list[dict[str, Any]] = []
        try:
            from reverserx.tools.dynamic.network_indexer import search_flows
            collection = f"network_flows_{context.project_id}"
            persist = str(context.data_dir / "chroma")
            chroma_hits = search_flows(arguments.query, collection, persist, limit=arguments.limit)
        except Exception:
            pass

        # Merge: live + chroma deduplicated
        seen_urls = set()
        merged: list[dict[str, Any]] = []
        for h in live_hits:
            if h.get("url") not in seen_urls:
                seen_urls.add(h.get("url", ""))
                merged.append({**h, "source": "live"})
        for h in chroma_hits:
            meta = h.get("metadata", {})
            url = meta.get("url", "") if isinstance(meta, dict) else ""
            if url not in seen_urls:
                seen_urls.add(url)
                merged.append({**h, "source": "chroma"})

        return ToolExecution(
            output={
                "query": arguments.query,
                "hits": merged[:arguments.limit],
                "count": len(merged),
                "live_count": len(live_hits),
                "chroma_count": len(chroma_hits),
            },
            notices=(
                f"Found {len(merged)} total matches ({len(live_hits)} live, "
                f"{len(chroma_hits)} indexed). "
                "Use proxy_live_capture to capture traffic first if live is empty.",
            ),
        )
