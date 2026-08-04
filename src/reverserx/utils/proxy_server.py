"""Real-time HTTP/HTTPS proxy server using mitmdump with inline addon.

Spawns mitmdump as a subprocess with a Python addon that streams JSON flow
events to stdout. No asyncio wrangling — uses the stable mitmdump CLI with
`--scripts` to inject our capture addon.

Provides live flow streaming, full body capture, and auto-indexing into
ChromaDB.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reverserx.utils.proxy import CapturedFlow, normalize_url, redact_secrets


class ProxyServerError(RuntimeError):
    """Raised when the proxy server cannot start."""


@dataclass
class LiveFlow:
    """A captured HTTP flow with full body content."""

    id: str
    url: str
    method: str = ""
    status: int = 0
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_body: str = ""
    request_size: int = 0
    response_size: int = 0
    duration_ms: int = 0
    timestamp: float = 0.0
    host: str = ""
    path: str = ""
    is_websocket: bool = False

    @property
    def normalized_url(self) -> str:
        return normalize_url(self.url)

    def to_dict(self, *, include_bodies: bool = False, max_body: int = 4_000) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "url": self.url,
            "normalized_url": self.normalized_url,
            "method": self.method,
            "status": self.status,
            "host": self.host,
            "path": self.path,
            "duration_ms": self.duration_ms,
            "request_headers": redact_secrets(self.request_headers),
            "response_headers": redact_secrets(self.response_headers),
            "request_size": self.request_size,
            "response_size": self.response_size,
            "timestamp": self.timestamp,
        }
        if include_bodies:
            d["request_body"] = self.request_body[:max_body]
            d["response_body"] = self.response_body[:max_body]
        return d

    def to_captured_flow(self) -> CapturedFlow:
        return CapturedFlow(
            id=self.id,
            url=self.url,
            method=self.method,
            status=self.status,
            request_headers=redact_secrets(self.request_headers),
            response_headers=redact_secrets(self.response_headers),
            request_body_hash=hashlib.sha256(self.request_body.encode(errors="replace")).hexdigest() if self.request_body else "",
            response_body_hash=hashlib.sha256(self.response_body.encode(errors="replace")).hexdigest() if self.response_body else "",
            request_size=self.request_size,
            response_size=self.response_size,
            duration_ms=self.duration_ms,
            timestamp=self.timestamp,
        )


# Inline mitmproxy addon written as a Python script string.
# This is written to a temp file and loaded via mitmdump --scripts.
_FLOW_CAPTURE_SCRIPT = '''
import json
import sys
import hashlib
import time

from mitmproxy import http

class ReverserXCapture:
    """Streams captured HTTP flows as JSON lines to stdout."""

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            req = flow.request
            resp = flow.response
            if req is None or resp is None:
                return

            req_body = ""
            if req.content:
                try:
                    req_body = req.content.decode("utf-8", errors="replace")[:10000]
                except Exception:
                    req_body = ""

            resp_body = ""
            if resp.content:
                try:
                    resp_body = resp.content.decode("utf-8", errors="replace")[:10000]
                except Exception:
                    resp_body = ""

            duration = 0
            if resp.timestamp_end and req.timestamp_start:
                duration = int((resp.timestamp_end - req.timestamp_start) * 1000)

            event = {
                "type": "flow",
                "id": "flow_" + hashlib.sha256(f"{req.url}:{time.time()}".encode()).hexdigest()[:16],
                "url": req.pretty_url or req.url,
                "method": req.method,
                "status": resp.status_code,
                "host": req.host or "",
                "path": req.path or "",
                "request_headers": dict(req.headers),
                "response_headers": dict(resp.headers),
                "request_body": req_body[:5000],
                "response_body": resp_body[:5000],
                "request_size": len(req.content) if req.content else 0,
                "response_size": len(resp.content) if resp.content else 0,
                "duration_ms": duration,
                "timestamp": time.time(),
            }
            # Write JSON line — this goes to mitmdump stdout which we capture
            print("REVERSERX_FLOW:" + json.dumps(event), flush=True)
        except Exception:
            pass

addons = [ReverserXCapture()]
'''


class ReverserXProxyServer:
    """Real-time mitmproxy capture via mitmdump subprocess with inline addon.

    Spawns mitmdump with a Python addon that emits JSON flow events.
    Parses the streaming output to populate LiveFlow objects.
    """

    def __init__(
        self,
        port: int = 8080,
        *,
        project_id: str = "",
        data_dir: Path | None = None,
        capture_bodies: bool = True,
        auto_index: bool = False,
        on_flow: Callable[[LiveFlow], None] | None = None,
    ) -> None:
        self.port = port
        self.project_id = project_id
        self.data_dir = data_dir or Path("/tmp/reverserx-proxy")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.capture_bodies = capture_bodies
        self.auto_index = auto_index

        self.flows: list[LiveFlow] = []
        self._errors: list[str] = []
        self._lock = threading.Lock()
        self._running = False
        self._process: subprocess.Popen[Any] | None = None
        self._thread: threading.Thread | None = None
        self._script_path: Path | None = None
        self._external_callback = on_flow

    def start(self) -> None:
        """Start mitmdump with the capture addon."""
        if self._running:
            return

        # Verify mitmdump is available
        try:
            result = subprocess.run(
                ["mitmdump", "--version"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                raise ProxyServerError(f"mitmdump not available: {result.stderr.strip()}")
        except FileNotFoundError as exc:
            raise ProxyServerError("mitmdump not found. Install: pip install mitmproxy") from exc
        except subprocess.TimeoutExpired as exc:
            raise ProxyServerError("mitmdump --version timed out") from exc

        # Write the addon script to a temp file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", prefix="reverserx_addon_", delete=False
        ) as f:
            f.write(_FLOW_CAPTURE_SCRIPT)
            self._script_path = Path(f.name)

        # Start mitmdump
        args = [
            "mitmdump",
            "--listen-port", str(self.port),
            "--listen-host", "127.0.0.1",
            "--scripts", str(self._script_path),
            "--quiet",
        ]

        try:
            self._process = subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                text=True,
                bufsize=1,  # Line buffered for real-time streaming
            )
        except (OSError, FileNotFoundError) as exc:
            if self._script_path and self._script_path.exists():
                self._script_path.unlink()
            raise ProxyServerError(f"cannot start mitmdump: {exc}") from exc

        self._running = True

        # Start stdout reader thread
        self._thread = threading.Thread(target=self._read_stdout, daemon=True)
        self._thread.start()

        # Brief wait for startup
        time.sleep(1)
        if self._process.poll() is not None:
            stderr = ""
            with contextlib.suppress(Exception):
                stderr = self._process.stderr.read() if self._process.stderr else ""
            self._running = False
            raise ProxyServerError(f"mitmdump exited immediately: {stderr[:500]}")

    def _read_stdout(self) -> None:
        """Read mitmdump stdout, parse JSON flow events."""
        if self._process is None or self._process.stdout is None:
            return
        try:
            for line in self._process.stdout:
                line = line.strip()
                if not line.startswith("REVERSERX_FLOW:"):
                    continue
                try:
                    data = json.loads(line[len("REVERSERX_FLOW:"):])
                    live = LiveFlow(
                        id=data.get("id", ""),
                        url=data.get("url", ""),
                        method=data.get("method", ""),
                        status=data.get("status", 0),
                        request_headers=data.get("request_headers", {}),
                        response_headers=data.get("response_headers", {}),
                        request_body=data.get("request_body", ""),
                        response_body=data.get("response_body", ""),
                        request_size=data.get("request_size", 0),
                        response_size=data.get("response_size", 0),
                        duration_ms=data.get("duration_ms", 0),
                        timestamp=data.get("timestamp", time.time()),
                        host=data.get("host", ""),
                        path=data.get("path", ""),
                    )
                    with self._lock:
                        self.flows.append(live)
                    if self._external_callback:
                        with contextlib.suppress(Exception):
                            self._external_callback(live)
                    if self.auto_index and self.project_id and self.data_dir:
                        self._auto_index_flow(live)
                except (json.JSONDecodeError, KeyError):
                    pass
        except (OSError, ValueError):
            pass

    def _auto_index_flow(self, flow: LiveFlow) -> None:
        try:
            from reverserx.tools.dynamic.network_indexer import index_flows_to_chroma
            cf = flow.to_captured_flow()
            index_flows_to_chroma(
                [cf],
                f"network_flows_{self.project_id}",
                str(self.data_dir / "chroma"),
            )
        except Exception:
            pass

    def stop(self) -> dict[str, Any]:
        """Stop mitmdump and return captured flow summary."""
        self._running = False

        if self._process and self._process.poll() is None:
            try:
                os.killpg(os.getpgid(self._process.pid), signal.SIGTERM)
                self._process.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    self._process.kill()
                    self._process.wait(timeout=2)
                except (OSError, ProcessLookupError):
                    pass

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

        # Clean up temp addon script
        if self._script_path and self._script_path.exists():
            with contextlib.suppress(OSError):
                self._script_path.unlink()

        with self._lock:
            flows = list(self.flows)

        from reverserx.utils.proxy import group_endpoints
        endpoints = group_endpoints([f.to_captured_flow() for f in flows])

        return {
            "status": "stopped",
            "port": self.port,
            "flows_captured": len(flows),
            "endpoints": [
                {"pattern": e.pattern, "method": e.method, "host": e.host, "count": e.flow_count}
                for e in endpoints[:50]
            ],
            "endpoint_count": len(endpoints),
            "total_request_bytes": sum(f.request_size for f in flows),
            "total_response_bytes": sum(f.response_size for f in flows),
        }

    def list_flows(self, *, limit: int = 100, include_bodies: bool = False) -> list[dict[str, Any]]:
        with self._lock:
            flows = list(self.flows[-limit:])
        return [f.to_dict(include_bodies=include_bodies) for f in flows]

    def get_endpoints(self) -> list[dict[str, Any]]:
        with self._lock:
            flows = list(self.flows)
        from reverserx.utils.proxy import group_endpoints
        endpoints = group_endpoints([f.to_captured_flow() for f in flows])
        return [
            {"pattern": e.pattern, "method": e.method, "host": e.host, "count": e.flow_count}
            for e in endpoints
        ]

    def search_flows(self, query: str, *, limit: int = 20) -> list[dict[str, Any]]:
        q = query.lower()
        matches: list[dict[str, Any]] = []
        with self._lock:
            for f in self.flows:
                if q in f.url.lower() or q in f.host.lower() or q in f.request_body.lower() or q in f.response_body.lower():
                    matches.append(f.to_dict(include_bodies=True))
                    if len(matches) >= limit:
                        break
        return matches
