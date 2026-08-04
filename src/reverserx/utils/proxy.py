"""mitmproxy lifecycle management and HAR/flow normalization."""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess as _subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reverserx.utils.subprocess import CommandLaunchError, CommandResult, run_command


class ProxyError(RuntimeError):
    """Raised when a proxy operation cannot complete."""


_SECRET_HEADERS = frozenset({
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
})


@dataclass
class NormalizedEndpoint:
    """An API endpoint pattern with variable path segments collapsed."""

    pattern: str  # e.g. /api/v1/users/{id}/posts/{post_id}
    method: str = ""
    host: str = ""
    flow_count: int = 0
    raw_urls: list[str] = field(default_factory=list)


@dataclass
class CapturedFlow:
    """One captured HTTP request/response pair."""

    id: str
    url: str
    method: str = ""
    status: int = 0
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    request_body_hash: str = ""
    response_body_hash: str = ""
    request_size: int = 0
    response_size: int = 0
    duration_ms: int = 0
    timestamp: float = 0.0


def redact_secrets(headers: dict[str, str]) -> dict[str, str]:
    """Return headers with secret values replaced by content hashes."""
    redacted: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in _SECRET_HEADERS:
            redacted[name] = f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"
        else:
            redacted[name] = value
    return redacted


def normalize_url(url: str) -> str:
    """Collapse variable path segments into {variable} placeholders.

    /api/v1/users/123/posts/456 → /api/v1/users/{id}/posts/{id}
    """
    parts = url.split("/")
    normalized: list[str] = []
    for part in parts:
        # UUIDs
        if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", part):
            normalized.append("{uuid}")
        # Numeric IDs
        elif re.match(r"^\d+$", part):
            normalized.append("{id}")
        # Short hex strings (tokens)
        elif re.match(r"^[0-9a-f]{16,}$", part):
            normalized.append("{token}")
        else:
            normalized.append(part)
    return "/".join(normalized)


def group_endpoints(flows: list[CapturedFlow]) -> list[NormalizedEndpoint]:
    """Group captured flows by normalized endpoint pattern."""
    groups: dict[tuple[str, str, str], NormalizedEndpoint] = {}
    for flow in flows:
        pattern = normalize_url(flow.url)
        key = (pattern, flow.method, extract_host(flow.url))
        if key not in groups:
            groups[key] = NormalizedEndpoint(
                pattern=pattern, method=flow.method, host=key[2]
            )
        groups[key].flow_count += 1
        groups[key].raw_urls.append(flow.url)
    return sorted(groups.values(), key=lambda e: e.flow_count, reverse=True)


def extract_host(url: str) -> str:
    """Extract the host from a URL."""
    match = re.match(r"https?://([^/:]+)", url)
    return match.group(1) if match else ""


def parse_har(har_path: Path) -> list[CapturedFlow]:
    """Parse a HAR file into CapturedFlow records."""
    data = json.loads(har_path.read_text(encoding="utf-8"))
    entries = data.get("log", {}).get("entries", [])
    flows: list[CapturedFlow] = []
    for entry in entries:
        request = entry.get("request", {})
        response = entry.get("response", {})
        url = request.get("url", "")
        req_body = ""
        if request.get("postData", {}).get("text"):
            req_body = request["postData"]["text"]
        resp_body = ""
        content = response.get("content", {})
        if content.get("text"):
            resp_body = content["text"]
        flows.append(
            CapturedFlow(
                id=f"har_{hashlib.sha256(url.encode()).hexdigest()[:12]}",
                url=url,
                method=request.get("method", "GET"),
                status=response.get("status", 0),
                request_headers=redact_secrets(
                    {h["name"]: h["value"] for h in request.get("headers", [])}
                ),
                response_headers=redact_secrets(
                    {h["name"]: h["value"] for h in response.get("headers", [])}
                ),
                request_body_hash=hashlib.sha256(req_body.encode()).hexdigest() if req_body else "",
                response_body_hash=hashlib.sha256(resp_body.encode()).hexdigest() if resp_body else "",
                request_size=request.get("bodySize", 0),
                response_size=response.get("bodySize", 0),
                duration_ms=entry.get("time", 0),
                timestamp=time.time(),
            )
        )
    return flows


# --- Background mitmdump process registry ---
_proxy_processes: dict[str, _subprocess.Popen[Any]] = {}


def start_mitmproxy(
    port: int = 8080,
    *,
    output_dir: Path | None = None,
    mitmproxy_path: str = "mitmdump",
    timeout: float = 15,
) -> dict[str, Any]:
    """Start mitmdump as a background process for live traffic capture.

    Returns process metadata including PID, port, and HAR output path.
    Uses subprocess.Popen directly for background execution.
    """
    # Probe that mitmdump is available
    try:
        result = run_command(
            (mitmproxy_path, "--version"),
            timeout=timeout,
            output_limit=10_000,
        )
    except CommandLaunchError as exc:
        raise ProxyError(str(exc)) from exc
    if result.returncode != 0:
        raise ProxyError(f"mitmdump not available: {result.stderr.strip()}")

    capture_dir = output_dir or Path(tempfile.gettempdir()) / "reverserx-captures"
    capture_dir.mkdir(parents=True, exist_ok=True)
    har_path = capture_dir / f"capture-{int(time.time())}.har"

    args: list[str] = [
        mitmproxy_path,
        "--listen-port", str(port),
        "--set", f"hardump={har_path}",
        "--quiet",
    ]

    try:
        process = _subprocess.Popen(
            args,
            stdin=_subprocess.DEVNULL,
            stdout=_subprocess.PIPE,
            stderr=_subprocess.PIPE,
            start_new_session=True,
        )
    except (OSError, FileNotFoundError) as exc:
        raise ProxyError(f"cannot start mitmdump: {exc}") from exc

    key = str(port)
    _proxy_processes[key] = process

    # Brief wait to confirm startup
    time.sleep(0.5)
    if process.poll() is not None:
        stderr = ""
        try:
            stderr = (process.stderr.read() if process.stderr else b"").decode(errors="replace")
        except Exception:
            pass
        raise ProxyError(f"mitmdump exited immediately (port {port} in use?): {stderr[:500]}")

    return {
        "pid": process.pid or 0,
        "port": port,
        "har_path": str(har_path),
        "status": "running",
        "proxy_url": f"http://127.0.0.1:{port}",
    }


def stop_mitmproxy(port: int = 8080, *, timeout: float = 10) -> dict[str, Any]:
    """Stop a running mitmdump process and collect the HAR output."""
    key = str(port)
    process = _proxy_processes.pop(key, None)
    if process is None:
        return {"status": "not_running", "port": port, "flows": 0}

    # Graceful termination
    try:
        if os.name != "nt" and process.pid:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=timeout)
    except (ProcessLookupError, _subprocess.TimeoutExpired):
        try:
            process.kill()
            process.wait(timeout=2)
        except (OSError, ProcessLookupError):
            pass

    return {"status": "stopped", "port": port, "pid": process.pid}


def proxy_status(port: int = 8080) -> dict[str, Any]:
    """Check if mitmdump is running on the given port."""
    key = str(port)
    process = _proxy_processes.get(key)
    if process is None:
        return {"status": "not_running", "port": port}
    if process.poll() is not None:
        del _proxy_processes[key]
        return {"status": "exited", "port": port, "returncode": process.returncode}
    return {"status": "running", "port": port, "pid": process.pid}
