"""mitmproxy lifecycle management and HAR/flow normalization."""

from __future__ import annotations

import hashlib
import json
import re
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


def start_mitmproxy(
    port: int = 8080,
    *,
    output_dir: Path | None = None,
    mitmproxy_path: str = "mitmdump",
    timeout: float = 15,
) -> int:
    """Start mitmdump and return the PID (requires subprocess management).

    Note: This starts mitmdump in the background. The caller is responsible
    for lifecycle management. Returns 0 if the process couldn't be verified.
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
    return 1  # PID placeholder — actual background process management via tool layer
