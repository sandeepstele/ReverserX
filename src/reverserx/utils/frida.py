"""Frida session management and script lifecycle utilities."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reverserx.utils.subprocess import CommandLaunchError, CommandResult, run_command


class FridaError(RuntimeError):
    """Raised when a Frida operation cannot complete."""


@dataclass
class FridaHookEvent:
    """A single structured event captured from a Frida hook."""

    hook_type: str  # crypto, http, intent, pinning, custom
    timestamp: float
    class_name: str = ""
    method_name: str = ""
    args: list[Any] = field(default_factory=list)
    result: Any = None
    stacktrace: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class FridaSessionState:
    serial: str
    package: str
    mode: str  # "attach" or "spawn"
    pid: int | None = None
    started_at: float = 0.0
    script_version: str = ""
    events: list[FridaHookEvent] = field(default_factory=list)
    raw_output: str = ""
    errors: list[str] = field(default_factory=list)
    disconnected: bool = False


def frida_version(*, frida_path: str = "frida", timeout: float = 10) -> str:
    """Probe the installed Frida version."""
    try:
        result = run_command((frida_path, "--version"), timeout=timeout, output_limit=1_000)
    except CommandLaunchError as exc:
        raise FridaError(str(exc)) from exc
    if result.returncode != 0:
        raise FridaError(f"frida --version failed: {result.stderr.strip()}")
    return result.stdout.strip()


def frida_ps(
    serial: str, *, frida_path: str = "frida", timeout: float = 15
) -> list[dict[str, Any]]:
    """List running processes on a device via Frida."""
    try:
        result = run_command(
            (frida_path, "-D", serial, "-R"),
            timeout=timeout,
            output_limit=500_000,
        )
        # Frida -R lists processes but returns them in a terminal UI format.
        # For structured output, use frida-ps.
        result = run_command(
            (frida_path, "-ps", "-D", serial),
            timeout=timeout,
            output_limit=500_000,
        )
    except CommandLaunchError as exc:
        raise FridaError(str(exc)) from exc
    if result.returncode != 0:
        raise FridaError(f"frida-ps failed: {result.stderr.strip()}")
    processes: list[dict[str, Any]] = []
    for line in result.stdout.strip().splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            processes.append({"pid": int(parts[0]), "name": parts[1]})
    return processes


def load_hook_script(
    hook_name: str,
    hooks_dir: Path,
    *,
    extra_code: str = "",
    target_class: str = "",
    target_method: str = "",
) -> str:
    """Load a bundled hook script by name, optionally with extra code appended.

    Hook names correspond to files in hooks_dir (without .js extension):
    crypto, pinning, http, intents, classtrace.
    """
    hook_file = hooks_dir / f"{hook_name}.js"
    if not hook_file.is_file():
        raise FridaError(f"hook script not found: {hook_file}")
    script = hook_file.read_text(encoding="utf-8")
    # Inject target class/method if provided
    if target_class and "{TARGET_CLASS}" in script:
        script = script.replace("{TARGET_CLASS}", target_class)
    if target_method and "{TARGET_METHOD}" in script:
        script = script.replace("{TARGET_METHOD}", target_method)
    if extra_code:
        script = f"{script}\n// --- user extension ---\n{extra_code}"
    return script


def compute_hook_fingerprint(script: str) -> str:
    """Return a content fingerprint for hook version tracking."""
    return hashlib.sha256(script.encode()).hexdigest()


def parse_frida_output(output: str) -> list[FridaHookEvent]:
    """Parse Frida script output lines into structured events."""
    events: list[FridaHookEvent] = []
    for line in output.strip().splitlines():
        # Frida's console.log from hook scripts should emit JSON lines
        line = line.strip()
        if not line:
            continue
        # Try to extract JSON from lines that may have Frida prefix noise
        # e.g., [Device::PID]-> {"type": "crypto", ...}
        bracket = line.rfind("}")
        if bracket == -1:
            continue
        brace = line[: bracket + 1].rfind("{")
        if brace == -1:
            continue
        try:
            data = json.loads(line[brace : bracket + 1])
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict) or "type" not in data:
            continue
        event = FridaHookEvent(
            hook_type=str(data.get("type", "custom")),
            timestamp=data.get("timestamp", time.time()),
            class_name=str(data.get("class", "")),
            method_name=str(data.get("method", "")),
            args=data.get("args", []),
            result=data.get("result"),
            stacktrace=str(data.get("stacktrace", "")),
            metadata={k: v for k, v in data.items() if k not in {
                "type", "timestamp", "class", "method", "args", "result", "stacktrace",
            }},
        )
        events.append(event)
    return events
