"""Frida session management, script lifecycle, and live execution engine."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reverserx.utils.subprocess import CommandLaunchError, run_command


class FridaError(RuntimeError):
    """Raised when a Frida operation cannot complete."""


# --- Session registry (module-level, survives across tool calls) ---
_sessions: dict[str, FridaSessionState] = {}


def _session_key(project_id: str, package: str) -> str:
    return f"{project_id}:{package}"


# --- Frida Live Execution Engine ---


@dataclass
class FridaRunner:
    """Spawn frida CLI, collect structured events, manage lifecycle.

    Uses the frida CLI binary (not Python bindings) for simplicity and
    reliability. Parses JSON lines emitted by send() in hook scripts.
    """

    serial: str
    package: str
    script_path: Path
    project_id: str = ""
    frida_path: str = "frida"
    timeout: float = 120.0
    spawn: bool = False

    def run(self) -> list[FridaHookEvent]:
        """Execute frida CLI and return parsed events.

        Uses subprocess.Popen directly (not run_command) to stream output
        in real-time and support graceful termination.
        """
        args = [
            self.frida_path,
            "-D", self.serial,
            "-l", str(self.script_path),
        ]
        if self.spawn:
            args.extend(["-f", self.package, "--no-pause"])
        else:
            args.append(self.package)

        events: list[FridaHookEvent] = []

        try:
            process = subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                text=True,
            )
        except (OSError, FileNotFoundError) as exc:
            raise FridaError(f"cannot start frida: {exc}") from exc

        # Register session
        key = _session_key(self.project_id, self.package)
        _sessions[key] = FridaSessionState(
            serial=self.serial,
            package=self.package,
            mode="spawn" if self.spawn else "attach",
            started_at=time.time(),
        )

        # Collect output with timeout
        stdout_lines: list[str] = []
        stderr_lines: list[str] = []

        def _drain(stream: Any, into: list[str]) -> None:
            try:
                for line in stream:
                    into.append(line.rstrip("\n"))
            except (OSError, ValueError):
                pass

        t_stdout = threading.Thread(target=_drain, args=(process.stdout, stdout_lines), daemon=True)
        t_stderr = threading.Thread(target=_drain, args=(process.stderr, stderr_lines), daemon=True)
        t_stdout.start()
        t_stderr.start()

        try:
            process.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            _terminate_gracefully(process)
            _sessions[key].errors.append("frida timed out")

        t_stdout.join(timeout=2)
        t_stderr.join(timeout=2)

        # Parse events
        raw = "\n".join(stdout_lines)
        events = parse_frida_output(raw)

        # Update session state
        session = _sessions[key]
        session.events = events
        session.raw_output = raw
        session.errors.extend(stderr_lines)

        return events

    @classmethod
    def stop_session(cls, project_id: str, package: str) -> bool:
        """Attempt to clean up a running Frida session."""
        key = _session_key(project_id, package)
        session = _sessions.pop(key, None)
        if session is None:
            return False
        # Try to kill the process by package on device
        with contextlib.suppress(CommandLaunchError, FridaError):
            run_command(
                ("adb", "-s", session.serial, "shell", "am", "force-stop", package),
                timeout=5,
                output_limit=1_000,
            )
        return True


def _terminate_gracefully(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name != "nt":
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=2)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        with contextlib.suppress(OSError, ProcessLookupError):
            process.kill()


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
