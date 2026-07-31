"""Bounded subprocess execution without implicit shell interpretation."""

from __future__ import annotations

import os
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import IO


class CommandLaunchError(RuntimeError):
    """Raised when a command cannot be started."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    cancelled: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.cancelled


class _BoundedCollector:
    def __init__(self, stream: IO[bytes], limit: int) -> None:
        self._stream = stream
        self._limit = limit
        self._data = bytearray()
        self.total_bytes = 0

    def collect(self) -> None:
        while chunk := self._stream.read(65_536):
            self.total_bytes += len(chunk)
            remaining = self._limit - len(self._data)
            if remaining > 0:
                self._data.extend(chunk[:remaining])

    @property
    def text(self) -> str:
        return self._data.decode("utf-8", errors="replace")

    @property
    def truncated(self) -> bool:
        return self.total_bytes > self._limit


def run_command(
    args: Sequence[str],
    *,
    timeout: float = 60.0,
    output_limit: int = 1_000_000,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    cancel_event: threading.Event | None = None,
) -> CommandResult:
    """Execute an argument vector and continuously drain bounded output.

    ``shell`` is always disabled. Output beyond the configured limits is drained
    but discarded, preventing child-process deadlocks and unbounded memory use.
    """

    command = tuple(args)
    if not command or any(not isinstance(arg, str) or "\0" in arg for arg in command):
        raise ValueError("args must be a non-empty sequence of valid strings")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if output_limit <= 0:
        raise ValueError("output_limit must be positive")

    process_env = os.environ.copy()
    if env:
        process_env.update(env)

    started = time.monotonic()
    try:
        process = subprocess.Popen(  # noqa: S603 - validated argv, no shell
            command,
            cwd=cwd,
            env=process_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name != "nt",
        )
    except OSError as exc:
        raise CommandLaunchError(f"cannot start {command[0]!r}: {exc}") from exc

    if process.stdout is None or process.stderr is None:  # pragma: no cover
        process.kill()
        raise CommandLaunchError("subprocess output pipes were not created")

    stdout = _BoundedCollector(process.stdout, output_limit)
    stderr = _BoundedCollector(process.stderr, output_limit)
    threads = [
        threading.Thread(target=stdout.collect, daemon=True),
        threading.Thread(target=stderr.collect, daemon=True),
    ]
    for thread in threads:
        thread.start()

    deadline = started + timeout
    timed_out = False
    cancelled = False
    while process.poll() is None:
        if cancel_event is not None and cancel_event.is_set():
            cancelled = True
            _terminate_process(process)
            break
        if time.monotonic() >= deadline:
            timed_out = True
            _terminate_process(process)
            break
        time.sleep(0.02)

    try:
        returncode = process.wait(timeout=2)
    except subprocess.TimeoutExpired:  # pragma: no cover - defensive escalation
        process.kill()
        returncode = process.wait()
    for thread in threads:
        thread.join(timeout=2)

    return CommandResult(
        args=command,
        returncode=returncode,
        stdout=stdout.text,
        stderr=stderr.text,
        duration_seconds=time.monotonic() - started,
        timed_out=timed_out,
        cancelled=cancelled,
        stdout_truncated=stdout.truncated,
        stderr_truncated=stderr.truncated,
    )


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":  # pragma: no cover - exercised on Windows CI in future
        process.kill()
        return
    try:
        os.killpg(process.pid, 15)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, 9)
