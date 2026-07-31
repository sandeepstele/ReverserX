"""Host and external-tool capability discovery."""

from __future__ import annotations

import shutil
import sys
from dataclasses import asdict, dataclass
from typing import Any

from reverserx.utils.subprocess import CommandLaunchError, run_command


@dataclass(frozen=True, slots=True)
class DependencyCheck:
    name: str
    required: bool
    available: bool
    path: str | None
    version: str | None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


PROBES: tuple[tuple[str, tuple[str, ...], bool], ...] = (
    ("java", ("-version",), False),
    ("jadx", ("--version",), False),
    ("adb", ("version",), False),
    ("frida", ("--version",), False),
    ("mitmproxy", ("--version",), False),
    ("ghidraRun", ("-h",), False),
    ("ollama", ("--version",), False),
    ("git", ("--version",), True),
)


def check_dependencies() -> list[DependencyCheck]:
    checks = [
        DependencyCheck(
            name="python",
            required=True,
            available=True,
            path=sys.executable,
            version=sys.version.split()[0],
        )
    ]
    checks.extend(
        _probe(name, arguments, required) for name, arguments, required in PROBES
    )
    return checks


def _probe(name: str, arguments: tuple[str, ...], required: bool) -> DependencyCheck:
    path = shutil.which(name)
    if path is None:
        return DependencyCheck(name, required, False, None, None, "not found on PATH")
    try:
        result = run_command((path, *arguments), timeout=10, output_limit=20_000)
    except CommandLaunchError as exc:
        return DependencyCheck(name, required, False, path, None, str(exc))
    combined = "\n".join(
        part for part in (result.stdout, result.stderr) if part
    ).strip()
    version = combined.splitlines()[0] if combined else "detected"
    if result.timed_out:
        return DependencyCheck(
            name, required, False, path, None, "version probe timed out"
        )
    if result.returncode != 0:
        error = version if combined else f"version probe exited {result.returncode}"
        return DependencyCheck(name, required, False, path, None, error)
    return DependencyCheck(name, required, True, path, version)
