"""Safe ADB wrapper over run_command for Android device interaction."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from reverserx.utils.subprocess import CommandLaunchError, CommandResult, run_command


class AdbError(RuntimeError):
    """Raised when an ADB command cannot complete."""


@dataclass(frozen=True, slots=True)
class AdbDevice:
    serial: str
    state: str = "unknown"
    model: str = ""
    product: str = ""
    transport_id: str = ""


def _parse_devices(output: str) -> list[AdbDevice]:
    devices: list[AdbDevice] = []
    for line in output.strip().splitlines():
        if not line.strip() or line.startswith("*") or "List of devices" in line:
            continue
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        serial = parts[0]
        state = parts[1] if len(parts) > 1 else "unknown"
        info = " ".join(parts[2:]) if len(parts) > 2 else ""
        model_match = re.search(r"model:(\S+)", info)
        product_match = re.search(r"product:(\S+)", info)
        transport_match = re.search(r"transport_id:(\S+)", info)
        devices.append(
            AdbDevice(
                serial=serial,
                state=state,
                model=model_match.group(1) if model_match else "",
                product=product_match.group(1) if product_match else "",
                transport_id=transport_match.group(1) if transport_match else "",
            )
        )
    return devices


def run_adb(
    args: tuple[str, ...],
    *,
    timeout: float = 30,
    output_limit: int = 1_000_000,
    adb_path: str = "adb",
) -> CommandResult:
    """Run an ADB command via run_command with validated args."""
    try:
        return run_command(
            (adb_path,) + args,
            timeout=timeout,
            output_limit=output_limit,
        )
    except CommandLaunchError as exc:
        raise AdbError(str(exc)) from exc


def list_devices(*, adb_path: str = "adb", timeout: float = 15) -> list[AdbDevice]:
    """List connected ADB devices with details."""
    result = run_adb(("devices", "-l"), timeout=timeout, adb_path=adb_path)
    if result.timed_out:
        raise AdbError("adb devices timed out")
    return _parse_devices(result.stdout)


def device_info(
    serial: str, *, adb_path: str = "adb", timeout: float = 15
) -> dict[str, Any]:
    """Collect diagnostics for a specific device."""
    info: dict[str, Any] = {"serial": serial, "connected": False}

    # Check connection
    result = run_adb(("-s", serial, "shell", "echo", "ok"), timeout=5, adb_path=adb_path)
    if result.returncode != 0:
        return info
    info["connected"] = True

    # Get props
    for prop, key in [
        ("ro.build.version.release", "android_version"),
        ("ro.product.cpu.abi", "abi"),
        ("ro.build.version.sdk", "sdk"),
        ("ro.debuggable", "debuggable"),
    ]:
        r = run_adb(
            ("-s", serial, "shell", "getprop", prop), timeout=timeout, adb_path=adb_path
        )
        if r.returncode == 0:
            info[key] = r.stdout.strip()

    # Check root
    r = run_adb(("-s", serial, "shell", "id"), timeout=timeout, adb_path=adb_path)
    info["root"] = "uid=0" in r.stdout if r.returncode == 0 else False

    # Installed packages
    r = run_adb(
        ("-s", serial, "shell", "pm", "list", "packages"),
        timeout=timeout,
        adb_path=adb_path,
    )
    if r.returncode == 0:
        info["packages"] = [
            line.removeprefix("package:").strip()
            for line in r.stdout.strip().splitlines()
            if line.startswith("package:")
        ]

    return info


def shell(
    serial: str,
    command: str,
    *,
    adb_path: str = "adb",
    timeout: float = 30,
    output_limit: int = 1_000_000,
) -> CommandResult:
    """Execute a shell command on a device."""
    return run_adb(
        ("-s", serial, "shell", command),
        timeout=timeout,
        output_limit=output_limit,
        adb_path=adb_path,
    )


def logcat(
    serial: str,
    package: str | None = None,
    *,
    lines: int = 10_000,
    duration_seconds: float = 300,
    adb_path: str = "adb",
) -> CommandResult:
    """Collect logcat output, optionally filtered by package."""
    args: list[str] = ["-s", serial, "logcat", "-d", "-t", str(lines)]
    if package:
        args.extend(["--pid", f"$(pidof {package})"])
    return run_adb(tuple(args), timeout=duration_seconds, adb_path=adb_path)
