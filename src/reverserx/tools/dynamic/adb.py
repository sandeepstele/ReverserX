"""ADB device tools — discovery, shell, info, and logcat collection."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from reverserx.tools.base import BaseTool, EmptyInput, ToolContext, ToolExecution
from reverserx.utils.adb import (
    AdbError,
    device_info,
    list_devices,
    logcat,
    run_adb,
    shell,
)


class AdbDeviceTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")
    serial: str = Field(min_length=1, description="Device serial number")


class AdbShellInput(AdbDeviceTarget):
    command: str = Field(min_length=1, max_length=10_000)


class AdbLogcatInput(AdbDeviceTarget):
    package: str = Field(default="", description="Filter by Android package name")
    lines: int = Field(default=10_000, ge=1, le=100_000)
    timeout_seconds: float = Field(default=300, gt=0)


class AdbDeviceListTool(BaseTool[EmptyInput]):
    name = "adb_device_list"
    description = "List connected ADB devices with model, product, and transport details."
    version = "1.0.0"
    input_model = EmptyInput

    def execute(self, context: ToolContext, arguments: EmptyInput) -> ToolExecution:
        try:
            devices = list_devices()
        except AdbError as exc:
            return ToolExecution(
                output={"devices": [], "count": 0, "error": str(exc)},
                notices=(f"ADB error: {exc}",),
            )
        return ToolExecution(
            output={
                "devices": [
                    {
                        "serial": d.serial,
                        "state": d.state,
                        "model": d.model,
                        "product": d.product,
                    }
                    for d in devices
                ],
                "count": len(devices),
            }
        )


class AdbDeviceInfoTool(BaseTool[AdbDeviceTarget]):
    name = "adb_device_info"
    description = "Collect diagnostics for a specific ADB device: version, ABI, root, packages."
    version = "1.0.0"
    input_model = AdbDeviceTarget

    def execute(self, context: ToolContext, arguments: AdbDeviceTarget) -> ToolExecution:
        try:
            info = device_info(arguments.serial)
        except AdbError as exc:
            return ToolExecution(
                output={"serial": arguments.serial, "error": str(exc)},
                notices=(f"ADB error: {exc}",),
            )
        return ToolExecution(output=info)


class AdbShellTool(BaseTool[AdbShellInput]):
    name = "adb_shell"
    description = "Execute a shell command on a connected ADB device."
    version = "1.0.0"
    input_model = AdbShellInput

    def execute(self, context: ToolContext, arguments: AdbShellInput) -> ToolExecution:
        try:
            result = shell(arguments.serial, arguments.command)
        except AdbError as exc:
            return ToolExecution(
                output={"stdout": "", "stderr": str(exc), "returncode": -1, "timed_out": False},
                notices=(f"ADB error: {exc}",),
            )
        return ToolExecution(
            output={
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "timed_out": result.timed_out,
            },
            notices=(("Command timed out",) if result.timed_out else ()),
        )


class AdbLogcatTool(BaseTool[AdbLogcatInput]):
    name = "adb_logcat"
    description = "Collect logcat output filtered by package with line and time bounds."
    version = "1.0.0"
    input_model = AdbLogcatInput

    def execute(self, context: ToolContext, arguments: AdbLogcatInput) -> ToolExecution:
        try:
            result = logcat(
                arguments.serial,
                package=arguments.package if arguments.package else None,
                lines=arguments.lines,
                duration_seconds=arguments.timeout_seconds,
            )
        except AdbError as exc:
            return ToolExecution(
                output={"lines": [], "line_count": 0, "timed_out": False, "duration_seconds": 0, "error": str(exc)},
                notices=(f"ADB error: {exc}",),
            )
        lines = result.stdout.strip().splitlines()
        return ToolExecution(
            output={
                "lines": lines,
                "line_count": len(lines),
                "timed_out": result.timed_out,
                "duration_seconds": result.duration_seconds,
            },
            notices=(
                ("Logcat collection timed out",) if result.timed_out else ()
            ),
        )
