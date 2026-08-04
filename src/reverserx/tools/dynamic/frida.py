"""Frida dynamic instrumentation tools — process listing, script loading."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from reverserx.tools.base import BaseTool, EmptyInput, ToolContext, ToolExecution
from reverserx.utils.frida import (
    FridaError,
    frida_ps,
    frida_version,
    load_hook_script,
    parse_frida_output,
)


class FridaDeviceTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")
    serial: str = Field(min_length=1, description="Device serial number")


class FridaInjectInput(FridaDeviceTarget):
    package: str = Field(min_length=1, description="Android package name")
    hook_name: str = Field(
        default="crypto",
        description="Instrumentation script: crypto, pinning, http, intents",
    )
    target_class: str = Field(default="", description="Optional class to target")
    target_method: str = Field(default="", description="Optional method to target")
    extra_code: str = Field(default="", description="Additional JavaScript to append")
    timeout_seconds: float = Field(default=120, gt=0)
    spawn: bool = Field(default=False, description="Spawn the app instead of attaching")


class FridaPsTool(BaseTool[FridaDeviceTarget]):
    name = "frida_ps"
    description = "List running processes on an authorized device via Frida."
    version = "1.0.0"
    input_model = FridaDeviceTarget

    def execute(self, context: ToolContext, arguments: FridaDeviceTarget) -> ToolExecution:
        try:
            version = frida_version()
            processes = frida_ps(arguments.serial)
        except FridaError as exc:
            return ToolExecution(
                output={"processes": [], "error": str(exc)},
                notices=(f"Frida error: {exc}",),
            )
        return ToolExecution(
            output={
                "frida_version": version,
                "processes": processes,
                "count": len(processes),
            }
        )


class FridaHookListTool(BaseTool[EmptyInput]):
    name = "frida_hook_list"
    description = "List available Frida instrumentation scripts for authorized analysis."
    version = "1.0.0"
    input_model = EmptyInput

    def execute(self, context: ToolContext, arguments: EmptyInput) -> ToolExecution:
        hooks_dir = Path(__file__).resolve().parent / "hooks"
        hooks: list[dict[str, str]] = []
        for hook_file in sorted(hooks_dir.glob("*.js")):
            name = hook_file.stem
            desc = ""
            first_line = ""
            try:
                first_line = hook_file.read_text(encoding="utf-8").split("\n")[0]
                if first_line.startswith("//"):
                    desc = first_line.lstrip("/ ").strip()
            except (OSError, UnicodeDecodeError):
                pass
            hooks.append({"name": name, "description": desc, "path": str(hook_file)})
        return ToolExecution(output={"hooks": hooks, "count": len(hooks)})


class FridaInjectTool(BaseTool[FridaInjectInput]):
    name = "frida_inject"
    description = "Load a Frida instrumentation script for an authorized app process."
    version = "1.0.0"
    input_model = FridaInjectInput

    def execute(self, context: ToolContext, arguments: FridaInjectInput) -> ToolExecution:
        hooks_dir = Path(__file__).resolve().parent / "hooks"
        try:
            script = load_hook_script(
                arguments.hook_name,
                hooks_dir,
                extra_code=arguments.extra_code,
                target_class=arguments.target_class,
                target_method=arguments.target_method,
            )
        except FridaError as exc:
            return ToolExecution(
                output={"error": str(exc)},
                notices=(f"Hook load error: {exc}",),
            )

        # In a real Frida session, the script would be injected via frida CLI
        # or the Frida Python bindings. For the MVP, we return the script
        # ready for injection and document the command.
        from reverserx.utils.frida import compute_hook_fingerprint

        mode = "spawn" if arguments.spawn else "attach"
        command = (
            f"frida -D {arguments.serial} -l {hooks_dir / arguments.hook_name}.js "
            f"-f {arguments.package}" if arguments.spawn else
            f"frida -D {arguments.serial} -l {hooks_dir / arguments.hook_name}.js "
            f"{arguments.package}"
        )

        return ToolExecution(
            output={
                "hook_name": arguments.hook_name,
                "package": arguments.package,
                "mode": mode,
                "fingerprint": compute_hook_fingerprint(script),
                "script_preview": script[:5000],
                "suggested_command": command,
                "device_serial": arguments.serial,
            },
            notices=(
                "Frida injection requires a running frida-server on the device. "
                "Run this tool inside an agent session for automated injection. "
                "The returned script_preview is for review before execution.",
            ),
        )
