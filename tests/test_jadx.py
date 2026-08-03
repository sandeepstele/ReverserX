import json
import zipfile
from collections.abc import Sequence
from pathlib import Path

import pytest
from pydantic import ValidationError

import reverserx.tools.static.jadx as jadx_module
from reverserx.tools.base import ToolContext
from reverserx.tools.static.jadx import (
    JadxInput,
    JadxResult,
    JadxStatus,
    JadxTool,
    JadxToolError,
)
from reverserx.utils.subprocess import CommandLaunchError, CommandResult


def _write_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"binary manifest")
        archive.writestr("classes.dex", b"dex\n035\0fixture")
    return path


class SuccessfulJadx:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.decompile_calls = 0

    def __call__(self, args: Sequence[str], **_: object) -> CommandResult:
        command = tuple(args)
        self.calls.append(command)
        if command[-1] == "--version":
            return CommandResult(command, 0, "1.5.6\n", "", 0.01)

        self.decompile_calls += 1
        output_dir = Path(command[command.index("-d") + 1])
        source_dir = output_dir / "sources" / "com" / "example"
        resource_dir = output_dir / "resources" / "res" / "layout"
        source_dir.mkdir(parents=True)
        resource_dir.mkdir(parents=True)
        (source_dir / "MainActivity.java").write_text("class MainActivity {}")
        (source_dir / "Crypto.java").write_text("class Crypto {}")
        (output_dir / "resources" / "AndroidManifest.xml").write_text("<manifest />")
        (resource_dir / "main.xml").write_text("<layout />")
        return CommandResult(
            command,
            0,
            "INFO - done\nWARN - one class was inconsistent\n",
            "",
            1.25,
        )


def test_input_model_is_strict_and_forbids_unknown_fields(tmp_path: Path) -> None:
    apk = _write_apk(tmp_path / "fixture.apk")

    parsed = JadxInput.model_validate({"apk_path": str(apk), "threads": 2})

    assert parsed.apk_path == apk
    with pytest.raises(ValidationError):
        JadxInput.model_validate({"apk_path": str(apk), "threads": "2"})
    with pytest.raises(ValidationError):
        JadxInput.model_validate({"apk_path": str(apk), "unknown": True})
    with pytest.raises(ValidationError):
        JadxInput(apk_path=apk, timeout_seconds=0.5)


def test_new_result_diagnostics_are_backward_compatible() -> None:
    output_dir = Path("/runtime/projects/prj_fixture/jadx/output")
    legacy_payload = {
        "status": "succeeded",
        "apk_path": "/runtime/base.apk",
        "apk_sha256": "a" * 64,
        "output_dir": str(output_dir),
        "cache_key": "b" * 64,
        "cache_marker_path": str(output_dir / ".reverserx-jadx-cache.json"),
        "jadx_version": "1.5.6",
        "options": {
            "threads": 4,
            "deobfuscate": True,
            "show_inconsistent_code": False,
            "decode_resources": True,
        },
        "version_command": ["jadx", "--version"],
        "command": ["jadx", "/runtime/base.apk"],
        "version_probe_duration_seconds": 0.1,
        "duration_seconds": 1.0,
        "return_code": 0,
        "source_file_count": 1,
        "resource_file_count": 1,
        "manifest_path": None,
        "stdout": "",
        "stderr": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "warnings": [],
        "errors": [],
    }

    restored = JadxResult.model_validate_json(json.dumps(legacy_payload))

    assert restored.cache_hit is False
    assert restored.reported_error_count is None


def test_decompile_returns_structured_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_apk(tmp_path / "fixture.apk")
    runner = SuccessfulJadx()
    monkeypatch.setattr(jadx_module, "run_command", runner)
    context = ToolContext(project_id="prj_fixture", data_dir=tmp_path / "runtime")

    execution = JadxTool().execute(
        context,
        JadxInput(
            apk_path=apk,
            threads=3,
            deobfuscate=True,
            show_inconsistent_code=True,
        ),
    )

    output = execution.output
    project_root = (tmp_path / "runtime" / "projects" / "prj_fixture").resolve()
    output_dir = Path(output["output_dir"])
    assert output["status"] == "succeeded"
    assert output["jadx_version"] == "1.5.6"
    assert output["source_file_count"] == 2
    assert output["resource_file_count"] == 2
    assert Path(output["manifest_path"]) == (
        output_dir / "resources" / "AndroidManifest.xml"
    )
    assert Path(output["apk_path"]) == apk.resolve()
    assert len(output["apk_sha256"]) == 64
    assert len(output["cache_key"]) == 64
    assert output_dir.is_relative_to(project_root)
    assert output["command"][0] == "jadx"
    assert output["command"][-1] == str(apk.resolve())
    assert "--show-bad-code" in output["command"]
    assert execution.notices == ("WARN - one class was inconsistent",)
    assert runner.decompile_calls == 1

    marker_path = Path(output["cache_marker_path"])
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    assert marker["schema_version"] == 3
    assert marker["cache_key"] == output["cache_key"]
    assert marker["apk_sha256"] == output["apk_sha256"]
    assert marker["jadx_version"] == "1.5.6"
    assert marker["options"]["threads"] == 3
    assert marker["outcome"] == {
        "errors": [],
        "reported_error_count": None,
        "return_code": 0,
        "status": "succeeded",
        "stderr_truncated": False,
        "stdout_truncated": False,
        "warnings": ["WARN - one class was inconsistent"],
    }
    assert marker["output_snapshot"]["file_count"] == 4
    assert marker["output_snapshot"]["source_file_count"] == 2
    assert marker["output_snapshot"]["resource_file_count"] == 2
    assert marker["output_snapshot"]["manifest_relative_path"] == (
        "resources/AndroidManifest.xml"
    )
    assert len(marker["output_snapshot"]["sha256"]) == 64


def test_matching_marker_is_cached_and_force_rebuilds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_apk(tmp_path / "fixture.apk")
    runner = SuccessfulJadx()
    monkeypatch.setattr(jadx_module, "run_command", runner)
    context = ToolContext(project_id="prj_fixture", data_dir=tmp_path / "runtime")
    arguments = JadxInput(apk_path=apk)

    first = JadxTool().execute(context, arguments)
    cached = JadxTool().execute(context, arguments)

    assert first.output["cache_key"] == cached.output["cache_key"]
    assert cached.output["status"] == "cached"
    assert cached.output["cache_hit"] is True
    assert cached.output["duration_seconds"] == 0.0
    assert cached.output["return_code"] == 0
    assert cached.output["warnings"] == ["WARN - one class was inconsistent"]
    assert cached.output["errors"] == []
    assert cached.notices == ("WARN - one class was inconsistent",)
    assert runner.decompile_calls == 1

    forced = JadxTool().execute(context, arguments.model_copy(update={"force": True}))

    assert forced.output["status"] == "succeeded"
    assert forced.output["cache_key"] == first.output["cache_key"]
    assert runner.decompile_calls == 2


@pytest.mark.parametrize("damage", ["delete", "same-size-corruption"])
def test_cache_reuse_rejects_missing_or_corrupt_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    damage: str,
) -> None:
    apk = _write_apk(tmp_path / "fixture.apk")
    runner = SuccessfulJadx()
    monkeypatch.setattr(jadx_module, "run_command", runner)
    context = ToolContext(project_id="prj_fixture", data_dir=tmp_path / "runtime")
    arguments = JadxInput(apk_path=apk)
    first = JadxTool().execute(context, arguments)
    source = (
        Path(first.output["output_dir"]) / "sources" / "com" / "example" / "Crypto.java"
    )
    if damage == "delete":
        source.unlink()
    else:
        original = source.read_text(encoding="utf-8")
        source.write_text(original.replace("Crypto", "Xrypto"), encoding="utf-8")
        assert source.stat().st_size == len(original.encode("utf-8"))

    with pytest.raises(JadxToolError, match="failed integrity validation"):
        JadxTool().execute(context, arguments)

    assert runner.decompile_calls == 1
    rebuilt = JadxTool().execute(
        context,
        arguments.model_copy(update={"force": True}),
    )
    assert rebuilt.output["status"] == "succeeded"
    assert runner.decompile_calls == 2


def test_output_must_stay_inside_project_area(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_apk(tmp_path / "fixture.apk")
    runner = SuccessfulJadx()
    monkeypatch.setattr(jadx_module, "run_command", runner)
    context = ToolContext(project_id="prj_fixture", data_dir=tmp_path / "runtime")

    with pytest.raises(JadxToolError, match="inside the project area"):
        JadxTool().execute(
            context,
            JadxInput(apk_path=apk, output_dir=tmp_path / "outside"),
        )

    assert runner.calls == []


def test_existing_uncached_output_requires_force(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_apk(tmp_path / "fixture.apk")
    runner = SuccessfulJadx()
    monkeypatch.setattr(jadx_module, "run_command", runner)
    context = ToolContext(project_id="prj_fixture", data_dir=tmp_path / "runtime")
    output_dir = tmp_path / "runtime" / "projects" / "prj_fixture" / "chosen"
    output_dir.mkdir(parents=True)

    with pytest.raises(JadxToolError, match="already exists"):
        JadxTool().execute(
            context,
            JadxInput(apk_path=apk, output_dir=Path("chosen")),
        )

    assert runner.decompile_calls == 0


def test_malformed_input_is_rejected_without_starting_jadx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    malformed = tmp_path / "bad.apk"
    malformed.write_bytes(b"not a ZIP")
    runner = SuccessfulJadx()
    monkeypatch.setattr(jadx_module, "run_command", runner)
    context = ToolContext(project_id="prj_fixture", data_dir=tmp_path / "runtime")

    with pytest.raises(JadxToolError, match="not a readable APK ZIP"):
        JadxTool().execute(context, JadxInput(apk_path=malformed))

    assert runner.calls == []


def test_process_failure_exposes_structured_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_apk(tmp_path / "fixture.apk")

    def failed_runner(args: Sequence[str], **_: object) -> CommandResult:
        command = tuple(args)
        if command[-1] == "--version":
            return CommandResult(command, 0, "1.5.6\n", "", 0.01)
        return CommandResult(
            command,
            1,
            "",
            "ERROR - failed to decode classes.dex\n",
            0.25,
        )

    monkeypatch.setattr(jadx_module, "run_command", failed_runner)
    context = ToolContext(project_id="prj_fixture", data_dir=tmp_path / "runtime")

    with pytest.raises(JadxToolError, match="failed to decode") as raised:
        JadxTool().execute(context, JadxInput(apk_path=apk, allow_partial=True))

    result = raised.value.result
    assert result is not None
    assert result.status is JadxStatus.FAILED
    assert result.return_code == 1
    assert result.source_file_count == 0
    assert result.errors == ("ERROR - failed to decode classes.dex",)
    assert not result.cache_marker_path.exists()


def test_explicit_partial_mode_accepts_usable_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_apk(tmp_path / "fixture.apk")
    successful = SuccessfulJadx()

    def partial_runner(args: Sequence[str], **kwargs: object) -> CommandResult:
        completed = successful(args, **kwargs)
        if tuple(args)[-1] == "--version":
            return completed
        return CommandResult(
            completed.args,
            3,
            completed.stdout,
            "ERROR - finished with errors, count: 2\n",
            completed.duration_seconds,
        )

    monkeypatch.setattr(jadx_module, "run_command", partial_runner)
    context = ToolContext(project_id="prj_fixture", data_dir=tmp_path / "runtime")

    arguments = JadxInput(
        apk_path=apk,
        allow_partial=True,
        show_inconsistent_code=True,
    )
    execution = JadxTool().execute(context, arguments)

    assert execution.output["status"] == "partial"
    assert execution.output["cache_hit"] is False
    assert execution.output["return_code"] == 3
    assert execution.output["source_file_count"] == 2
    assert execution.output["manifest_path"] is not None
    assert execution.output["errors"] == ["ERROR - finished with errors, count: 2"]
    assert execution.output["reported_error_count"] == 2
    assert any("partial output" in notice for notice in execution.notices)
    marker_path = Path(execution.output["cache_marker_path"])
    assert marker_path.is_file()
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    assert marker["outcome"]["status"] == "partial"
    assert marker["outcome"]["return_code"] == 3
    assert marker["outcome"]["reported_error_count"] == 2

    cached = JadxTool().execute(context, arguments)

    assert cached.output["status"] == "partial"
    assert cached.output["cache_hit"] is True
    assert cached.output["return_code"] == 3
    assert cached.output["reported_error_count"] == 2
    assert cached.output["warnings"] == execution.output["warnings"]
    assert cached.output["errors"] == execution.output["errors"]
    assert cached.notices == execution.notices
    assert successful.decompile_calls == 1

    with pytest.raises(JadxToolError, match="cached JADX output is partial") as raised:
        JadxTool().execute(
            context,
            arguments.model_copy(update={"allow_partial": False}),
        )

    rejected = raised.value.result
    assert rejected is not None
    assert rejected.status is JadxStatus.PARTIAL
    assert rejected.cache_hit is True
    assert rejected.return_code == 3
    assert rejected.reported_error_count == 2
    assert rejected.warnings == tuple(execution.output["warnings"])
    assert rejected.errors == tuple(execution.output["errors"])
    assert successful.decompile_calls == 1


def test_output_affecting_show_bad_code_option_has_a_distinct_cache_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_apk(tmp_path / "fixture.apk")
    runner = SuccessfulJadx()
    monkeypatch.setattr(jadx_module, "run_command", runner)
    context = ToolContext(project_id="prj_fixture", data_dir=tmp_path / "runtime")

    regular = JadxTool().execute(context, JadxInput(apk_path=apk))
    bad_code = JadxTool().execute(
        context,
        JadxInput(apk_path=apk, show_inconsistent_code=True),
    )

    assert regular.output["cache_key"] != bad_code.output["cache_key"]
    assert regular.output["output_dir"] != bad_code.output["output_dir"]
    assert "--show-bad-code" not in regular.output["command"]
    assert "--show-bad-code" in bad_code.output["command"]
    assert runner.decompile_calls == 2


def test_timeout_is_an_explicit_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_apk(tmp_path / "fixture.apk")

    def timed_out_runner(args: Sequence[str], **_: object) -> CommandResult:
        command = tuple(args)
        if command[-1] == "--version":
            return CommandResult(command, 0, "1.5.6\n", "", 0.01)
        return CommandResult(
            command,
            -15,
            "",
            "",
            1.0,
            timed_out=True,
        )

    monkeypatch.setattr(jadx_module, "run_command", timed_out_runner)
    context = ToolContext(project_id="prj_fixture", data_dir=tmp_path / "runtime")

    with pytest.raises(JadxToolError, match="timed out") as raised:
        JadxTool().execute(context, JadxInput(apk_path=apk))

    assert raised.value.result is not None
    assert raised.value.result.status is JadxStatus.TIMED_OUT


def test_missing_jadx_exposes_version_probe_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _write_apk(tmp_path / "fixture.apk")

    def missing_runner(args: Sequence[str], **_: object) -> CommandResult:
        raise CommandLaunchError(f"cannot start {args[0]!r}")

    monkeypatch.setattr(jadx_module, "run_command", missing_runner)
    context = ToolContext(project_id="prj_fixture", data_dir=tmp_path / "runtime")

    with pytest.raises(JadxToolError, match="cannot start") as raised:
        JadxTool().execute(context, JadxInput(apk_path=apk))

    assert raised.value.result is not None
    assert raised.value.result.status is JadxStatus.FAILED
    assert raised.value.result.jadx_version == "unknown"
