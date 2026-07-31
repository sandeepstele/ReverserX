import json
from pathlib import Path

import pytest
from pydantic import BaseModel
from typer.testing import CliRunner

from reverserx.config import Settings
from reverserx.main import app
from reverserx.storage import Database
from reverserx.tools import BaseTool, ToolContext, ToolExecution, build_default_registry

runner = CliRunner()


class CrashInput(BaseModel):
    pass


class CrashTool(BaseTool[CrashInput]):
    name = "crash"
    description = "Test unexpected tool failure persistence."
    version = "9.9.9"
    input_model = CrashInput

    def execute(self, context: ToolContext, arguments: CrashInput) -> ToolExecution:
        del context, arguments
        raise RuntimeError("controlled test failure")


def test_cli_initializes_and_manages_project(tmp_path: Path) -> None:
    initialized = runner.invoke(app, ["--data-dir", str(tmp_path), "init"])
    created = runner.invoke(
        app,
        [
            "--data-dir",
            str(tmp_path),
            "--json",
            "project",
            "create",
            "Demo App",
            "--package",
            "com.example.demo",
            "--host",
            "api.example.test",
        ],
    )
    listed = runner.invoke(
        app, ["--data-dir", str(tmp_path), "--json", "project", "list"]
    )

    assert initialized.exit_code == 0, initialized.output
    assert created.exit_code == 0, created.output
    assert listed.exit_code == 0, listed.output
    projects = json.loads(listed.output)
    assert projects[0]["slug"] == "demo-app"
    assert projects[0]["scope"]["packages"] == ["com.example.demo"]


def test_cli_imports_artifact_and_records_tool_run(tmp_path: Path) -> None:
    source = tmp_path / "fixture.apk"
    source.write_bytes(b"fixture")
    runner.invoke(app, ["--data-dir", str(tmp_path), "project", "create", "Demo"])

    imported = runner.invoke(
        app,
        ["--data-dir", str(tmp_path), "artifact", "import", "demo", str(source)],
    )
    executed = runner.invoke(
        app,
        [
            "--data-dir",
            str(tmp_path),
            "tool",
            "run",
            "demo",
            "echo",
            "--arguments",
            '{"message":"ready"}',
        ],
    )

    assert imported.exit_code == 0, imported.output
    assert executed.exit_code == 0, executed.output
    database = Database(Settings(data_dir=tmp_path).database_path)
    project = database.get_project("demo")
    runs = database.list_tool_runs(project.id)
    assert runs[0].output_data["message"] == "ready"


def test_cli_doctor_supports_json(tmp_path: Path) -> None:
    result = runner.invoke(app, ["--data-dir", str(tmp_path), "--json", "doctor"])

    assert result.exit_code == 0, result.output
    checks = json.loads(result.output)
    assert any(check["name"] == "python" for check in checks)


def test_cli_persists_unexpected_tool_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = build_default_registry()
    registry.register(CrashTool())
    monkeypatch.setattr("reverserx.main.build_default_registry", lambda: registry)
    runner.invoke(app, ["--data-dir", str(tmp_path), "project", "create", "Demo"])

    result = runner.invoke(
        app,
        ["--data-dir", str(tmp_path), "tool", "run", "demo", "crash"],
    )

    assert result.exit_code == 1
    database = Database(Settings(data_dir=tmp_path).database_path)
    project = database.get_project("demo")
    runs = database.list_tool_runs(project.id)
    assert runs[0].status == "failed"
    assert runs[0].tool_version == "9.9.9"
    assert runs[0].error == "controlled test failure"
