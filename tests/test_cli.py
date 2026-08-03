import json
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from pydantic import BaseModel
from typer.testing import CliRunner

from reverserx.config import Settings
from reverserx.context.chunking import DEFAULT_MAX_SOURCE_BYTES
from reverserx.core.models import ToolRun, ToolRunStatus
from reverserx.main import app
from reverserx.storage import Database
from reverserx.tools import BaseTool, ToolContext, ToolExecution, build_default_registry
from reverserx.tools.static.jadx import JadxOptions, JadxResult, JadxStatus

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


def _apk_bytes(*, dex: bool = True, marker: bytes = b"fixture") -> bytes:
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", b"binary-manifest")
        archive.writestr("assets/marker.bin", marker)
        if dex:
            archive.writestr("classes.dex", b"dex\n035\0" + marker)
    return output.getvalue()


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


def test_phase1_cli_imports_indexes_queries_and_reports(tmp_path: Path) -> None:
    created = runner.invoke(
        app,
        [
            "--data-dir",
            str(tmp_path),
            "project",
            "create",
            "Fixture App",
            "--package",
            "com.example.fixture",
        ],
    )
    bundle = tmp_path / "fixture-bundle"
    bundle.mkdir()
    (bundle / "base.apk").write_bytes(_apk_bytes(marker=b"base"))
    (bundle / "split_config.en.apk").write_bytes(_apk_bytes(dex=False, marker=b"split"))

    imported = runner.invoke(
        app,
        [
            "--data-dir",
            str(tmp_path),
            "--json",
            "apk",
            "import",
            "fixture-app",
            str(bundle),
        ],
    )
    assert imported.exit_code == 0, imported.output
    imported_data = json.loads(imported.output)
    base_artifact_id = imported_data["result"]["base"]["artifact_id"]
    artifacts = runner.invoke(
        app,
        [
            "--data-dir",
            str(tmp_path),
            "--json",
            "artifact",
            "list",
            "fixture-app",
        ],
    )
    metadata = runner.invoke(
        app,
        [
            "--data-dir",
            str(tmp_path),
            "apk",
            "metadata",
            "fixture-app",
            "--artifact",
            base_artifact_id,
        ],
    )

    database = Database(Settings(data_dir=tmp_path).database_path)
    project_id = database.get_project("fixture-app").id
    decoded = tmp_path / "projects" / project_id / "decoded"
    sources = decoded / "sources"
    sources.mkdir(parents=True)
    (sources / "EncryptionManager.java").write_text(
        """
        package com.example.crypto;
        public class EncryptionManager {
            public byte[] encryptRequest(byte[] payload) {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                return cipher.doFinal(payload);
            }
        }
        """,
        encoding="utf-8",
    )
    manifest = decoded / "AndroidManifest.xml"
    manifest.write_text(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.fixture">
          <uses-permission android:name="android.permission.CAMERA" />
          <application android:debuggable="false">
            <activity android:name=".MainActivity" android:exported="true" />
          </application>
        </manifest>""",
        encoding="utf-8",
    )
    base_sha256 = imported_data["result"]["base"]["apk"]["sha256"]
    jadx_result = JadxResult(
        status=JadxStatus.SUCCEEDED,
        apk_path=Path("/artifact-store/blob"),
        apk_sha256=base_sha256,
        output_dir=decoded,
        cache_key="d" * 64,
        cache_marker_path=decoded / ".reverserx-jadx-cache.json",
        jadx_version="1.5.6-test",
        options=JadxOptions(
            threads=1,
            deobfuscate=True,
            show_inconsistent_code=False,
            decode_resources=True,
        ),
        version_command=("jadx", "--version"),
        command=("jadx", "fixture.apk"),
        version_probe_duration_seconds=0,
        duration_seconds=0,
        return_code=0,
        source_file_count=1,
        resource_file_count=1,
        manifest_path=manifest,
        stdout="",
        stderr="",
        stdout_truncated=False,
        stderr_truncated=False,
    )
    database.record_tool_run(
        ToolRun(
            project_id=project_id,
            tool_name="jadx_decompile",
            tool_version="1.0.0",
            status=ToolRunStatus.SUCCEEDED,
            output_data=jadx_result.model_dump(mode="json"),
        )
    )
    analyzed = runner.invoke(
        app,
        [
            "--data-dir",
            str(tmp_path),
            "manifest",
            "analyze",
            "fixture-app",
            "--path",
            str(manifest),
        ],
    )
    indexed = runner.invoke(
        app,
        [
            "--data-dir",
            str(tmp_path),
            "source",
            "index",
            "fixture-app",
            "--root",
            str(sources),
            "--vector-backend",
            "memory",
            "--artifact",
            base_artifact_id,
        ],
    )
    searched = runner.invoke(
        app,
        [
            "--data-dir",
            str(tmp_path),
            "--json",
            "source",
            "search",
            "fixture-app",
            "Cipher.getInstance",
        ],
    )
    queried = runner.invoke(
        app,
        [
            "--data-dir",
            str(tmp_path),
            "context",
            "query",
            "fixture-app",
            "AES request encryption Cipher",
            "--budget",
            "1000",
            "--vector-backend",
            "memory",
        ],
    )
    obfuscation = runner.invoke(
        app,
        [
            "--data-dir",
            str(tmp_path),
            "obfuscation",
            "detect",
            "fixture-app",
            "--root",
            str(sources),
        ],
    )
    reported = runner.invoke(
        app,
        [
            "--data-dir",
            str(tmp_path),
            "report",
            "static",
            "fixture-app",
            "--goal",
            "Locate request encryption",
        ],
    )

    for result in (
        created,
        imported,
        artifacts,
        metadata,
        analyzed,
        indexed,
        searched,
        queried,
        obfuscation,
        reported,
    ):
        assert result.exit_code == 0, result.output
    assert "Sources indexed: 1" in indexed.output
    assert "Sources skipped: 0" in indexed.output
    assert "Oversized fallbacks: 0" in indexed.output
    assert "Index warnings: 0" in indexed.output
    assert imported_data["result"]["base"]["apk"]["name"] == "base.apk"
    assert len(imported_data["result"]["splits"]) == 1
    assert len(json.loads(artifacts.output)) == 2
    search_data = json.loads(searched.output)
    assert search_data["result"]["hits"][0]["path"] == "EncryptionManager.java"
    report_path = tmp_path / "reports" / "fixture-app" / "static-analysis.md"
    report = report_path.read_text(encoding="utf-8")
    assert "# ReverserX Static Analysis Report" in report
    assert "com.example.fixture.MainActivity" in report
    assert "EncryptionManager.java" in report


def test_source_index_cli_reports_oversized_fallback(tmp_path: Path) -> None:
    created = runner.invoke(
        app,
        ["--data-dir", str(tmp_path), "project", "create", "Fallback Fixture"],
    )
    assert created.exit_code == 0, created.output
    database = Database(tmp_path / "reverserx.sqlite3")
    project = database.get_project("fallback-fixture")
    sources = tmp_path / "projects" / project.id / "sources"
    sources.mkdir(parents=True)
    line = f"// {'x' * 180}\n"
    line_count = DEFAULT_MAX_SOURCE_BYTES // len(line.encode("utf-8")) + 2
    (sources / "Huge.java").write_text(line * line_count, encoding="utf-8")

    indexed = runner.invoke(
        app,
        [
            "--data-dir",
            str(tmp_path),
            "source",
            "index",
            project.id,
            "--root",
            str(sources),
            "--vector-backend",
            "memory",
        ],
    )

    assert indexed.exit_code == 0, indexed.output
    assert "Sources indexed: 1" in indexed.output
    assert "Sources skipped: 0" in indexed.output
    assert "Oversized fallbacks: 1" in indexed.output
    assert "Index warnings: 1" in indexed.output
    assert "Huge.java (oversized_fallback)" in indexed.output


def test_static_report_requires_an_apk_result(tmp_path: Path) -> None:
    runner.invoke(app, ["--data-dir", str(tmp_path), "project", "create", "Demo"])

    result = runner.invoke(
        app, ["--data-dir", str(tmp_path), "report", "static", "demo"]
    )

    assert result.exit_code == 1
    assert "successful APK inspection or import is required" in result.output
