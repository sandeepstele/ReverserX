from __future__ import annotations

import io
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from pydantic import ValidationError

from reverserx.core.models import Project
from reverserx.storage.database import Database
from reverserx.storage.files import ArtifactStore
from reverserx.tools.base import ToolContext
from reverserx.tools.static.apk import ApkInspectionError, ApkRole
from reverserx.tools.static.bundle import (
    ApkBundleImportInput,
    ApkBundleImportTool,
    import_android_package,
)


def _apk_bytes(*, dex: bool = True, marker: bytes = b"fixture") -> bytes:
    output = io.BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", b"binary-manifest")
        archive.writestr("assets/fixture-marker.bin", marker)
        if dex:
            archive.writestr("classes.dex", b"dex\n035\x00" + marker)
    return output.getvalue()


def _write_zip(path: Path, members: list[tuple[str, bytes]]) -> None:
    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        for name, value in members:
            archive.writestr(name, value)


@pytest.fixture
def persistence(tmp_path: Path) -> tuple[Project, Database, ArtifactStore]:
    database = Database(tmp_path / "state.sqlite3")
    database.initialize()
    project = database.create_project(Project(slug="fixture", name="Fixture"))
    store = ArtifactStore(tmp_path / "artifacts")
    return project, database, store


def test_imports_standalone_apk_and_persists_it(
    tmp_path: Path,
    persistence: tuple[Project, Database, ArtifactStore],
) -> None:
    project, database, store = persistence
    source = tmp_path / "application.apk"
    content = _apk_bytes()
    source.write_bytes(content)

    result = import_android_package(
        source,
        project_id=project.id,
        artifact_store=store,
        database=database,
    )

    assert result.project_id == project.id
    assert result.base.apk.role is ApkRole.BASE
    assert result.base.artifact_id == result.base.artifact.id
    assert result.base.artifact.original_name == "application.apk"
    assert result.base.artifact.media_type == "application/vnd.android.package-archive"
    assert store.resolve(result.base.artifact).read_bytes() == content
    assert (
        database.get_artifact(project.id, result.base.artifact_id)
        == result.base.artifact
    )
    assert result.artifact_ids == (result.base.artifact_id,)


def test_imports_only_selected_apks_from_archive(
    tmp_path: Path,
    persistence: tuple[Project, Database, ArtifactStore],
) -> None:
    project, database, store = persistence
    source = tmp_path / "application.apkm"
    base = _apk_bytes(marker=b"base")
    split_b = _apk_bytes(dex=False, marker=b"b")
    split_a = _apk_bytes(dex=False, marker=b"a")
    _write_zip(
        source,
        [
            ("splits/z.apk", split_b),
            ("icon.png", b"not-imported"),
            ("base.apk", base),
            ("splits/a.apk", split_a),
        ],
    )

    result = import_android_package(
        source,
        project_id=project.id,
        artifact_store=store,
        database=database,
    )

    assert result.base.apk.name == "base.apk"
    assert [item.apk.name for item in result.splits] == [
        "splits/a.apk",
        "splits/z.apk",
    ]
    assert [item.artifact.original_name for item in result.all_imports] == [
        "base.apk",
        "splits/a.apk",
        "splits/z.apk",
    ]
    assert len(database.list_artifacts(project.id)) == 3
    assert all(store.resolve(item.artifact).is_file() for item in result.all_imports)
    assert b"not-imported" not in {
        store.resolve(item.artifact).read_bytes() for item in result.all_imports
    }


def test_imports_extracted_directory_without_trusting_member_paths(
    tmp_path: Path,
    persistence: tuple[Project, Database, ArtifactStore],
) -> None:
    project, database, store = persistence
    source = tmp_path / "unpacked"
    (source / "splits").mkdir(parents=True)
    base = _apk_bytes(marker=b"base")
    split = _apk_bytes(dex=False)
    (source / "base.apk").write_bytes(base)
    (source / "splits" / "config.en.apk").write_bytes(split)
    (source / "info.json").write_text('{"base_apk":"base.apk"}')

    result = import_android_package(
        source,
        project_id=project.id,
        artifact_store=store,
        database=database,
    )

    assert result.base.artifact.original_name == "base.apk"
    assert result.splits[0].artifact.original_name == "splits/config.en.apk"
    assert store.resolve(result.base.artifact).read_bytes() == base
    assert store.resolve(result.splits[0].artifact).read_bytes() == split


def test_content_addressing_deduplicates_members_and_repeated_imports(
    tmp_path: Path,
    persistence: tuple[Project, Database, ArtifactStore],
) -> None:
    project, database, store = persistence
    source = tmp_path / "duplicate-content.apkm"
    content = _apk_bytes()
    _write_zip(source, [("base.apk", content), ("split_config.en.apk", content)])

    first = import_android_package(
        source,
        project_id=project.id,
        artifact_store=store,
        database=database,
    )
    second = import_android_package(
        source,
        project_id=project.id,
        artifact_store=store,
        database=database,
    )

    assert first.base.artifact_id == first.splits[0].artifact_id
    assert second.artifact_ids == first.artifact_ids
    assert len(database.list_artifacts(project.id)) == 1


def test_tool_uses_context_project_and_returns_serializable_result(
    tmp_path: Path,
    persistence: tuple[Project, Database, ArtifactStore],
) -> None:
    project, database, store = persistence
    source = tmp_path / "application.apk"
    source.write_bytes(_apk_bytes())
    tool = ApkBundleImportTool(store, database)
    arguments = ApkBundleImportInput.model_validate({"path": str(source)})

    execution = tool.execute(
        ToolContext(project_id=project.id, data_dir=tmp_path), arguments
    )

    assert execution.output["project_id"] == project.id
    assert execution.output["base"]["artifact_id"]
    with pytest.raises(ValidationError):
        ApkBundleImportInput.model_validate(
            {"path": str(source), "undeclared": "value"}
        )


@pytest.mark.parametrize(
    "members",
    [
        [("../base.apk", b"invalid")],
        [("base.apk", b"not-an-apk")],
    ],
)
def test_invalid_archive_never_persists_artifacts(
    tmp_path: Path,
    persistence: tuple[Project, Database, ArtifactStore],
    members: list[tuple[str, bytes]],
) -> None:
    project, database, store = persistence
    source = tmp_path / "invalid.apkm"
    _write_zip(source, members)

    with pytest.raises(ApkInspectionError):
        import_android_package(
            source,
            project_id=project.id,
            artifact_store=store,
            database=database,
        )
    assert database.list_artifacts(project.id) == []


def test_duplicate_archive_member_never_persists_artifacts(
    tmp_path: Path,
    persistence: tuple[Project, Database, ArtifactStore],
) -> None:
    project, database, store = persistence
    source = tmp_path / "duplicate.apkm"
    with pytest.warns(UserWarning, match="Duplicate name"):
        _write_zip(
            source,
            [("base.apk", _apk_bytes()), ("base.apk", _apk_bytes())],
        )

    with pytest.raises(ApkInspectionError, match="duplicate ZIP member"):
        import_android_package(
            source,
            project_id=project.id,
            artifact_store=store,
            database=database,
        )
    assert database.list_artifacts(project.id) == []
