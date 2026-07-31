import stat
from pathlib import Path

import pytest

from reverserx.storage import ArtifactStore, ArtifactStoreError


def test_artifact_import_is_content_addressed_and_read_only(tmp_path: Path) -> None:
    source = tmp_path / "fixture.apk"
    source.write_bytes(b"authorized fixture")
    store = ArtifactStore(tmp_path / "artifacts")

    artifact = store.import_file("prj_fixture", source)
    target = store.resolve(artifact)

    assert target.read_bytes() == b"authorized fixture"
    assert artifact.sha256 in artifact.stored_path
    assert target != source
    assert target.stat().st_mode & stat.S_IWUSR == 0


def test_duplicate_content_reuses_the_same_blob(tmp_path: Path) -> None:
    first = tmp_path / "first.apk"
    second = tmp_path / "second.apk"
    first.write_bytes(b"same")
    second.write_bytes(b"same")
    store = ArtifactStore(tmp_path / "artifacts")

    first_artifact = store.import_file("prj_fixture", first)
    second_artifact = store.import_file("prj_fixture", second)

    assert first_artifact.sha256 == second_artifact.sha256
    assert first_artifact.stored_path == second_artifact.stored_path


def test_resolve_rejects_path_escape(tmp_path: Path) -> None:
    source = tmp_path / "fixture.apk"
    source.write_bytes(b"fixture")
    store = ArtifactStore(tmp_path / "artifacts")
    artifact = store.import_file("prj_fixture", source)
    escaped = artifact.model_copy(update={"stored_path": "../../outside"})

    with pytest.raises(ArtifactStoreError, match="escapes"):
        store.resolve(escaped)


def test_duplicate_import_detects_corrupted_blob(tmp_path: Path) -> None:
    source = tmp_path / "fixture.apk"
    source.write_bytes(b"same")
    store = ArtifactStore(tmp_path / "artifacts")
    artifact = store.import_file("prj_fixture", source)
    target = store.resolve(artifact)
    target.chmod(0o600)
    target.write_bytes(b"evil")

    with pytest.raises(ArtifactStoreError, match="integrity"):
        store.import_file("prj_fixture", source)
