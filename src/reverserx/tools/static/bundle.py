"""Materialize validated APK bundle members into durable project artifacts."""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path, PurePosixPath
from typing import IO
from zipfile import BadZipFile, LargeZipFile, ZipFile, ZipInfo

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from reverserx.core.models import Artifact
from reverserx.storage.database import Database
from reverserx.storage.files import ArtifactStore
from reverserx.tools.base import BaseTool, ToolContext, ToolExecution
from reverserx.tools.static.apk import (
    ApkDescriptor,
    ApkInspectionResult,
    ApkRole,
    PackageSourceKind,
    inspect_android_package,
)

_BUFFER_SIZE = 1024 * 1024
_APK_MEDIA_TYPE = "application/vnd.android.package-archive"


class BundleImportError(ValueError):
    """Raised when inspected package content cannot be imported consistently."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ApkBundleImportInput(_StrictModel):
    """Validated path accepted by :class:`ApkBundleImportTool`."""

    path: Path

    @field_validator("path", mode="before")
    @classmethod
    def accept_path_string(cls, value: object) -> object:
        if isinstance(value, str):
            return Path(value)
        return value


class ImportedApkArtifact(_StrictModel):
    """Link between an inspected APK member and its persisted artifact."""

    apk: ApkDescriptor
    artifact_id: str
    artifact: Artifact

    @model_validator(mode="after")
    def validate_identity(self) -> ImportedApkArtifact:
        if self.artifact_id != self.artifact.id:
            raise ValueError("artifact_id does not match artifact.id")
        if self.apk.sha256 != self.artifact.sha256:
            raise ValueError("APK and artifact SHA-256 values do not match")
        if self.apk.size_bytes != self.artifact.size_bytes:
            raise ValueError("APK and artifact sizes do not match")
        return self


class ApkBundleImportResult(_StrictModel):
    """Inspection plus durable base/split artifact identities."""

    project_id: str
    inspection: ApkInspectionResult
    base: ImportedApkArtifact
    splits: tuple[ImportedApkArtifact, ...] = ()

    @model_validator(mode="after")
    def validate_roles_and_project(self) -> ApkBundleImportResult:
        if self.base.apk.role is not ApkRole.BASE:
            raise ValueError("base import must reference the base APK")
        if any(item.apk.role is not ApkRole.SPLIT for item in self.splits):
            raise ValueError("split imports must reference split APKs")
        if any(
            item.artifact.project_id != self.project_id for item in self.all_imports
        ):
            raise ValueError("imported artifacts must belong to the result project")
        return self

    @property
    def all_imports(self) -> tuple[ImportedApkArtifact, ...]:
        """Return base first, followed by deterministic split order."""

        return (self.base, *self.splits)

    @property
    def artifact_ids(self) -> tuple[str, ...]:
        """Return artifact IDs in base/split order, retaining duplicate links."""

        return tuple(item.artifact_id for item in self.all_imports)


class ApkBundleImportTool(BaseTool[ApkBundleImportInput]):
    """Dependency-injected tool adapter for bundle import."""

    name = "apk_import"
    description = "Inspect an APK/APKM and import its base and split APK artifacts."
    version = "1.0.0"
    input_model = ApkBundleImportInput

    def __init__(
        self,
        artifact_store: ArtifactStore | None = None,
        database: Database | None = None,
    ) -> None:
        self.artifact_store = artifact_store
        self.database = database

    def execute(
        self, context: ToolContext, arguments: ApkBundleImportInput
    ) -> ToolExecution:
        database = self.database or Database(
            context.database_path or context.data_dir / "reverserx.sqlite3"
        )
        database.initialize()
        artifact_store = self.artifact_store or ArtifactStore(
            context.artifact_root or context.data_dir / "artifacts"
        )
        result = import_android_package(
            arguments.path,
            project_id=context.project_id,
            artifact_store=artifact_store,
            database=database,
        )
        return ToolExecution(output=result.model_dump(mode="json"))


def import_android_package(
    path: Path | str,
    *,
    project_id: str,
    artifact_store: ArtifactStore,
    database: Database,
) -> ApkBundleImportResult:
    """Inspect and import only the selected APKs from an Android package.

    APKM archives are never extracted wholesale.  Each already-validated member
    is streamed to an opaque staging file, checked against its inspection digest,
    and handed to :class:`ArtifactStore`.  The database's project/SHA uniqueness
    makes repeated or byte-identical imports return the existing artifact.
    """

    project = database.get_project(project_id)
    source = Path(path)
    inspection = inspect_android_package(source)
    descriptors = inspection.all_apks

    if inspection.source_kind is PackageSourceKind.APK:
        imports = _import_standalone(
            source, descriptors, project.id, artifact_store, database
        )
    elif inspection.source_kind is PackageSourceKind.APKM_ARCHIVE:
        imports = _import_archive(
            source, descriptors, project.id, artifact_store, database
        )
    else:
        imports = _import_directory(
            source, descriptors, project.id, artifact_store, database
        )

    return ApkBundleImportResult(
        project_id=project.id,
        inspection=inspection,
        base=imports[0],
        splits=tuple(imports[1:]),
    )


def _import_standalone(
    source: Path,
    descriptors: tuple[ApkDescriptor, ...],
    project_id: str,
    artifact_store: ArtifactStore,
    database: Database,
) -> list[ImportedApkArtifact]:
    if len(descriptors) != 1:
        raise BundleImportError("standalone APK inspection returned multiple APKs")
    try:
        with source.open("rb") as stream:
            imported = _import_stream(
                stream,
                descriptors[0],
                project_id,
                artifact_store,
                database,
            )
    except OSError as exc:
        raise BundleImportError(f"cannot read inspected APK {source}: {exc}") from exc
    return [imported]


def _import_archive(
    source: Path,
    descriptors: tuple[ApkDescriptor, ...],
    project_id: str,
    artifact_store: ArtifactStore,
    database: Database,
) -> list[ImportedApkArtifact]:
    imported: list[ImportedApkArtifact] = []
    try:
        with ZipFile(source) as archive:
            for descriptor in descriptors:
                member = _unique_member(archive, descriptor.name, str(source))
                with archive.open(member) as stream:
                    imported.append(
                        _import_stream(
                            stream,
                            descriptor,
                            project_id,
                            artifact_store,
                            database,
                        )
                    )
    except BundleImportError:
        raise
    except (BadZipFile, LargeZipFile, OSError, RuntimeError) as exc:
        raise BundleImportError(
            f"cannot read inspected APKM archive {source}: {exc}"
        ) from exc
    return imported


def _import_directory(
    root: Path,
    descriptors: tuple[ApkDescriptor, ...],
    project_id: str,
    artifact_store: ArtifactStore,
    database: Database,
) -> list[ImportedApkArtifact]:
    resolved_root = root.resolve(strict=True)
    imported: list[ImportedApkArtifact] = []
    for descriptor in descriptors:
        relative = PurePosixPath(descriptor.name)
        candidate = root.joinpath(*relative.parts)
        if candidate.is_symlink():
            raise BundleImportError(
                f"inspected APK became a symbolic link: {descriptor.name!r}"
            )
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(resolved_root)
        except (OSError, ValueError) as exc:
            raise BundleImportError(
                f"inspected APK escapes or is missing from bundle: {descriptor.name!r}"
            ) from exc
        if not resolved.is_file():
            raise BundleImportError(
                f"inspected APK is not a regular file: {descriptor.name!r}"
            )
        try:
            with resolved.open("rb") as stream:
                imported.append(
                    _import_stream(
                        stream,
                        descriptor,
                        project_id,
                        artifact_store,
                        database,
                    )
                )
        except OSError as exc:
            raise BundleImportError(
                f"cannot read inspected APK {descriptor.name!r}: {exc}"
            ) from exc
    return imported


def _unique_member(archive: ZipFile, name: str, label: str) -> ZipInfo:
    matches = [member for member in archive.infolist() if member.filename == name]
    if len(matches) != 1 or matches[0].is_dir():
        raise BundleImportError(
            f"inspected APK member is missing or duplicated: {label}!/{name}"
        )
    return matches[0]


def _import_stream(
    source: IO[bytes],
    descriptor: ApkDescriptor,
    project_id: str,
    artifact_store: ArtifactStore,
    database: Database,
) -> ImportedApkArtifact:
    staging = artifact_store.root / ".bundle-staging"
    staging.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    digest = hashlib.sha256()
    size = 0
    try:
        with tempfile.NamedTemporaryFile(
            dir=staging, prefix="apk-", suffix=".apk", delete=False
        ) as temporary:
            temporary_path = Path(temporary.name)
            while block := source.read(_BUFFER_SIZE):
                digest.update(block)
                size += len(block)
                temporary.write(block)
            temporary.flush()
            os.fsync(temporary.fileno())

        actual_sha256 = digest.hexdigest()
        if actual_sha256 != descriptor.sha256 or size != descriptor.size_bytes:
            raise BundleImportError(
                f"inspected APK changed before import: {descriptor.name!r}"
            )

        stored = artifact_store.import_file(project_id, temporary_path)
        if stored.sha256 != descriptor.sha256 or stored.size_bytes != size:
            raise BundleImportError(
                f"artifact store identity mismatch for APK: {descriptor.name!r}"
            )
        named_artifact = stored.model_copy(
            update={
                "original_name": descriptor.name,
                "media_type": _APK_MEDIA_TYPE,
            }
        )
        persisted = database.save_artifact(named_artifact)
        return ImportedApkArtifact(
            apk=descriptor,
            artifact_id=persisted.id,
            artifact=persisted,
        )
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
