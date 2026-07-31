"""Content-addressed, immutable artifact storage."""

from __future__ import annotations

import hashlib
import mimetypes
import os
import re
import tempfile
from pathlib import Path

from reverserx.core.models import Artifact

PROJECT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


class ArtifactStoreError(ValueError):
    """Raised when an artifact cannot be imported safely."""


class ArtifactStore:
    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()

    def import_file(self, project_id: str, source: Path) -> Artifact:
        if not PROJECT_ID_PATTERN.fullmatch(project_id):
            raise ArtifactStoreError("invalid project identifier")
        source_path = source.expanduser().resolve(strict=True)
        if not source_path.is_file():
            raise ArtifactStoreError(
                f"artifact source is not a regular file: {source_path}"
            )

        staging = self.root / ".staging"
        staging.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        size = 0
        temporary_path: Path | None = None
        try:
            with (
                source_path.open("rb") as source_file,
                tempfile.NamedTemporaryFile(dir=staging, delete=False) as temporary,
            ):
                temporary_path = Path(temporary.name)
                while chunk := source_file.read(1_048_576):
                    digest.update(chunk)
                    size += len(chunk)
                    temporary.write(chunk)
                temporary.flush()
                os.fsync(temporary.fileno())

            sha256 = digest.hexdigest()
            target = self.root / project_id / sha256[:2] / sha256 / "blob"
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                temporary_path.unlink(missing_ok=True)
                if target.stat().st_size != size or _sha256_file(target) != sha256:
                    raise ArtifactStoreError(
                        "existing artifact failed integrity validation"
                    )
            else:
                os.replace(temporary_path, target)
                target.chmod(0o444)
            temporary_path = None
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

        media_type = (
            mimetypes.guess_type(source_path.name)[0] or "application/octet-stream"
        )
        return Artifact(
            project_id=project_id,
            sha256=sha256,
            original_name=source_path.name,
            media_type=media_type,
            size_bytes=size,
            stored_path=str(target.relative_to(self.root)),
        )

    def resolve(self, artifact: Artifact) -> Path:
        candidate = (self.root / artifact.stored_path).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise ArtifactStoreError("artifact path escapes the store") from exc
        if not candidate.is_file():
            raise ArtifactStoreError(f"artifact blob is missing: {artifact.id}")
        return candidate


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1_048_576):
            digest.update(chunk)
    return digest.hexdigest()
