"""Safe, deterministic inspection of APK files and APKM bundles.

The inspector deliberately does not extract archive members.  It validates ZIP
structure in place, inventories nested APKs, and returns enough provenance for
later static-analysis tools to select the base APK without losing split APKs.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
from collections.abc import Iterator, Mapping
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import IO, Any
from zipfile import BadZipFile, LargeZipFile, ZipFile, ZipInfo

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

from reverserx.tools.base import BaseTool, ToolContext, ToolExecution

_BUFFER_SIZE = 1024 * 1024
_MAX_ARCHIVE_ENTRIES = 100_000
_MAX_ARCHIVE_UNCOMPRESSED_BYTES = 8 * 1024 * 1024 * 1024
_MAX_INFO_JSON_BYTES = 1024 * 1024
_MIN_COMPRESSION_RATIO_CHECK_BYTES = 1024 * 1024
_MAX_COMPRESSION_RATIO = 500
_DEX_NAME = re.compile(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex")
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


class ApkInspectionError(ValueError):
    """Raised when an APK or APKM cannot be inspected safely."""


class PackageSourceKind(StrEnum):
    """Physical form in which an Android package was supplied."""

    APK = "apk"
    APKM_ARCHIVE = "apkm_archive"
    APKM_DIRECTORY = "apkm_directory"


class ApkRole(StrEnum):
    """Role assigned to an APK inside an inspected package."""

    BASE = "base"
    SPLIT = "split"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ApkInspectInput(_StrictModel):
    """Validated input accepted by :class:`ApkInspectTool`."""

    path: Path

    @field_validator("path", mode="before")
    @classmethod
    def accept_path_string(cls, value: object) -> object:
        # Tool registries receive JSON-like dictionaries, so paths arrive as strings.
        if isinstance(value, str):
            return Path(value)
        return value


class ApkDescriptor(_StrictModel):
    """Content identity and structural inventory for one APK."""

    name: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)
    compressed_size_bytes: int | None = Field(default=None, ge=0)
    role: ApkRole
    split_id: str | None = None
    manifest_present: bool
    dex_files: tuple[str, ...] = ()
    archive_entry_count: int = Field(ge=1)
    uncompressed_size_bytes: int = Field(ge=0)


class ApkInspectionResult(_StrictModel):
    """Deterministic result shared by standalone APK and APKM inputs."""

    source_path: str = Field(min_length=1)
    source_kind: PackageSourceKind
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_size_bytes: int = Field(ge=0)
    info: dict[str, JsonValue] | None = None
    base_apk: ApkDescriptor
    split_apks: tuple[ApkDescriptor, ...] = ()

    @property
    def all_apks(self) -> tuple[ApkDescriptor, ...]:
        """Return the selected base followed by deterministically sorted splits."""

        return (self.base_apk, *self.split_apks)


class ApkInspectTool(BaseTool[ApkInspectInput]):
    """Tool adapter exposing safe package inspection to the tool registry."""

    name = "apk_inspect"
    description = "Validate an APK/APKM and inventory its base and split APKs."
    version = "1.0.0"
    input_model = ApkInspectInput

    def execute(
        self, context: ToolContext, arguments: ApkInspectInput
    ) -> ToolExecution:
        del context
        result = inspect_android_package(arguments.path)
        return ToolExecution(output=result.model_dump(mode="json"))


class _ApkSummary(_StrictModel):
    manifest_present: bool
    dex_files: tuple[str, ...]
    archive_entry_count: int
    uncompressed_size_bytes: int


class _ApkCandidate(_StrictModel):
    name: str
    sha256: str
    size_bytes: int
    compressed_size_bytes: int | None
    summary: _ApkSummary


def inspect_android_package(
    path: Path | str, *, allow_extensionless_apk: bool = False
) -> ApkInspectionResult:
    """Inspect an APK, APKM ZIP, or already-unpacked APKM directory.

    Archives are read in place and never extracted.  Every ZIP member is checked
    for unsafe names, duplicate names, unsupported links/encryption, declared
    expansion limits, and CRC failures before a result is returned.
    """

    source = Path(path)
    if source.is_symlink():
        raise ApkInspectionError(f"source must not be a symbolic link: {source}")
    if source.is_dir():
        return _inspect_apkm_directory(source)
    if not source.is_file():
        raise ApkInspectionError(f"package source is not a regular file: {source}")

    suffix = source.suffix.casefold()
    if suffix == ".apk" or (allow_extensionless_apk and not suffix):
        return _inspect_standalone_apk(source)
    if suffix in {".apkm", ".zip"}:
        return _inspect_apkm_archive(source)
    raise ApkInspectionError(
        "unsupported package source; expected an .apk, .apkm, .zip, or directory"
    )


def _inspect_standalone_apk(path: Path) -> ApkInspectionResult:
    digest, size = _hash_file(path)
    summary = _inspect_apk_file(path, str(path))
    candidate = _ApkCandidate(
        name=path.name,
        sha256=digest,
        size_bytes=size,
        compressed_size_bytes=None,
        summary=summary,
    )
    descriptor = _descriptor(candidate, ApkRole.BASE, None)
    return ApkInspectionResult(
        source_path=str(path),
        source_kind=PackageSourceKind.APK,
        source_sha256=digest,
        source_size_bytes=size,
        info=None,
        base_apk=descriptor,
    )


def _inspect_apkm_archive(path: Path) -> ApkInspectionResult:
    source_digest, source_size = _hash_file(path)
    try:
        with ZipFile(path) as archive:
            members = _validate_zip(archive, str(path))
            info_member = _select_info_member(members, str(path))
            info = (
                _read_info_json(archive, info_member, str(path))
                if info_member is not None
                else None
            )
            apk_members = sorted(
                (
                    member
                    for member in members.values()
                    if not member.is_dir()
                    and member.filename.casefold().endswith(".apk")
                ),
                key=lambda member: _name_sort_key(member.filename),
            )
            if not apk_members:
                raise ApkInspectionError(f"APKM contains no APK files: {path}")

            candidates: list[_ApkCandidate] = []
            for member in apk_members:
                digest, size = _hash_zip_member(archive, member, str(path))
                with archive.open(member) as nested:
                    summary = _inspect_apk_stream(nested, f"{path}!/{member.filename}")
                candidates.append(
                    _ApkCandidate(
                        name=member.filename,
                        sha256=digest,
                        size_bytes=size,
                        compressed_size_bytes=member.compress_size,
                        summary=summary,
                    )
                )
    except (BadZipFile, LargeZipFile, OSError, RuntimeError) as exc:
        raise ApkInspectionError(f"malformed APKM archive {path}: {exc}") from exc

    return _build_bundle_result(
        source_path=str(path),
        source_kind=PackageSourceKind.APKM_ARCHIVE,
        source_sha256=source_digest,
        source_size_bytes=source_size,
        info=info,
        candidates=candidates,
    )


def _inspect_apkm_directory(root: Path) -> ApkInspectionResult:
    files = _safe_directory_files(root)
    info_paths = [
        path for name, path in files if PurePosixPath(name).name == "info.json"
    ]
    if len(info_paths) > 1:
        raise ApkInspectionError(f"multiple info.json files found in APKM: {root}")
    info = _read_directory_info(info_paths[0]) if info_paths else None

    apk_files = [
        (name, path) for name, path in files if name.casefold().endswith(".apk")
    ]
    if not apk_files:
        raise ApkInspectionError(f"APKM contains no APK files: {root}")

    candidates: list[_ApkCandidate] = []
    for name, path in apk_files:
        digest, size = _hash_file(path)
        candidates.append(
            _ApkCandidate(
                name=name,
                sha256=digest,
                size_bytes=size,
                compressed_size_bytes=None,
                summary=_inspect_apk_file(path, str(path)),
            )
        )

    source_digest, source_size = _hash_directory_inventory(files)
    return _build_bundle_result(
        source_path=str(root),
        source_kind=PackageSourceKind.APKM_DIRECTORY,
        source_sha256=source_digest,
        source_size_bytes=source_size,
        info=info,
        candidates=candidates,
    )


def _build_bundle_result(
    *,
    source_path: str,
    source_kind: PackageSourceKind,
    source_sha256: str,
    source_size_bytes: int,
    info: dict[str, JsonValue] | None,
    candidates: list[_ApkCandidate],
) -> ApkInspectionResult:
    ordered = sorted(candidates, key=lambda candidate: _name_sort_key(candidate.name))
    base_name = _select_base_name(ordered, info)
    split_ids = _metadata_split_ids(info, {item.name for item in ordered})

    base_candidate = next(item for item in ordered if item.name == base_name)
    split_candidates = [item for item in ordered if item.name != base_name]
    base = _descriptor(base_candidate, ApkRole.BASE, None)
    splits = tuple(
        _descriptor(
            item,
            ApkRole.SPLIT,
            split_ids.get(item.name) or _derive_split_id(item.name),
        )
        for item in split_candidates
    )
    return ApkInspectionResult(
        source_path=source_path,
        source_kind=source_kind,
        source_sha256=source_sha256,
        source_size_bytes=source_size_bytes,
        info=info,
        base_apk=base,
        split_apks=splits,
    )


def _descriptor(
    candidate: _ApkCandidate, role: ApkRole, split_id: str | None
) -> ApkDescriptor:
    return ApkDescriptor(
        name=candidate.name,
        sha256=candidate.sha256,
        size_bytes=candidate.size_bytes,
        compressed_size_bytes=candidate.compressed_size_bytes,
        role=role,
        split_id=split_id,
        manifest_present=candidate.summary.manifest_present,
        dex_files=candidate.summary.dex_files,
        archive_entry_count=candidate.summary.archive_entry_count,
        uncompressed_size_bytes=candidate.summary.uncompressed_size_bytes,
    )


def _inspect_apk_file(path: Path, label: str) -> _ApkSummary:
    try:
        with ZipFile(path) as archive:
            return _inspect_open_apk(archive, label)
    except (BadZipFile, LargeZipFile, OSError, RuntimeError) as exc:
        raise ApkInspectionError(f"malformed APK {label}: {exc}") from exc


def _inspect_apk_stream(stream: IO[bytes], label: str) -> _ApkSummary:
    try:
        with ZipFile(stream) as archive:
            return _inspect_open_apk(archive, label)
    except (BadZipFile, LargeZipFile, OSError, RuntimeError) as exc:
        raise ApkInspectionError(f"malformed APK {label}: {exc}") from exc


def _inspect_open_apk(archive: ZipFile, label: str) -> _ApkSummary:
    members = _validate_zip(archive, label)
    manifest = members.get("AndroidManifest.xml")
    if manifest is None or manifest.is_dir() or manifest.file_size == 0:
        raise ApkInspectionError(
            f"APK is missing a non-empty AndroidManifest.xml: {label}"
        )
    dex_files = tuple(
        sorted(
            (
                member.filename
                for member in members.values()
                if not member.is_dir() and _DEX_NAME.fullmatch(member.filename)
            ),
            key=_name_sort_key,
        )
    )
    return _ApkSummary(
        manifest_present=True,
        dex_files=dex_files,
        archive_entry_count=len(members),
        uncompressed_size_bytes=sum(member.file_size for member in members.values()),
    )


def _validate_zip(archive: ZipFile, label: str) -> dict[str, ZipInfo]:
    infos = archive.infolist()
    if not infos:
        raise ApkInspectionError(f"ZIP archive is empty: {label}")
    if len(infos) > _MAX_ARCHIVE_ENTRIES:
        raise ApkInspectionError(
            f"ZIP archive has too many entries ({len(infos)}): {label}"
        )

    members: dict[str, ZipInfo] = {}
    uncompressed_size = 0
    for member in infos:
        name = _validate_member_name(member.filename, label)
        if name in members:
            raise ApkInspectionError(f"duplicate ZIP member {name!r}: {label}")
        if member.flag_bits & 0x1:
            raise ApkInspectionError(f"encrypted ZIP member {name!r}: {label}")
        unix_mode = member.external_attr >> 16
        if unix_mode and stat.S_ISLNK(unix_mode):
            raise ApkInspectionError(f"symbolic-link ZIP member {name!r}: {label}")
        if member.file_size < 0 or member.compress_size < 0:
            raise ApkInspectionError(f"invalid ZIP member size for {name!r}: {label}")
        if member.file_size >= _MIN_COMPRESSION_RATIO_CHECK_BYTES and (
            member.compress_size == 0
            or member.file_size / member.compress_size > _MAX_COMPRESSION_RATIO
        ):
            raise ApkInspectionError(
                f"suspicious ZIP compression ratio for {name!r}: {label}"
            )
        uncompressed_size += member.file_size
        if uncompressed_size > _MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            raise ApkInspectionError(f"ZIP expansion limit exceeded: {label}")
        members[name] = member

    try:
        bad_member = archive.testzip()
    except (BadZipFile, RuntimeError, OSError) as exc:
        raise ApkInspectionError(
            f"ZIP integrity check failed for {label}: {exc}"
        ) from exc
    if bad_member is not None:
        raise ApkInspectionError(f"ZIP CRC check failed for {bad_member!r}: {label}")
    return members


def _validate_member_name(name: str, label: str) -> str:
    if not name or "\x00" in name or "\\" in name:
        raise ApkInspectionError(f"unsafe ZIP member name {name!r}: {label}")
    if name.startswith("/") or _DRIVE_PREFIX.match(name):
        raise ApkInspectionError(f"unsafe ZIP member name {name!r}: {label}")

    without_trailing_slash = name[:-1] if name.endswith("/") else name
    parts = PurePosixPath(without_trailing_slash).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ApkInspectionError(f"unsafe ZIP member name {name!r}: {label}")
    canonical = "/".join(parts)
    expected = canonical + ("/" if name.endswith("/") else "")
    if name != expected:
        raise ApkInspectionError(f"non-canonical ZIP member name {name!r}: {label}")
    return canonical


def _safe_directory_files(root: Path) -> list[tuple[str, Path]]:
    files: list[tuple[str, Path]] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        _validate_member_name(relative, str(root))
        if path.is_symlink():
            raise ApkInspectionError(f"symbolic links are not allowed in APKM: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ApkInspectionError(f"non-regular file found in APKM: {path}")
        files.append((relative, path))
    files.sort(key=lambda item: _name_sort_key(item[0]))
    return files


def _select_info_member(members: Mapping[str, ZipInfo], label: str) -> ZipInfo | None:
    matches = [
        member
        for name, member in members.items()
        if not member.is_dir() and PurePosixPath(name).name == "info.json"
    ]
    if len(matches) > 1:
        raise ApkInspectionError(f"multiple info.json files found in APKM: {label}")
    return matches[0] if matches else None


def _read_info_json(
    archive: ZipFile, member: ZipInfo, label: str
) -> dict[str, JsonValue]:
    if member.file_size > _MAX_INFO_JSON_BYTES:
        raise ApkInspectionError(f"info.json exceeds size limit: {label}")
    with archive.open(member) as source:
        raw = source.read(_MAX_INFO_JSON_BYTES + 1)
    return _parse_info_json(raw, f"{label}!/{member.filename}")


def _read_directory_info(path: Path) -> dict[str, JsonValue]:
    try:
        if path.stat().st_size > _MAX_INFO_JSON_BYTES:
            raise ApkInspectionError(f"info.json exceeds size limit: {path}")
        return _parse_info_json(path.read_bytes(), str(path))
    except OSError as exc:
        raise ApkInspectionError(f"cannot read info.json {path}: {exc}") from exc


def _parse_info_json(raw: bytes, label: str) -> dict[str, JsonValue]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        parsed: dict[str, Any] = {}
        for key, value in pairs:
            if key in parsed:
                raise ApkInspectionError(f"duplicate info.json key {key!r}: {label}")
            parsed[key] = value
        return parsed

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ApkInspectionError(f"malformed info.json {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ApkInspectionError(f"info.json must contain a JSON object: {label}")
    # Validation guarantees that callers receive JSON values rather than arbitrary
    # objects returned by a custom decoder.
    validated = _InfoDocument.model_validate({"value": value})
    return validated.value


class _InfoDocument(_StrictModel):
    value: dict[str, JsonValue]


def _select_base_name(
    candidates: list[_ApkCandidate], info: dict[str, JsonValue] | None
) -> str:
    names = {candidate.name for candidate in candidates}
    explicit = _metadata_base_names(info, names)
    if len(explicit) > 1:
        raise ApkInspectionError(
            f"APKM metadata identifies multiple base APKs: {sorted(explicit)}"
        )
    if explicit:
        return next(iter(explicit))

    named_base = {
        candidate.name
        for candidate in candidates
        if PurePosixPath(candidate.name).name.casefold() == "base.apk"
    }
    if len(named_base) > 1:
        raise ApkInspectionError(
            f"APKM contains ambiguous base.apk candidates: {sorted(named_base)}"
        )
    if named_base:
        return next(iter(named_base))
    if len(candidates) == 1:
        return candidates[0].name

    code_candidates = [
        candidate.name for candidate in candidates if candidate.summary.dex_files
    ]
    if len(code_candidates) == 1:
        return code_candidates[0]
    raise ApkInspectionError(
        "cannot determine a unique base APK; provide info.json metadata or base.apk"
    )


def _metadata_base_names(
    info: dict[str, JsonValue] | None, available_names: set[str]
) -> set[str]:
    if info is None:
        return set()

    matches: set[str] = set()
    for record in _walk_metadata(info):
        for key, value in record.items():
            normalized_key = key.casefold().replace("-", "_")
            if normalized_key in {
                "base_apk",
                "baseapk",
                "base_file",
                "basefile",
            } and isinstance(value, str):
                resolved = _resolve_apk_reference(value, available_names, True)
                if resolved is not None:
                    matches.add(resolved)

        reference = _record_apk_reference(record)
        if reference is None:
            continue
        is_base = any(
            isinstance(value, bool) and value
            for key, value in record.items()
            if key.casefold().replace("-", "_") in {"is_base", "isbase"}
        )
        role_values = {
            value.casefold()
            for key, value in record.items()
            if key.casefold().replace("-", "_")
            in {"id", "split", "split_id", "type", "role"}
            and isinstance(value, str)
        }
        if is_base or role_values.intersection({"base", "master"}):
            resolved = _resolve_apk_reference(reference, available_names, True)
            if resolved is not None:
                matches.add(resolved)
    return matches


def _metadata_split_ids(
    info: dict[str, JsonValue] | None, available_names: set[str]
) -> dict[str, str]:
    if info is None:
        return {}
    split_ids: dict[str, str] = {}
    for record in _walk_metadata(info):
        reference = _record_apk_reference(record)
        if reference is None:
            continue
        identifier = next(
            (
                value
                for key, value in record.items()
                if key.casefold().replace("-", "_") in {"id", "split", "split_id"}
                and isinstance(value, str)
                and value.casefold() not in {"base", "master"}
            ),
            None,
        )
        if identifier is None:
            continue
        resolved = _resolve_apk_reference(reference, available_names, False)
        if resolved is not None:
            split_ids[resolved] = identifier
    return split_ids


def _walk_metadata(value: JsonValue) -> Iterator[dict[str, JsonValue]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_metadata(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_metadata(child)


def _record_apk_reference(record: Mapping[str, JsonValue]) -> str | None:
    for key, value in record.items():
        if (
            key.casefold().replace("-", "_")
            in {"file", "filename", "path", "apk", "apk_file"}
            and isinstance(value, str)
            and value.casefold().endswith(".apk")
        ):
            return value
    return None


def _resolve_apk_reference(
    reference: str, available_names: set[str], required: bool
) -> str | None:
    normalized = reference.replace("\\", "/").removeprefix("./")
    if normalized in available_names:
        return normalized
    basename_matches = {
        name
        for name in available_names
        if PurePosixPath(name).name == PurePosixPath(normalized).name
    }
    if len(basename_matches) == 1:
        return next(iter(basename_matches))
    if required:
        if not basename_matches:
            raise ApkInspectionError(
                f"info.json base APK reference does not exist: {reference!r}"
            )
        raise ApkInspectionError(
            f"info.json base APK reference is ambiguous: {reference!r}"
        )
    return None


def _derive_split_id(name: str) -> str:
    stem = PurePosixPath(name).stem
    return stem.removeprefix("split_")


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(_BUFFER_SIZE), b""):
                digest.update(block)
                size += len(block)
    except OSError as exc:
        raise ApkInspectionError(f"cannot read package file {path}: {exc}") from exc
    return digest.hexdigest(), size


def _hash_zip_member(archive: ZipFile, member: ZipInfo, label: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with archive.open(member) as source:
            for block in iter(lambda: source.read(_BUFFER_SIZE), b""):
                digest.update(block)
                size += len(block)
    except (BadZipFile, RuntimeError, OSError) as exc:
        raise ApkInspectionError(
            f"cannot read APK member {member.filename!r} from {label}: {exc}"
        ) from exc
    if size != member.file_size:
        raise ApkInspectionError(
            f"APK member size mismatch for {member.filename!r}: {label}"
        )
    return digest.hexdigest(), size


def _hash_directory_inventory(files: list[tuple[str, Path]]) -> tuple[str, int]:
    digest = hashlib.sha256()
    total_size = 0
    for name, path in files:
        file_digest, size = _hash_file(path)
        encoded_name = name.encode("utf-8")
        digest.update(len(encoded_name).to_bytes(8, "big"))
        digest.update(encoded_name)
        digest.update(size.to_bytes(8, "big"))
        digest.update(bytes.fromhex(file_digest))
        total_size += size
    return digest.hexdigest(), total_size


def _name_sort_key(name: str) -> tuple[str, str]:
    return name.casefold(), name
