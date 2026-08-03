"""Safe, deterministic adapter for JADX command-line decompilation."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
import zipfile
from collections.abc import Iterable
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from reverserx.tools.base import BaseTool, ToolContext, ToolExecution
from reverserx.utils.subprocess import CommandLaunchError, CommandResult, run_command

_CACHE_MARKER = ".reverserx-jadx-cache.json"
_CACHE_SCHEMA_VERSION = 3
_MAX_CACHE_MARKER_BYTES = 25_000_000
_BUFFER_SIZE = 1024 * 1024
_PROJECT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_WARNING_PATTERN = re.compile(r"\bwarn(?:ing)?\b", re.IGNORECASE)
_ERROR_PATTERN = re.compile(r"\b(?:error|fatal)\b", re.IGNORECASE)
_REPORTED_ERROR_COUNT_PATTERN = re.compile(
    r"finished\s+with\s+errors\s*,?\s*count\s*:\s*(\d+)",
    re.IGNORECASE,
)


class JadxStatus(StrEnum):
    """Outcome of a JADX invocation."""

    SUCCEEDED = "succeeded"
    CACHED = "cached"
    PARTIAL = "partial"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class JadxOptions(BaseModel):
    """Output-affecting JADX options included in the cache identity."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    threads: int = Field(ge=1, le=64)
    deobfuscate: bool
    show_inconsistent_code: bool
    decode_resources: bool


class JadxInput(BaseModel):
    """Validated input accepted by :class:`JadxTool`."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    apk_path: Path
    output_dir: Path | None = None
    force: bool = False
    allow_partial: bool = False
    threads: int = Field(default=4, ge=1, le=64)
    deobfuscate: bool = True
    show_inconsistent_code: bool = False
    decode_resources: bool = True
    timeout_seconds: float = Field(default=900.0, ge=1.0, le=7_200.0)
    output_limit_bytes: int = Field(default=1_000_000, ge=1_024, le=10_000_000)

    @field_validator("apk_path", "output_dir", mode="before")
    @classmethod
    def parse_paths(cls, value: object) -> object:
        if isinstance(value, str):
            if "\0" in value:
                raise ValueError("paths cannot contain NUL bytes")
            return Path(value)
        return value


class JadxResult(BaseModel):
    """Structured, bounded metadata for a JADX execution or cache hit."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    status: JadxStatus
    cache_hit: bool = False
    apk_path: Path
    apk_sha256: str = Field(min_length=64, max_length=64)
    output_dir: Path
    cache_key: str = Field(min_length=64, max_length=64)
    cache_marker_path: Path
    jadx_version: str = Field(min_length=1)
    options: JadxOptions
    version_command: tuple[str, ...]
    command: tuple[str, ...]
    version_probe_duration_seconds: float = Field(ge=0)
    duration_seconds: float = Field(ge=0)
    return_code: int | None
    source_file_count: int = Field(ge=0)
    resource_file_count: int = Field(ge=0)
    manifest_path: Path | None
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    reported_error_count: int | None = Field(default=None, ge=0)


class _CachedOutcome(BaseModel):
    """Process outcome retained in a trusted, versioned cache marker."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    status: JadxStatus
    return_code: int | None
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    reported_error_count: int | None = Field(default=None, ge=0)
    stdout_truncated: bool = False
    stderr_truncated: bool = False


class _OutputSnapshot(BaseModel):
    """Content identity for reusable JADX output, excluding the cache marker."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    file_count: int = Field(ge=0)
    total_size_bytes: int = Field(ge=0)
    source_file_count: int = Field(ge=0)
    resource_file_count: int = Field(ge=0)
    manifest_relative_path: str | None = None


class _CacheMarker(BaseModel):
    """On-disk identity and original process outcome for reusable output."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: int
    cache_key: str = Field(min_length=64, max_length=64)
    apk_sha256: str = Field(min_length=64, max_length=64)
    jadx_version: str = Field(min_length=1)
    options: JadxOptions
    adapter_version: str = Field(min_length=1)
    outcome: _CachedOutcome
    output_snapshot: _OutputSnapshot


class JadxToolError(RuntimeError):
    """Raised for invalid inputs or an unsuccessful JADX execution.

    Process failures expose their structured result through ``result`` so callers
    that need diagnostics do not have to parse the exception message.
    """

    def __init__(self, message: str, result: JadxResult | None = None) -> None:
        super().__init__(message)
        self.result = result


class JadxTool(BaseTool[JadxInput]):
    """Decompile one validated APK into a project-confined directory."""

    name = "jadx_decompile"
    description = "Decompile a validated Android APK with JADX."
    version = "1.0.0"
    input_model = JadxInput

    def __init__(self, executable: str | Path = "jadx") -> None:
        executable_text = str(executable)
        if not executable_text or "\0" in executable_text:
            raise ValueError("JADX executable must be a valid command or path")
        self.executable = executable_text

    def execute(self, context: ToolContext, arguments: JadxInput) -> ToolExecution:
        apk_path = _validate_apk(arguments.apk_path)
        apk_sha256 = _sha256_file(apk_path)
        project_root = _project_root(context)

        # Validate an explicitly requested destination before starting any process.
        requested_output = None
        if arguments.output_dir is not None:
            requested_output = _resolve_output(project_root, arguments.output_dir)

        options = JadxOptions(
            threads=arguments.threads,
            deobfuscate=arguments.deobfuscate,
            show_inconsistent_code=arguments.show_inconsistent_code,
            decode_resources=arguments.decode_resources,
        )
        version_command = (self.executable, "--version")
        try:
            version_result = run_command(
                version_command,
                timeout=min(arguments.timeout_seconds, 15.0),
                output_limit=min(arguments.output_limit_bytes, 20_000),
            )
        except CommandLaunchError as exc:
            output_dir = requested_output or _default_output(
                project_root, apk_sha256, "unknown", options, self.version
            )
            result = _result_for_version_failure(
                apk_path=apk_path,
                apk_sha256=apk_sha256,
                output_dir=output_dir,
                options=options,
                version_command=version_command,
                adapter_version=self.version,
                error=str(exc),
            )
            raise JadxToolError(str(exc), result) from exc

        jadx_version = _extract_version(version_result)
        if not version_result.succeeded or jadx_version is None:
            output_dir = requested_output or _default_output(
                project_root, apk_sha256, "unknown", options, self.version
            )
            result = _result_for_bad_version_probe(
                apk_path=apk_path,
                apk_sha256=apk_sha256,
                output_dir=output_dir,
                options=options,
                version_command=version_command,
                version_result=version_result,
                adapter_version=self.version,
            )
            raise JadxToolError(result.errors[0], result)

        cache_key = _cache_key(apk_sha256, jadx_version, options, self.version)
        output_dir = requested_output or _resolve_output(
            project_root, Path("jadx") / cache_key
        )
        marker_path = output_dir / _CACHE_MARKER
        command = _build_command(self.executable, apk_path, output_dir, options)

        cache_marker = None
        if not arguments.force:
            cache_marker = _read_cache_marker(
                marker_path,
                cache_key=cache_key,
                apk_sha256=apk_sha256,
                jadx_version=jadx_version,
                options=options,
                adapter_version=self.version,
            )
        if cache_marker is not None:
            try:
                observed_snapshot = _snapshot_output(output_dir)
            except JadxToolError as exc:
                raise JadxToolError(
                    "cached JADX output failed integrity validation; use force to "
                    "rebuild it"
                ) from exc
            if observed_snapshot != cache_marker.output_snapshot:
                raise JadxToolError(
                    "cached JADX output failed integrity validation; use force to "
                    "rebuild it"
                )
            source_count = observed_snapshot.source_file_count
            resource_count = observed_snapshot.resource_file_count
            manifest_path = (
                output_dir / observed_snapshot.manifest_relative_path
                if observed_snapshot.manifest_relative_path is not None
                else None
            )
            outcome = cache_marker.outcome
            cached_status = (
                JadxStatus.CACHED
                if outcome.status is JadxStatus.SUCCEEDED
                else JadxStatus.PARTIAL
            )
            result = JadxResult(
                status=cached_status,
                cache_hit=True,
                apk_path=apk_path,
                apk_sha256=apk_sha256,
                output_dir=output_dir,
                cache_key=cache_key,
                cache_marker_path=marker_path,
                jadx_version=jadx_version,
                options=options,
                version_command=version_command,
                command=command,
                version_probe_duration_seconds=version_result.duration_seconds,
                duration_seconds=0.0,
                return_code=outcome.return_code,
                source_file_count=source_count,
                resource_file_count=resource_count,
                manifest_path=manifest_path,
                stdout="",
                stderr="",
                stdout_truncated=outcome.stdout_truncated,
                stderr_truncated=outcome.stderr_truncated,
                warnings=outcome.warnings,
                errors=outcome.errors,
                reported_error_count=outcome.reported_error_count,
            )
            if cached_status is JadxStatus.PARTIAL and not arguments.allow_partial:
                raise JadxToolError(
                    "cached JADX output is partial; pass allow_partial to reuse it "
                    "or use force to rebuild it",
                    result,
                )
            notices = result.warnings
            if result.stdout_truncated or result.stderr_truncated:
                notices = (*notices, "JADX process output was truncated")
            return ToolExecution(output=result.model_dump(mode="json"), notices=notices)

        _prepare_output(output_dir, force=arguments.force)
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        project_root.mkdir(parents=True, exist_ok=True)

        try:
            command_result = run_command(
                command,
                timeout=arguments.timeout_seconds,
                output_limit=arguments.output_limit_bytes,
                cwd=project_root,
            )
        except CommandLaunchError as exc:
            result = _result_for_command_failure(
                apk_path=apk_path,
                apk_sha256=apk_sha256,
                output_dir=output_dir,
                cache_key=cache_key,
                jadx_version=jadx_version,
                options=options,
                version_command=version_command,
                command=command,
                version_probe_duration=version_result.duration_seconds,
                error=str(exc),
            )
            raise JadxToolError(str(exc), result) from exc

        warnings, errors = _diagnostics(command_result)
        status = _status_for(command_result)
        output_is_safe = _output_remains_confined(output_dir, project_root)
        if not output_is_safe:
            status = JadxStatus.FAILED
            errors = (*errors, "JADX output escaped the project area")
        elif command_result.succeeded and not output_dir.is_dir():
            status = JadxStatus.FAILED
            errors = (
                *errors,
                "JADX exited successfully but created no output directory",
            )

        if output_is_safe:
            source_count, resource_count, manifest_path = _inspect_output(output_dir)
        else:
            source_count, resource_count, manifest_path = 0, 0, None
        if (
            command_result.succeeded
            and output_is_safe
            and not _output_is_usable(
                source_count,
                resource_count,
                manifest_path,
                options,
            )
        ):
            status = JadxStatus.FAILED
            errors = (
                *errors,
                "JADX exited successfully but produced no usable output",
            )
        if (
            arguments.allow_partial
            and status is JadxStatus.FAILED
            and output_is_safe
            and source_count > 0
            and (manifest_path is not None or not options.decode_resources)
        ):
            status = JadxStatus.PARTIAL
            warnings = (
                *warnings,
                "JADX returned errors; partial output was accepted by explicit request",
            )

        result = JadxResult(
            status=status,
            apk_path=apk_path,
            apk_sha256=apk_sha256,
            output_dir=output_dir,
            cache_key=cache_key,
            cache_marker_path=marker_path,
            jadx_version=jadx_version,
            options=options,
            version_command=version_command,
            command=command,
            version_probe_duration_seconds=version_result.duration_seconds,
            duration_seconds=command_result.duration_seconds,
            return_code=command_result.returncode,
            source_file_count=source_count,
            resource_file_count=resource_count,
            manifest_path=manifest_path,
            stdout=command_result.stdout,
            stderr=command_result.stderr,
            stdout_truncated=command_result.stdout_truncated,
            stderr_truncated=command_result.stderr_truncated,
            warnings=warnings,
            errors=errors,
            reported_error_count=_reported_error_count(errors),
        )
        if status not in {JadxStatus.SUCCEEDED, JadxStatus.PARTIAL}:
            message = errors[0] if errors else f"JADX execution {status.value}"
            raise JadxToolError(message, result)

        _write_cache_marker(
            marker_path,
            result=result,
            adapter_version=self.version,
        )
        notices = warnings
        if command_result.stdout_truncated or command_result.stderr_truncated:
            notices = (*notices, "JADX process output was truncated")
        return ToolExecution(output=result.model_dump(mode="json"), notices=notices)


def _validate_apk(path: Path) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise JadxToolError(
            f"APK does not exist or cannot be resolved: {path}"
        ) from exc
    if not resolved.is_file():
        raise JadxToolError(f"APK is not a regular file: {resolved}")
    try:
        with zipfile.ZipFile(resolved) as archive:
            try:
                manifest = archive.getinfo("AndroidManifest.xml")
            except KeyError as exc:
                raise JadxToolError(
                    "input is not an APK: AndroidManifest.xml is missing"
                ) from exc
            if manifest.is_dir():
                raise JadxToolError(
                    "input is not an APK: AndroidManifest.xml is not a file"
                )
    except (OSError, zipfile.BadZipFile) as exc:
        raise JadxToolError(f"input is not a readable APK ZIP: {resolved}") from exc
    return resolved


def _project_root(context: ToolContext) -> Path:
    if _PROJECT_ID_PATTERN.fullmatch(context.project_id) is None:
        raise JadxToolError("invalid project identifier")
    try:
        data_root = context.data_dir.expanduser().resolve()
    except (OSError, RuntimeError) as exc:
        raise JadxToolError("data directory cannot be resolved") from exc
    if data_root.exists() and not data_root.is_dir():
        raise JadxToolError(f"data directory is not a directory: {data_root}")
    project_root = (data_root / "projects" / context.project_id).resolve()
    try:
        project_root.relative_to(data_root)
    except ValueError as exc:  # pragma: no cover - defensive against symlink races
        raise JadxToolError("project area escapes the data directory") from exc
    return project_root


def _resolve_output(project_root: Path, requested: Path) -> Path:
    if "\0" in str(requested):
        raise JadxToolError("output path cannot contain NUL bytes")
    candidate = requested.expanduser()
    if not candidate.is_absolute():
        candidate = project_root / candidate
    try:
        resolved = candidate.resolve()
        relative = resolved.relative_to(project_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise JadxToolError(
            f"output directory must be inside the project area: {project_root}"
        ) from exc
    if relative == Path("."):
        raise JadxToolError("output directory cannot be the project root")
    if candidate.is_symlink():
        raise JadxToolError("output directory cannot be a symbolic link")
    return resolved


def _default_output(
    project_root: Path,
    apk_sha256: str,
    jadx_version: str,
    options: JadxOptions,
    adapter_version: str,
) -> Path:
    cache_key = _cache_key(apk_sha256, jadx_version, options, adapter_version)
    return _resolve_output(project_root, Path("jadx") / cache_key)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1_048_576):
                digest.update(chunk)
    except OSError as exc:
        raise JadxToolError(f"cannot read APK: {path}") from exc
    return digest.hexdigest()


def _extract_version(result: CommandResult) -> str | None:
    combined = "\n".join(part for part in (result.stdout, result.stderr) if part)
    return next((line.strip() for line in combined.splitlines() if line.strip()), None)


def _cache_key(
    apk_sha256: str,
    jadx_version: str,
    options: JadxOptions,
    adapter_version: str,
) -> str:
    identity = {
        "apk_sha256": apk_sha256,
        "jadx_version": jadx_version,
        "options": options.model_dump(mode="json"),
        "adapter_version": adapter_version,
    }
    encoded = json.dumps(
        identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _read_cache_marker(
    marker_path: Path,
    *,
    cache_key: str,
    apk_sha256: str,
    jadx_version: str,
    options: JadxOptions,
    adapter_version: str,
) -> _CacheMarker | None:
    if (
        not marker_path.is_file()
        or marker_path.is_symlink()
        or not marker_path.parent.is_dir()
    ):
        return None
    try:
        if marker_path.stat().st_size > _MAX_CACHE_MARKER_BYTES:
            return None
        marker = _CacheMarker.model_validate_json(
            marker_path.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, ValidationError):
        return None
    if marker.schema_version != _CACHE_SCHEMA_VERSION:
        return None
    if marker.outcome.status not in {JadxStatus.SUCCEEDED, JadxStatus.PARTIAL}:
        return None
    expected_identity = (
        cache_key,
        apk_sha256,
        jadx_version,
        options,
        adapter_version,
    )
    observed_identity = (
        marker.cache_key,
        marker.apk_sha256,
        marker.jadx_version,
        marker.options,
        marker.adapter_version,
    )
    if observed_identity != expected_identity:
        return None
    return marker


def _write_cache_marker(
    marker_path: Path,
    *,
    result: JadxResult,
    adapter_version: str,
) -> None:
    if result.status not in {JadxStatus.SUCCEEDED, JadxStatus.PARTIAL}:
        raise JadxToolError("refusing to cache an unsuccessful JADX outcome", result)
    marker = _CacheMarker(
        schema_version=_CACHE_SCHEMA_VERSION,
        cache_key=result.cache_key,
        apk_sha256=result.apk_sha256,
        jadx_version=result.jadx_version,
        options=result.options,
        adapter_version=adapter_version,
        outcome=_CachedOutcome(
            status=result.status,
            return_code=result.return_code,
            warnings=result.warnings,
            errors=result.errors,
            reported_error_count=result.reported_error_count,
            stdout_truncated=result.stdout_truncated,
            stderr_truncated=result.stderr_truncated,
        ),
        output_snapshot=_snapshot_output(result.output_dir),
    )
    encoded = (
        json.dumps(
            marker.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    )
    if len(encoded.encode("utf-8")) > _MAX_CACHE_MARKER_BYTES:
        raise JadxToolError("JADX cache diagnostics exceed the marker safety limit")
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=marker_path.parent,
            prefix=f"{marker_path.name}.",
            delete=False,
        ) as temporary:
            temporary.write(encoded)
            temporary.flush()
            temporary_path = Path(temporary.name)
        temporary_path.replace(marker_path)
        temporary_path = None
    except OSError as exc:
        raise JadxToolError(f"cannot write JADX cache marker: {marker_path}") from exc
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _build_command(
    executable: str, apk_path: Path, output_dir: Path, options: JadxOptions
) -> tuple[str, ...]:
    command = [
        executable,
        "-d",
        str(output_dir),
        "-j",
        str(options.threads),
    ]
    if options.deobfuscate:
        command.append("--deobf")
    if options.show_inconsistent_code:
        command.append("--show-bad-code")
    if not options.decode_resources:
        command.append("--no-res")
    command.append(str(apk_path))
    return tuple(command)


def _prepare_output(output_dir: Path, *, force: bool) -> None:
    if not output_dir.exists():
        return
    if not force:
        raise JadxToolError(
            "JADX output already exists without a matching cache marker; use force"
        )
    try:
        if output_dir.is_dir():
            shutil.rmtree(output_dir)
        else:
            output_dir.unlink()
    except OSError as exc:
        raise JadxToolError(
            f"cannot clear JADX output directory: {output_dir}"
        ) from exc


def _output_remains_confined(output_dir: Path, project_root: Path) -> bool:
    """Defend marker creation against a process replacing output with a symlink."""

    if output_dir.is_symlink():
        return False
    if not output_dir.exists():
        return True
    try:
        resolved = output_dir.resolve(strict=True)
        resolved.relative_to(project_root)
    except (OSError, RuntimeError, ValueError):
        return False
    return resolved == output_dir


def _inspect_output(output_dir: Path) -> tuple[int, int, Path | None]:
    sources = output_dir / "sources"
    resources = output_dir / "resources"
    source_count = _count_files(sources)
    resource_count = _count_files(resources)
    candidates = (
        resources / "AndroidManifest.xml",
        output_dir / "AndroidManifest.xml",
    )
    manifest = next((path for path in candidates if path.is_file()), None)
    return source_count, resource_count, manifest


def _output_is_usable(
    source_count: int,
    resource_count: int,
    manifest_path: Path | None,
    options: JadxOptions,
) -> bool:
    if source_count == 0 and resource_count == 0:
        return False
    return not options.decode_resources or manifest_path is not None


def _snapshot_output(output_dir: Path) -> _OutputSnapshot:
    """Hash all JADX output files so cache reuse cannot hide damage or deletion."""

    if output_dir.is_symlink() or not output_dir.is_dir():
        raise JadxToolError("JADX output directory is missing or unsafe")
    try:
        paths = sorted(
            output_dir.rglob("*"),
            key=lambda path: path.relative_to(output_dir).as_posix(),
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise JadxToolError("cannot inventory JADX output") from exc

    aggregate = hashlib.sha256()
    file_count = 0
    total_size = 0
    source_count = 0
    resource_count = 0
    observed_files: set[str] = set()
    try:
        for path in paths:
            if path.is_symlink():
                raise JadxToolError(f"JADX output contains a symbolic link: {path}")
            if path.is_dir():
                continue
            if not path.is_file():
                raise JadxToolError(f"JADX output contains a non-regular file: {path}")
            relative = path.relative_to(output_dir).as_posix()
            if relative == _CACHE_MARKER:
                continue

            file_digest = hashlib.sha256()
            size = 0
            with path.open("rb") as stream:
                while block := stream.read(_BUFFER_SIZE):
                    file_digest.update(block)
                    size += len(block)
            encoded_relative = relative.encode("utf-8", errors="surrogateescape")
            aggregate.update(len(encoded_relative).to_bytes(8, "big"))
            aggregate.update(encoded_relative)
            aggregate.update(size.to_bytes(8, "big"))
            aggregate.update(file_digest.digest())
            observed_files.add(relative)
            file_count += 1
            total_size += size
            if relative.startswith("sources/"):
                source_count += 1
            elif relative.startswith("resources/"):
                resource_count += 1
    except OSError as exc:
        raise JadxToolError("cannot read JADX output for cache validation") from exc

    manifest_relative = next(
        (
            candidate
            for candidate in (
                "resources/AndroidManifest.xml",
                "AndroidManifest.xml",
            )
            if candidate in observed_files
        ),
        None,
    )
    return _OutputSnapshot(
        sha256=aggregate.hexdigest(),
        file_count=file_count,
        total_size_bytes=total_size,
        source_file_count=source_count,
        resource_file_count=resource_count,
        manifest_relative_path=manifest_relative,
    )


def _count_files(root: Path) -> int:
    if not root.is_dir():
        return 0
    try:
        return sum(1 for path in root.rglob("*") if path.is_file())
    except OSError:
        return 0


def _diagnostics(result: CommandResult) -> tuple[tuple[str, ...], tuple[str, ...]]:
    lines = [
        line.strip()
        for output in (result.stdout, result.stderr)
        for line in output.splitlines()
        if line.strip()
    ]
    warnings = _unique(line for line in lines if _WARNING_PATTERN.search(line))
    errors = _unique(line for line in lines if _ERROR_PATTERN.search(line))
    if result.timed_out:
        errors = (*errors, "JADX execution timed out")
    elif result.cancelled:
        errors = (*errors, "JADX execution was cancelled")
    elif result.returncode != 0 and not errors:
        detail = next((line for line in reversed(lines) if line), "")
        message = f"JADX exited with code {result.returncode}"
        if detail:
            message = f"{message}: {detail[:2_000]}"
        errors = (message,)
    return warnings, _unique(errors)


def _reported_error_count(errors: Iterable[str]) -> int | None:
    counts = (
        int(match.group(1))
        for error in errors
        if (match := _REPORTED_ERROR_COUNT_PATTERN.search(error)) is not None
    )
    return max(counts, default=None)


def _unique(lines: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(lines))


def _status_for(result: CommandResult) -> JadxStatus:
    if result.timed_out:
        return JadxStatus.TIMED_OUT
    if result.cancelled:
        return JadxStatus.CANCELLED
    if result.returncode != 0:
        return JadxStatus.FAILED
    return JadxStatus.SUCCEEDED


def _result_for_version_failure(
    *,
    apk_path: Path,
    apk_sha256: str,
    output_dir: Path,
    options: JadxOptions,
    version_command: tuple[str, ...],
    adapter_version: str,
    error: str,
) -> JadxResult:
    cache_key = _cache_key(apk_sha256, "unknown", options, adapter_version)
    return JadxResult(
        status=JadxStatus.FAILED,
        apk_path=apk_path,
        apk_sha256=apk_sha256,
        output_dir=output_dir,
        cache_key=cache_key,
        cache_marker_path=output_dir / _CACHE_MARKER,
        jadx_version="unknown",
        options=options,
        version_command=version_command,
        command=(),
        version_probe_duration_seconds=0.0,
        duration_seconds=0.0,
        return_code=None,
        source_file_count=0,
        resource_file_count=0,
        manifest_path=None,
        stdout="",
        stderr="",
        stdout_truncated=False,
        stderr_truncated=False,
        errors=(error,),
    )


def _result_for_bad_version_probe(
    *,
    apk_path: Path,
    apk_sha256: str,
    output_dir: Path,
    options: JadxOptions,
    version_command: tuple[str, ...],
    version_result: CommandResult,
    adapter_version: str,
) -> JadxResult:
    warnings, errors = _diagnostics(version_result)
    if not errors:
        errors = ("JADX version probe returned no version",)
    status = _status_for(version_result)
    if status is JadxStatus.SUCCEEDED:
        status = JadxStatus.FAILED
    cache_key = _cache_key(apk_sha256, "unknown", options, adapter_version)
    return JadxResult(
        status=status,
        apk_path=apk_path,
        apk_sha256=apk_sha256,
        output_dir=output_dir,
        cache_key=cache_key,
        cache_marker_path=output_dir / _CACHE_MARKER,
        jadx_version="unknown",
        options=options,
        version_command=version_command,
        command=(),
        version_probe_duration_seconds=version_result.duration_seconds,
        duration_seconds=0.0,
        return_code=version_result.returncode,
        source_file_count=0,
        resource_file_count=0,
        manifest_path=None,
        stdout=version_result.stdout,
        stderr=version_result.stderr,
        stdout_truncated=version_result.stdout_truncated,
        stderr_truncated=version_result.stderr_truncated,
        warnings=warnings,
        errors=errors,
    )


def _result_for_command_failure(
    *,
    apk_path: Path,
    apk_sha256: str,
    output_dir: Path,
    cache_key: str,
    jadx_version: str,
    options: JadxOptions,
    version_command: tuple[str, ...],
    command: tuple[str, ...],
    version_probe_duration: float,
    error: str,
) -> JadxResult:
    return JadxResult(
        status=JadxStatus.FAILED,
        apk_path=apk_path,
        apk_sha256=apk_sha256,
        output_dir=output_dir,
        cache_key=cache_key,
        cache_marker_path=output_dir / _CACHE_MARKER,
        jadx_version=jadx_version,
        options=options,
        version_command=version_command,
        command=command,
        version_probe_duration_seconds=version_probe_duration,
        duration_seconds=0.0,
        return_code=None,
        source_file_count=0,
        resource_file_count=0,
        manifest_path=None,
        stdout="",
        stderr="",
        stdout_truncated=False,
        stderr_truncated=False,
        errors=(error,),
    )
