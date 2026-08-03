"""ReverserX command-line entry point."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from pydantic import BaseModel, ValidationError
from rich.console import Console
from rich.table import Table

from reverserx import __version__
from reverserx.config import Settings, SettingsError
from reverserx.core.models import Artifact, Project, ToolRun, ToolRunStatus, utc_now
from reverserx.storage import (
    ArtifactStore,
    ArtifactStoreError,
    ConflictError,
    Database,
    NotFoundError,
)
from reverserx.tools import ToolContext, ToolRegistry, build_default_registry
from reverserx.utils.logging import configure_logging
from reverserx.utils.platform import check_dependencies

console = Console()
error_console = Console(stderr=True)

app = typer.Typer(
    name="reverserx",
    help="Authorized Android, API, and native reverse-engineering workspace.",
    no_args_is_help=True,
)
project_app = typer.Typer(help="Create and inspect analysis projects.")
artifact_app = typer.Typer(help="Import immutable analysis artifacts.")
tool_app = typer.Typer(help="Inspect and run registered tools.")
config_app = typer.Typer(help="Inspect resolved application configuration.")
apk_app = typer.Typer(help="Inspect and decompile authorized Android packages.")
manifest_app = typer.Typer(help="Analyze decoded Android manifests.")
source_app = typer.Typer(help="Index and search decompiled source code.")
context_app = typer.Typer(help="Retrieve token-budgeted analysis context.")
obfuscation_app = typer.Typer(help="Inspect source trees for obfuscation signals.")
report_app = typer.Typer(help="Render deterministic analysis reports.")
app.add_typer(project_app, name="project")
app.add_typer(artifact_app, name="artifact")
app.add_typer(tool_app, name="tool")
app.add_typer(config_app, name="config")
app.add_typer(apk_app, name="apk")
app.add_typer(manifest_app, name="manifest")
app.add_typer(source_app, name="source")
app.add_typer(context_app, name="context")
app.add_typer(obfuscation_app, name="obfuscation")
app.add_typer(report_app, name="report")


@dataclass(frozen=True, slots=True)
class CliState:
    settings: Settings
    json_output: bool


@dataclass(frozen=True, slots=True)
class Runtime:
    settings: Settings
    database: Database
    artifacts: ArtifactStore
    tools: ToolRegistry

    @classmethod
    def create(cls, settings: Settings) -> Runtime:
        database = Database(settings.database_path)
        database.initialize()
        return cls(
            settings=settings,
            database=database,
            artifacts=ArtifactStore(settings.artifact_root),
            tools=build_default_registry(),
        )


class ToolCommandError(RuntimeError):
    """Expose the persisted failed run to user-facing commands."""

    def __init__(self, message: str, run: ToolRun) -> None:
        super().__init__(message)
        self.run = run


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"ReverserX {__version__}")
        raise typer.Exit()


@app.callback()
def global_options(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Optional YAML configuration file."),
    ] = None,
    data_dir: Annotated[
        Path | None,
        typer.Option("--data-dir", help="Override the ReverserX data directory."),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit machine-readable JSON where supported."),
    ] = False,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the installed version and exit.",
        ),
    ] = False,
) -> None:
    del version
    try:
        settings = Settings.from_sources(config, overrides={"data_dir": data_dir})
    except (SettingsError, ValidationError, ValueError) as exc:
        _fail(str(exc))
    secrets = (
        secret.get_secret_value()
        for secret in (
            settings.anthropic_api_key,
            settings.deepseek_api_key,
            settings.openai_api_key,
        )
        if secret is not None
    )
    configure_logging(settings.log_level, secrets)
    ctx.obj = CliState(settings=settings, json_output=json_output)


@app.command("init")
def initialize(ctx: typer.Context) -> None:
    """Initialize local database and artifact directories."""

    runtime = _runtime(ctx)
    runtime.settings.artifact_root.mkdir(parents=True, exist_ok=True)
    _emit(
        ctx,
        {
            "data_dir": str(runtime.settings.data_dir),
            "database": str(runtime.settings.database_path),
            "schema_version": runtime.database.schema_version(),
        },
        f"Initialized ReverserX at {runtime.settings.data_dir}",
    )


@app.command()
def doctor(ctx: typer.Context) -> None:
    """Report host and optional reverse-engineering dependencies."""

    checks = check_dependencies()
    state = _state(ctx)
    if state.json_output:
        _print_json([check.as_dict() for check in checks])
        return
    table = Table(title="ReverserX environment")
    table.add_column("Dependency")
    table.add_column("Required")
    table.add_column("Status")
    table.add_column("Version / reason")
    for check in checks:
        status = (
            "[green]available[/green]"
            if check.available
            else "[yellow]missing[/yellow]"
        )
        detail = check.version or check.error or ""
        table.add_row(check.name, "yes" if check.required else "no", status, detail)
    console.print(table)


@config_app.command("show")
def config_show(ctx: typer.Context) -> None:
    """Show resolved configuration with provider secrets redacted."""

    data = _state(ctx).settings.redacted()
    if _state(ctx).json_output:
        _print_json(data)
        return
    for key, value in data.items():
        console.print(f"[bold]{key}[/bold]: {value}")


@project_app.command("create")
def project_create(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Human-readable project name.")],
    slug: Annotated[
        str | None,
        typer.Option(help="Stable lowercase project reference."),
    ] = None,
    description: Annotated[
        str, typer.Option(help="Optional project description.")
    ] = "",
    package: Annotated[
        list[str] | None,
        typer.Option("--package", help="Authorized Android package; repeatable."),
    ] = None,
    host: Annotated[
        list[str] | None,
        typer.Option("--host", help="Authorized API host; repeatable."),
    ] = None,
) -> None:
    """Create a project and its initial authorization scope."""

    runtime = _runtime(ctx)
    project_slug = slug or _slugify(name)
    scope = {"packages": sorted(package or []), "hosts": sorted(host or [])}
    try:
        project = runtime.database.create_project(
            Project(slug=project_slug, name=name, description=description, scope=scope)
        )
    except (ConflictError, ValidationError, ValueError) as exc:
        _fail(str(exc))
    _emit(
        ctx,
        project.model_dump(mode="json"),
        f"Created project {project.slug} ({project.id})",
    )


@project_app.command("list")
def project_list(ctx: typer.Context) -> None:
    """List local projects."""

    projects = _runtime(ctx).database.list_projects()
    if _state(ctx).json_output:
        _print_json([project.model_dump(mode="json") for project in projects])
        return
    if not projects:
        console.print("No projects found.")
        return
    table = Table(title="Projects")
    table.add_column("Slug")
    table.add_column("Name")
    table.add_column("ID")
    table.add_column("Created")
    for project in projects:
        table.add_row(
            project.slug, project.name, project.id, project.created_at.isoformat()
        )
    console.print(table)


@project_app.command("show")
def project_show(
    ctx: typer.Context,
    reference: Annotated[str, typer.Argument(help="Project slug or ID.")],
) -> None:
    """Show a project's metadata and authorized scope."""

    project = _get_project(ctx, reference)
    _emit(
        ctx,
        project.model_dump(mode="json"),
        f"{project.name} ({project.id})\nScope: {project.scope}",
    )


@artifact_app.command("import")
def artifact_import(
    ctx: typer.Context,
    project: Annotated[str, typer.Argument(help="Project slug or ID.")],
    source: Annotated[Path, typer.Argument(help="Path to an authorized artifact.")],
) -> None:
    """Copy a file into content-addressed immutable project storage."""

    runtime = _runtime(ctx)
    resolved_project = _get_project_from_runtime(runtime, project)
    try:
        artifact = runtime.artifacts.import_file(resolved_project.id, source)
        artifact = runtime.database.save_artifact(artifact)
    except (ArtifactStoreError, FileNotFoundError, OSError, ValueError) as exc:
        _fail(str(exc))
    _emit(
        ctx,
        artifact.model_dump(mode="json"),
        f"Imported {artifact.original_name}\nSHA-256: {artifact.sha256}\nArtifact: {artifact.id}",
    )


@artifact_app.command("list")
def artifact_list(
    ctx: typer.Context,
    project: Annotated[str, typer.Argument(help="Project slug or ID.")],
) -> None:
    """List immutable artifacts associated with a project."""

    runtime = _runtime(ctx)
    resolved_project = _get_project_from_runtime(runtime, project)
    artifacts = runtime.database.list_artifacts(resolved_project.id)
    if _state(ctx).json_output:
        _print_json([artifact.model_dump(mode="json") for artifact in artifacts])
        return
    if not artifacts:
        console.print("No artifacts found.")
        return
    table = Table(title=f"Artifacts — {resolved_project.slug}")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Size")
    table.add_column("SHA-256")
    for artifact in artifacts:
        table.add_row(
            artifact.id,
            artifact.original_name,
            str(artifact.size_bytes),
            artifact.sha256,
        )
    console.print(table)


@apk_app.command("inspect")
def apk_inspect(
    ctx: typer.Context,
    project: Annotated[str, typer.Argument(help="Project slug or ID.")],
    source: Annotated[
        Path,
        typer.Argument(help="Authorized APK, APKM archive, or APKM directory."),
    ],
) -> None:
    """Validate a package and inventory its base and split APKs."""

    run = _run_cli_tool(ctx, project, "apk_inspect", {"path": str(source)})
    base = run.output_data.get("base_apk", {})
    splits = run.output_data.get("split_apks", [])
    _emit(
        ctx,
        _tool_run_payload(run),
        (
            f"Package inspection succeeded ({run.id})\n"
            f"Base: {_mapping_value(base, 'name')}\n"
            f"Splits: {len(splits) if isinstance(splits, list) else 0}"
        ),
    )


@apk_app.command("import")
def apk_import(
    ctx: typer.Context,
    project: Annotated[str, typer.Argument(help="Project slug or ID.")],
    source: Annotated[
        Path,
        typer.Argument(help="Authorized APK, APKM archive, or APKM directory."),
    ],
) -> None:
    """Inspect and import the selected base and split APKs as artifacts."""

    run = _run_cli_tool(ctx, project, "apk_import", {"path": str(source)})
    base = run.output_data.get("base", {})
    splits = run.output_data.get("splits", [])
    artifact = _mapping_value(base, "artifact")
    _emit(
        ctx,
        _tool_run_payload(run),
        (
            f"Android package imported ({run.id})\n"
            f"Base artifact: {_mapping_value(artifact, 'id')}\n"
            f"Split artifacts: {len(splits) if isinstance(splits, list) else 0}"
        ),
    )


@apk_app.command("decompile")
def apk_decompile(
    ctx: typer.Context,
    project: Annotated[str, typer.Argument(help="Project slug or ID.")],
    artifact: Annotated[
        str | None,
        typer.Option(
            "--artifact",
            help="Artifact ID or SHA-256; defaults to the unique base.apk.",
        ),
    ] = None,
    threads: Annotated[int, typer.Option(min=1, max=64, help="JADX worker count.")] = 4,
    timeout_seconds: Annotated[
        float,
        typer.Option("--timeout", min=1.0, max=7_200.0, help="JADX timeout."),
    ] = 900.0,
    force: Annotated[
        bool, typer.Option(help="Replace an existing cached output.")
    ] = False,
    accept_partial: Annotated[
        bool,
        typer.Option(
            help="Accept usable source/manifest output when JADX reports class errors."
        ),
    ] = False,
    show_bad_code: Annotated[
        bool,
        typer.Option(help="Ask JADX to emit inconsistent code with warning comments."),
    ] = False,
    deobfuscate: Annotated[bool, typer.Option("--deobfuscate/--no-deobfuscate")] = True,
    decode_resources: Annotated[
        bool, typer.Option("--resources/--no-resources")
    ] = True,
) -> None:
    """Decompile the selected imported APK into project-confined storage."""

    runtime = _runtime(ctx)
    resolved_project = _get_project_from_runtime(runtime, project)
    selected = _select_apk_artifact(runtime, resolved_project, artifact)
    try:
        apk_path = runtime.artifacts.resolve(selected)
    except ArtifactStoreError as exc:
        _fail(str(exc))
    run = _execute_cli_tool(
        ctx,
        runtime,
        resolved_project,
        "jadx_decompile",
        {
            "apk_path": str(apk_path),
            "threads": threads,
            "timeout_seconds": timeout_seconds,
            "force": force,
            "allow_partial": accept_partial,
            "deobfuscate": deobfuscate,
            "show_inconsistent_code": show_bad_code,
            "decode_resources": decode_resources,
        },
    )
    _emit(
        ctx,
        _tool_run_payload(run),
        (
            f"JADX {run.output_data.get('status', 'succeeded')} ({run.id})\n"
            f"Sources: {run.output_data.get('source_file_count', 0)}\n"
            f"Output: {run.output_data.get('output_dir', '')}"
        ),
    )


@apk_app.command("metadata")
def apk_metadata(
    ctx: typer.Context,
    project: Annotated[str, typer.Argument(help="Project slug or ID.")],
    artifact: Annotated[
        str | None,
        typer.Option(
            "--artifact",
            help="Artifact ID or SHA-256; defaults to the unique base.apk.",
        ),
    ] = None,
) -> None:
    """Inventory APK content, native libraries, and signing evidence."""

    runtime = _runtime(ctx)
    resolved_project = _get_project_from_runtime(runtime, project)
    selected = _select_apk_artifact(runtime, resolved_project, artifact)
    try:
        apk_path = runtime.artifacts.resolve(selected)
    except ArtifactStoreError as exc:
        _fail(str(exc))
    run = _execute_cli_tool(
        ctx,
        runtime,
        resolved_project,
        "apk_metadata",
        {"path": str(apk_path)},
    )
    native_libraries = run.output_data.get("native_libraries", [])
    _emit(
        ctx,
        _tool_run_payload(run),
        (
            f"APK metadata collected ({run.id})\n"
            f"DEX files: {len(run.output_data.get('dex_files', []))}\n"
            f"Native libraries: "
            f"{len(native_libraries) if isinstance(native_libraries, list) else 0}\n"
            f"Signing evidence: "
            f"{_mapping_value(run.output_data.get('signing'), 'status')}"
        ),
    )


@manifest_app.command("analyze")
def manifest_analyze(
    ctx: typer.Context,
    project: Annotated[str, typer.Argument(help="Project slug or ID.")],
    path: Annotated[
        Path | None,
        typer.Option(
            "--path", help="Decoded AndroidManifest.xml; defaults to latest JADX run."
        ),
    ] = None,
) -> None:
    """Analyze permissions, components, and exported attack surface."""

    runtime = _runtime(ctx)
    resolved_project = _get_project_from_runtime(runtime, project)
    manifest_path = path or _latest_jadx_path(runtime, resolved_project, "manifest")
    run = _execute_cli_tool(
        ctx,
        runtime,
        resolved_project,
        "manifest_analyze",
        {"manifest_path": str(manifest_path)},
    )
    permissions = run.output_data.get("permissions", [])
    attack_surface = run.output_data.get("attack_surface", [])
    _emit(
        ctx,
        _tool_run_payload(run),
        (
            f"Manifest analysis succeeded ({run.id})\n"
            f"Package: {run.output_data.get('package_name', '<unknown>')}\n"
            f"Permissions: {len(permissions) if isinstance(permissions, list) else 0}\n"
            f"Exported surface: "
            f"{len(attack_surface) if isinstance(attack_surface, list) else 0}"
        ),
    )


@source_app.command("index")
def source_index(
    ctx: typer.Context,
    project: Annotated[str, typer.Argument(help="Project slug or ID.")],
    root: Annotated[
        Path | None,
        typer.Option("--root", help="Source root; defaults to latest JADX sources."),
    ] = None,
    artifact: Annotated[
        str | None,
        typer.Option("--artifact", help="Artifact ID or SHA-256 for provenance."),
    ] = None,
    vector_backend: Annotated[
        str,
        typer.Option(help="Vector backend: chroma or memory."),
    ] = "chroma",
    embedding_provider: Annotated[
        str,
        typer.Option(help="Embedding provider: hashing or ollama."),
    ] = "hashing",
) -> None:
    """Build a persistent source, summary, and semantic index."""

    runtime = _runtime(ctx)
    resolved_project = _get_project_from_runtime(runtime, project)
    source_root = root or _latest_jadx_path(runtime, resolved_project, "sources")
    artifact_id: str | None = None
    if artifact is not None:
        try:
            artifact_id = runtime.database.get_artifact(
                resolved_project.id, artifact
            ).id
        except NotFoundError as exc:
            _fail(str(exc))
    run = _execute_cli_tool(
        ctx,
        runtime,
        resolved_project,
        "source_index",
        {
            "source_root": str(source_root),
            "artifact_id": artifact_id,
            "vector_backend": vector_backend,
            "embedding_provider": embedding_provider,
        },
    )
    warning_text = _source_index_warning_text(run.output_data)
    index_data = run.output_data.get("index")
    _emit(
        ctx,
        _tool_run_payload(run),
        (
            f"Source index ready ({run.id})\n"
            f"Index: {_mapping_value(index_data, 'id')}\n"
            f"Sources indexed: {run.output_data.get('source_file_count', 0)}\n"
            "Sources skipped: "
            f"{run.output_data.get('skipped_source_file_count', 0)}\n"
            "Oversized fallbacks: "
            f"{run.output_data.get('oversized_fallback_source_file_count', 0)}\n"
            f"Chunks: {run.output_data.get('chunk_count', 0)}\n"
            f"Summaries: {run.output_data.get('summary_count', 0)}\n"
            "Index warnings: "
            f"{run.output_data.get('source_index_warning_count', 0)}"
            f"{warning_text}"
        ),
    )


@source_app.command("search")
def source_search(
    ctx: typer.Context,
    project: Annotated[str, typer.Argument(help="Project slug or ID.")],
    query: Annotated[str, typer.Argument(help="Text or regular expression.")],
    regex: Annotated[bool, typer.Option(help="Interpret query as a regex.")] = False,
    case_sensitive: Annotated[bool, typer.Option(help="Preserve case.")] = False,
    limit: Annotated[
        int, typer.Option("--limit", min=1, max=1_000, help="Maximum hits.")
    ] = 50,
) -> None:
    """Search the latest persisted source index."""

    run = _run_cli_tool(
        ctx,
        project,
        "source_search",
        {
            "query": query,
            "mode": "regex" if regex else "exact",
            "case_sensitive": case_sensitive,
            "max_results": limit,
        },
    )
    hits = run.output_data.get("hits", [])
    _emit(
        ctx,
        _tool_run_payload(run),
        f"Source search returned {len(hits) if isinstance(hits, list) else 0} hits ({run.id})",
    )


@context_app.command("query")
def context_query(
    ctx: typer.Context,
    project: Annotated[str, typer.Argument(help="Project slug or ID.")],
    query: Annotated[str, typer.Argument(help="Analysis question or retrieval goal.")],
    budget: Annotated[
        int,
        typer.Option("--budget", min=100, max=2_000_000, help="Token budget."),
    ] = 60_000,
    limit: Annotated[
        int, typer.Option("--limit", min=1, max=1_000, help="Candidate limit.")
    ] = 20,
    vector_backend: Annotated[
        str, typer.Option(help="Vector backend: chroma or memory.")
    ] = "chroma",
    embedding_provider: Annotated[
        str, typer.Option(help="Embedding provider: hashing or ollama.")
    ] = "hashing",
    known_path: Annotated[
        list[str] | None,
        typer.Option("--known-path", help="Known relevant path prefix; repeatable."),
    ] = None,
) -> None:
    """Retrieve hybrid-ranked source without exceeding a token budget."""

    run = _run_cli_tool(
        ctx,
        project,
        "context_query",
        {
            "query": query,
            "token_budget": budget,
            "limit": limit,
            "vector_backend": vector_backend,
            "embedding_provider": embedding_provider,
            "known_paths": known_path or [],
        },
    )
    packed = run.output_data.get("packed_context", {})
    packed_items = packed.get("items", []) if isinstance(packed, dict) else []
    selected_count = len(packed_items) if isinstance(packed_items, list) else 0
    _emit(
        ctx,
        _tool_run_payload(run),
        (
            f"Context query succeeded ({run.id})\n"
            f"Selected chunks: {selected_count}\n"
            f"Estimated tokens: {_mapping_value(packed, 'used_tokens')} / {budget}"
        ),
    )


@obfuscation_app.command("detect")
def obfuscation_detect(
    ctx: typer.Context,
    project: Annotated[str, typer.Argument(help="Project slug or ID.")],
    root: Annotated[
        Path | None,
        typer.Option("--root", help="Source root; defaults to latest JADX sources."),
    ] = None,
) -> None:
    """Measure initial source-level obfuscation signals."""

    runtime = _runtime(ctx)
    resolved_project = _get_project_from_runtime(runtime, project)
    source_root = root or _latest_jadx_path(runtime, resolved_project, "sources")
    run = _execute_cli_tool(
        ctx,
        runtime,
        resolved_project,
        "detect_obfuscation",
        {"source_root": str(source_root)},
    )
    _emit(
        ctx,
        _tool_run_payload(run),
        (
            f"Obfuscation analysis succeeded ({run.id})\n"
            f"Classification: {run.output_data.get('kind', '')}\n"
            f"Confidence: {run.output_data.get('confidence', 0)}"
        ),
    )


@report_app.command("static")
def report_static(
    ctx: typer.Context,
    project: Annotated[str, typer.Argument(help="Project slug or ID.")],
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            help="Markdown path inside the data directory; uses reports/ by default.",
        ),
    ] = None,
    goal: Annotated[
        str | None,
        typer.Option(help="Optional analysis goal recorded in the report."),
    ] = None,
    force: Annotated[
        bool, typer.Option(help="Replace an existing generated report.")
    ] = False,
) -> None:
    """Render the latest persisted Phase 1 results as Markdown."""

    runtime = _runtime(ctx)
    resolved_project = _get_project_from_runtime(runtime, project)
    output_path = output or (
        runtime.settings.data_dir
        / "reports"
        / resolved_project.slug
        / "static-analysis.md"
    )
    output_path = output_path.expanduser().resolve()
    _require_within(output_path, runtime.settings.data_dir.expanduser().resolve())
    if output_path.suffix.casefold() not in {".md", ".markdown"}:
        _fail("static report output must use a .md or .markdown extension")
    if output_path.exists() and not force:
        _fail(f"report already exists; pass --force to replace it: {output_path}")

    apk_run = _latest_successful_run(runtime, resolved_project, ("apk_import",))
    if apk_run is None:
        apk_run = _latest_successful_run(runtime, resolved_project, ("apk_inspect",))
    if apk_run is None:
        _fail("a successful APK inspection or import is required before reporting")
    apk_data: object = apk_run.output_data
    if apk_run.tool_name == "apk_import":
        apk_data = apk_run.output_data.get("inspection")
    if not isinstance(apk_data, dict):
        _fail(f"APK tool run {apk_run.id} has no valid inspection result")
    base_apk = apk_data.get("base_apk")
    if not isinstance(base_apk, dict) or not isinstance(base_apk.get("sha256"), str):
        _fail(f"APK tool run {apk_run.id} has no base APK identity")
    base_sha256 = base_apk["sha256"]
    base_artifact_id = _imported_base_artifact_id(apk_run)

    metadata_run = _latest_matching_run(
        runtime,
        resolved_project,
        ("apk_metadata",),
        lambda candidate: candidate.output_data.get("apk_sha256") == base_sha256,
    )
    jadx_run = _latest_matching_run(
        runtime,
        resolved_project,
        ("jadx_decompile",),
        lambda candidate: candidate.output_data.get("apk_sha256") == base_sha256,
    )
    jadx_output = _run_output_path(jadx_run, "output_dir")
    manifest_run = _latest_matching_run(
        runtime,
        resolved_project,
        ("manifest_analyze",),
        lambda candidate: _path_belongs_to(
            _run_output_path(candidate, "manifest_path"), jadx_output
        ),
    )
    index_run = _latest_matching_run(
        runtime,
        resolved_project,
        ("source_index",),
        lambda candidate: _index_matches_lineage(
            candidate, base_artifact_id, jadx_output
        ),
    )
    index_id = _nested_output_value(index_run, "index", "id")
    source_root = _nested_output_value(index_run, "index", "source_root")
    query_run = _latest_matching_run(
        runtime,
        resolved_project,
        ("context_query",),
        lambda candidate: (
            index_id is not None and candidate.output_data.get("index_id") == index_id
        ),
    )
    obfuscation_run = _latest_matching_run(
        runtime,
        resolved_project,
        ("detect_obfuscation",),
        lambda candidate: (
            source_root is not None
            and candidate.output_data.get("source_root") == source_root
        ),
    )
    related_runs = tuple(
        run
        for run in (
            apk_run,
            metadata_run,
            jadx_run,
            manifest_run,
            obfuscation_run,
            index_run,
            query_run,
        )
        if run is not None
    )
    arguments: dict[str, Any] = {
        "project": {
            "project_id": resolved_project.id,
            "name": resolved_project.name,
            "slug": resolved_project.slug,
            "description": resolved_project.description,
            "analysis_goal": goal,
            "authorization_confirmed": bool(_scope_labels(resolved_project)),
            "authorized_scope": _scope_labels(resolved_project),
        },
        "apk": apk_data,
        "apk_metadata": metadata_run.output_data if metadata_run else None,
        "jadx": jadx_run.output_data if jadx_run else None,
        "manifest": manifest_run.output_data if manifest_run else None,
        "obfuscation": obfuscation_run.output_data if obfuscation_run else None,
        "context": _context_report_data(index_run),
        "source_references": _report_source_references(query_run),
        "tool_run_ids": tuple(run.id for run in related_runs),
    }
    run = _execute_cli_tool(ctx, runtime, resolved_project, "static_report", arguments)
    markdown = run.output_data.get("markdown")
    if not isinstance(markdown, str):  # pragma: no cover - typed tool invariant
        _fail(f"static report tool run {run.id} returned no Markdown")
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(markdown, encoding="utf-8")
    except OSError as exc:
        _fail(f"cannot write static report {output_path}: {exc}")
    payload = _tool_run_payload(run)
    payload["output_path"] = str(output_path)
    _emit(
        ctx,
        payload,
        (
            f"Static report written ({run.id})\n"
            f"Path: {output_path}\n"
            f"SHA-256: {run.output_data.get('markdown_sha256', '')}"
        ),
    )


@tool_app.command("list")
def tool_list(ctx: typer.Context) -> None:
    """List registered tools and their input schemas."""

    schemas = _runtime(ctx).tools.list_schemas()
    if _state(ctx).json_output:
        _print_json(schemas)
        return
    table = Table(title="Registered tools")
    table.add_column("Name")
    table.add_column("Version")
    table.add_column("Description")
    for schema in schemas:
        table.add_row(schema["name"], schema["version"], schema["description"])
    console.print(table)


@tool_app.command("run")
def tool_run(
    ctx: typer.Context,
    project: Annotated[str, typer.Argument(help="Project slug or ID.")],
    tool_name: Annotated[str, typer.Argument(help="Registered tool name.")],
    arguments: Annotated[
        str,
        typer.Option("--arguments", "-a", help="Tool arguments as a JSON object."),
    ] = "{}",
) -> None:
    """Run a registered tool and persist its input, output, and status."""

    runtime = _runtime(ctx)
    resolved_project = _get_project_from_runtime(runtime, project)
    try:
        parsed = json.loads(arguments)
        if not isinstance(parsed, dict):
            raise ValueError("tool arguments must be a JSON object")
    except (json.JSONDecodeError, ValueError) as exc:
        _fail(str(exc))

    try:
        run = _execute_registered_tool(runtime, resolved_project, tool_name, parsed)
    except ToolCommandError as exc:
        _fail(str(exc))
    _emit(
        ctx,
        _tool_run_payload(run),
        f"Tool {tool_name} succeeded ({run.id})\n{run.output_data}",
    )


def _run_cli_tool(
    ctx: typer.Context,
    project_reference: str,
    tool_name: str,
    arguments: dict[str, Any],
) -> ToolRun:
    runtime = _runtime(ctx)
    project = _get_project_from_runtime(runtime, project_reference)
    try:
        return _execute_registered_tool(runtime, project, tool_name, arguments)
    except ToolCommandError as exc:
        _fail(f"{exc} (tool run {exc.run.id})")


def _execute_cli_tool(
    ctx: typer.Context,
    runtime: Runtime,
    project: Project,
    tool_name: str,
    arguments: dict[str, Any],
) -> ToolRun:
    try:
        return _execute_registered_tool(runtime, project, tool_name, arguments)
    except ToolCommandError as exc:
        _fail(f"{exc} (tool run {exc.run.id})")


def _execute_registered_tool(
    runtime: Runtime,
    project: Project,
    tool_name: str,
    arguments: dict[str, Any],
) -> ToolRun:
    """Execute one allowlisted tool and persist success or structured failure."""

    started = utc_now()
    tool_version = "unknown"
    try:
        tool = runtime.tools.get(tool_name)
        tool_version = tool.version
        result = runtime.tools.execute(
            tool_name,
            ToolContext(
                project_id=project.id,
                data_dir=runtime.settings.data_dir,
                database_path=runtime.settings.database_path,
                artifact_root=runtime.settings.artifact_root,
            ),
            arguments,
        )
    except Exception as exc:
        output = _structured_error_output(exc)
        status = _failure_status(output)
        run = ToolRun(
            project_id=project.id,
            tool_name=tool_name,
            tool_version=tool_version,
            status=status,
            input_data=arguments,
            output_data=output,
            error=str(exc),
            started_at=started,
            completed_at=utc_now(),
        )
        runtime.database.record_tool_run(run)
        raise ToolCommandError(str(exc), run) from exc

    run = ToolRun(
        project_id=project.id,
        tool_name=tool.name,
        tool_version=tool.version,
        status=ToolRunStatus.SUCCEEDED,
        input_data=arguments,
        output_data=result.output,
        started_at=started,
        completed_at=utc_now(),
    )
    runtime.database.record_tool_run(run)
    return run


def _structured_error_output(exc: Exception) -> dict[str, Any]:
    result = getattr(exc, "result", None)
    if isinstance(result, BaseModel):
        dumped = result.model_dump(mode="json")
        if isinstance(dumped, dict):
            return dumped
    return {}


def _failure_status(output: dict[str, Any]) -> ToolRunStatus:
    status = output.get("status")
    if status == "timed_out":
        return ToolRunStatus.TIMED_OUT
    if status == "cancelled":
        return ToolRunStatus.CANCELLED
    return ToolRunStatus.FAILED


def _select_apk_artifact(
    runtime: Runtime, project: Project, reference: str | None
) -> Artifact:
    if reference is not None:
        try:
            return runtime.database.get_artifact(project.id, reference)
        except NotFoundError as exc:
            _fail(str(exc))

    artifacts = runtime.database.list_artifacts(project.id)
    bases = [
        artifact
        for artifact in artifacts
        if Path(artifact.original_name).name.casefold() == "base.apk"
    ]
    if not bases and len(artifacts) == 1:
        return artifacts[0]
    if len(bases) == 1:
        return bases[0]
    if not bases:
        _fail(
            "no default APK artifact found; import one or provide --artifact ID/SHA-256"
        )
    _fail("multiple base.apk artifacts found; select one with --artifact ID/SHA-256")


def _latest_jadx_path(runtime: Runtime, project: Project, target: str) -> Path:
    for run in reversed(runtime.database.list_tool_runs(project.id)):
        if run.tool_name != "jadx_decompile" or run.status != ToolRunStatus.SUCCEEDED:
            continue
        raw_output = run.output_data.get("output_dir")
        if not isinstance(raw_output, str):
            continue
        output_dir = Path(raw_output).expanduser().resolve()
        _require_data_path(runtime, project, output_dir)
        if target == "sources":
            candidate = output_dir / "sources"
        elif target == "manifest":
            raw_manifest = run.output_data.get("manifest_path")
            candidate = (
                Path(raw_manifest).expanduser().resolve()
                if isinstance(raw_manifest, str)
                else output_dir / "resources" / "AndroidManifest.xml"
            )
        else:  # pragma: no cover - internal invariant
            raise ValueError(f"unsupported JADX target: {target}")
        _require_data_path(runtime, project, candidate)
        if candidate.exists():
            return candidate
    _fail(f"no usable {target} found in a successful JADX run for {project.slug}")


def _require_data_path(runtime: Runtime, project: Project, path: Path) -> None:
    project_root = (
        (runtime.settings.data_dir / "projects" / project.id).expanduser().resolve()
    )
    try:
        path.relative_to(project_root)
    except ValueError:
        _fail(f"stored tool output escapes the project directory: {path}")


def _tool_run_payload(run: ToolRun) -> dict[str, Any]:
    return {
        "tool_run": run.model_dump(mode="json"),
        "result": run.output_data,
    }


def _mapping_value(value: object, key: str) -> object:
    if isinstance(value, dict):
        return value.get(key, "")
    return ""


def _latest_successful_run(
    runtime: Runtime, project: Project, tool_names: tuple[str, ...]
) -> ToolRun | None:
    return next(
        (
            run
            for run in reversed(runtime.database.list_tool_runs(project.id))
            if run.tool_name in tool_names and run.status == ToolRunStatus.SUCCEEDED
        ),
        None,
    )


def _latest_matching_run(
    runtime: Runtime,
    project: Project,
    tool_names: tuple[str, ...],
    predicate: Callable[[ToolRun], bool],
) -> ToolRun | None:
    return next(
        (
            run
            for run in reversed(runtime.database.list_tool_runs(project.id))
            if run.tool_name in tool_names
            and run.status == ToolRunStatus.SUCCEEDED
            and predicate(run)
        ),
        None,
    )


def _imported_base_artifact_id(run: ToolRun) -> str | None:
    if run.tool_name != "apk_import":
        return None
    base = run.output_data.get("base")
    if not isinstance(base, dict):
        return None
    artifact_id = base.get("artifact_id")
    return artifact_id if isinstance(artifact_id, str) else None


def _run_output_path(run: ToolRun | None, key: str) -> Path | None:
    if run is None:
        return None
    value = run.output_data.get(key)
    if not isinstance(value, str):
        return None
    return Path(value).expanduser().resolve()


def _path_belongs_to(path: Path | None, root: Path | None) -> bool:
    if path is None or root is None:
        return False
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _nested_output_value(run: ToolRun | None, container: str, key: str) -> str | None:
    if run is None:
        return None
    value = run.output_data.get(container)
    if not isinstance(value, dict):
        return None
    nested = value.get(key)
    return nested if isinstance(nested, str) else None


def _index_matches_lineage(
    run: ToolRun, artifact_id: str | None, jadx_output: Path | None
) -> bool:
    index = run.output_data.get("index")
    if not isinstance(index, dict):
        return False
    if artifact_id is not None and index.get("artifact_id") != artifact_id:
        return False
    source_root = index.get("source_root")
    if not isinstance(source_root, str):
        return False
    if jadx_output is not None:
        return Path(source_root).expanduser().resolve() == (jadx_output / "sources")
    return artifact_id is not None


def _scope_labels(project: Project) -> tuple[str, ...]:
    labels: list[str] = []
    for kind, raw_values in sorted(project.scope.items()):
        if isinstance(raw_values, (list, tuple, set)):
            values = raw_values
        else:
            values = (raw_values,)
        labels.extend(
            f"{kind}:{value}"
            for value in values
            if value is not None and str(value).strip()
        )
    return tuple(sorted(set(labels), key=lambda value: (value.casefold(), value)))


def _context_report_data(run: ToolRun | None) -> dict[str, Any] | None:
    if run is None:
        return None
    index = run.output_data.get("index")
    if not isinstance(index, dict):
        return None
    chunk_count = run.output_data.get("chunk_count", 0)
    return {
        "index_id": index.get("id"),
        "source_root": index.get("source_root"),
        "source_file_count": run.output_data.get("source_file_count"),
        "skipped_source_file_count": run.output_data.get(
            "skipped_source_file_count", 0
        ),
        "oversized_fallback_source_file_count": run.output_data.get(
            "oversized_fallback_source_file_count", 0
        ),
        "source_index_warning_count": run.output_data.get(
            "source_index_warning_count", 0
        ),
        "source_index_warnings": _report_source_index_warnings(run.output_data),
        "chunk_count": chunk_count,
        "summary_count": run.output_data.get("summary_count", 0),
        "vector_document_count": chunk_count,
        "embedding_provider": run.output_data.get("embedding_provider"),
    }


def _report_source_index_warnings(output_data: dict[str, Any]) -> tuple[str, ...]:
    raw_warnings = output_data.get("source_index_warnings")
    if not isinstance(raw_warnings, list):
        return ()
    warnings: list[str] = []
    for warning in raw_warnings:
        if not isinstance(warning, dict):
            continue
        path = warning.get("path")
        reason = warning.get("reason")
        detail = warning.get("detail")
        if all(isinstance(value, str) for value in (path, reason, detail)):
            warnings.append(f"{path} ({reason}): {detail}")
    return tuple(warnings)


def _report_source_references(run: ToolRun | None) -> tuple[dict[str, Any], ...]:
    if run is None:
        return ()
    raw_matches = run.output_data.get("matches")
    if not isinstance(raw_matches, list):
        return ()
    query = run.output_data.get("query", "context query")
    references: list[dict[str, Any]] = []
    for match in raw_matches:
        if not isinstance(match, dict):
            continue
        path = match.get("path")
        start_line = match.get("start_line")
        end_line = match.get("end_line")
        if (
            not isinstance(path, str)
            or not isinstance(start_line, int)
            or not isinstance(end_line, int)
        ):
            continue
        references.append(
            {
                "path": path,
                "start_line": start_line,
                "end_line": end_line,
                "symbol": match.get("symbol"),
                "summary": (
                    f"Retrieved for {query!s}; hybrid score {match.get('score', 0)}"
                ),
                "chunk_id": match.get("chunk_id"),
                "tool_run_id": run.id,
            }
        )
    return tuple(references)


def _require_within(path: Path, root: Path) -> None:
    try:
        path.relative_to(root)
    except ValueError:
        _fail(f"path must be within {root}: {path}")


def _state(ctx: typer.Context) -> CliState:
    if not isinstance(ctx.obj, CliState):  # pragma: no cover - framework invariant
        _fail("CLI state is not initialized")
    return ctx.obj


def _runtime(ctx: typer.Context) -> Runtime:
    try:
        return Runtime.create(_state(ctx).settings)
    except (OSError, ValueError) as exc:
        _fail(f"cannot initialize ReverserX: {exc}")


def _get_project(ctx: typer.Context, reference: str) -> Project:
    return _get_project_from_runtime(_runtime(ctx), reference)


def _get_project_from_runtime(runtime: Runtime, reference: str) -> Project:
    try:
        return runtime.database.get_project(reference)
    except NotFoundError as exc:
        _fail(str(exc))


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    if not slug:
        raise typer.BadParameter("project name cannot produce an empty slug")
    return slug


def _source_index_warning_text(output_data: dict[str, Any]) -> str:
    raw_count = output_data.get("source_index_warning_count", 0)
    warning_count = raw_count if isinstance(raw_count, int) else 0
    raw_warnings = output_data.get("source_index_warnings", [])
    warnings = raw_warnings if isinstance(raw_warnings, list) else []
    lines: list[str] = []
    for warning in warnings:
        if not isinstance(warning, dict):
            continue
        path = warning.get("path")
        reason = warning.get("reason")
        detail = warning.get("detail")
        if not all(isinstance(value, str) for value in (path, reason, detail)):
            continue
        lines.append(f"- {path} ({reason}): {detail}")
    omitted = max(0, warning_count - len(lines))
    if omitted:
        lines.append(f"- (+{omitted} additional warnings omitted)")
    return "\n" + "\n".join(lines) if lines else ""


def _emit(ctx: typer.Context, data: Any, human: str) -> None:
    if _state(ctx).json_output:
        _print_json(data)
    else:
        console.print(human)


def _print_json(data: Any) -> None:
    console.print_json(json.dumps(data, default=str, sort_keys=True))


def _fail(message: str) -> NoReturn:
    error_console.print(f"[red]Error:[/red] {message}")
    raise typer.Exit(code=1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
