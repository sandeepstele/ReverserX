"""ReverserX command-line entry point."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from reverserx import __version__
from reverserx.config import Settings, SettingsError
from reverserx.core.models import Project, ToolRun, ToolRunStatus, utc_now
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
app.add_typer(project_app, name="project")
app.add_typer(artifact_app, name="artifact")
app.add_typer(tool_app, name="tool")
app.add_typer(config_app, name="config")


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
    resolved_project = _get_project(ctx, project)
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
    resolved_project = _get_project(ctx, project)
    try:
        parsed = json.loads(arguments)
        if not isinstance(parsed, dict):
            raise ValueError("tool arguments must be a JSON object")
    except (json.JSONDecodeError, ValueError) as exc:
        _fail(str(exc))

    started = utc_now()
    tool_version = "unknown"
    try:
        tool = runtime.tools.get(tool_name)
        tool_version = tool.version
        result = runtime.tools.execute(
            tool_name,
            ToolContext(
                project_id=resolved_project.id, data_dir=runtime.settings.data_dir
            ),
            parsed,
        )
        run = ToolRun(
            project_id=resolved_project.id,
            tool_name=tool.name,
            tool_version=tool.version,
            status=ToolRunStatus.SUCCEEDED,
            input_data=parsed,
            output_data=result.output,
            started_at=started,
            completed_at=utc_now(),
        )
    except Exception as exc:
        run = ToolRun(
            project_id=resolved_project.id,
            tool_name=tool_name,
            tool_version=tool_version,
            status=ToolRunStatus.FAILED,
            input_data=parsed,
            error=str(exc),
            started_at=started,
            completed_at=utc_now(),
        )
        runtime.database.record_tool_run(run)
        _fail(str(exc))
    runtime.database.record_tool_run(run)
    _emit(
        ctx,
        run.model_dump(mode="json"),
        f"Tool {tool_name} succeeded ({run.id})\n{run.output_data}",
    )


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
    try:
        return _runtime(ctx).database.get_project(reference)
    except NotFoundError as exc:
        _fail(str(exc))


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    if not slug:
        raise typer.BadParameter("project name cannot produce an empty slug")
    return slug


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
