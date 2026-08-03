from pathlib import Path

import pytest

from reverserx.tools import ToolContext, build_default_registry
from reverserx.tools.registry import ToolRegistryError, ToolValidationError


def test_registry_exposes_schema_and_executes_validated_tool(tmp_path: Path) -> None:
    registry = build_default_registry()
    context = ToolContext(project_id="prj_fixture", data_dir=tmp_path)

    result = registry.execute("echo", context, {"message": "hello", "repeat": 2})

    assert "echo" in {schema["name"] for schema in registry.list_schemas()}
    assert result.output["lines"] == ["hello", "hello"]


def test_registry_rejects_unknown_tool(tmp_path: Path) -> None:
    context = ToolContext(project_id="prj_fixture", data_dir=tmp_path)

    with pytest.raises(ToolRegistryError, match="unknown tool"):
        build_default_registry().execute("missing", context, {})


def test_registry_rejects_undeclared_arguments(tmp_path: Path) -> None:
    context = ToolContext(project_id="prj_fixture", data_dir=tmp_path)

    with pytest.raises(ToolValidationError, match="invalid arguments"):
        build_default_registry().execute(
            "echo", context, {"message": "hello", "unexpected": True}
        )
