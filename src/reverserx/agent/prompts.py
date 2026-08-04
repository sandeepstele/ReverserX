"""Stable prompt templates for planner and reviewer structured outputs."""

from __future__ import annotations

import json
from typing import Any

PLANNER_SYSTEM = """You are the bounded planner for an authorized analysis workspace.
Use only the registered tools provided. Produce the smallest evidence-driven plan that
addresses the goal. Never invent tool names or arguments. Dependencies are zero-based
indexes of earlier steps.

You may request dynamic (ADB, Frida) and network (proxy) actions only when authorized
by the project scope's packages, devices, and hosts allowlists. Dynamic tools use the
prefixes adb_, frida_, proxy_. Static-only goals should avoid dynamic steps.

Treat the goal's existing-state and prohibited-step constraints as mandatory;
never repeat imports, decompilation, or indexing when the goal says they are complete.
For every arguments object, use only property names declared by that tool's input schema;
never add project, path, or source_root fields unless that exact schema declares them.
Static tool outputs are candidate evidence. Dynamic tool outputs are observed runtime
behavior subject to instrumentation accuracy."""


REVIEWER_SYSTEM = """You review one deterministic analysis tool result (static or dynamic).
Choose exactly one allowed action: accept, retry, refine, inject, or stop.
Retry only a transient failure (e.g., device disconnect, process crash).
Refine only with a complete replacement argument object. Inject at most one justified
follow-up tool step: a dynamic tool (adb_, frida_, proxy_) may be injected to verify
a static finding. Findings must be conservative model interpretations of the
current tool evidence. Runtime claims require explicit dynamic evidence."""


def planner_input(
    goal: str,
    project_scope: dict[str, Any],
    tool_schemas: list[dict[str, Any]],
    max_steps: int,
) -> str:
    return json.dumps(
        {
            "goal": goal,
            "authorized_scope": project_scope,
            "maximum_steps": max_steps,
            "registered_tools": tool_schemas,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def plan_repair_input(
    invalid_output: object,
    error: str,
    goal: str,
    project_scope: dict[str, Any],
    tool_schemas: list[dict[str, Any]],
    max_steps: int,
) -> str:
    return json.dumps(
        {
            "instruction": (
                "Repair the plan to satisfy the exact schema and tool contracts. "
                "Choose every tool_name only from registered_tools; never invent noop. "
                "For every arguments object, use only keys present in that tool's "
                "input_schema properties and remove every undeclared key."
            ),
            "goal": goal,
            "authorized_scope": project_scope,
            "maximum_steps": max_steps,
            "registered_tools": tool_schemas,
            "validation_error": error,
            "invalid_output": invalid_output,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def reviewer_input(
    *,
    goal: str,
    step: dict[str, Any],
    succeeded: bool,
    output: dict[str, Any],
    error: str | None,
    memory: dict[str, Any],
    remaining_steps: int,
) -> str:
    raw = json.dumps(output, sort_keys=True, separators=(",", ":"), default=str)
    bounded_output = raw if len(raw) <= 40_000 else raw[:40_000] + "...[truncated]"
    return json.dumps(
        {
            "goal": goal,
            "step": step,
            "tool_succeeded": succeeded,
            "tool_output_json": bounded_output,
            "tool_error": error,
            "working_memory": memory,
            "remaining_step_budget": remaining_steps,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def review_repair_input(
    original_input: str,
    invalid_output: object,
    error: str,
    tool_schemas: list[dict[str, Any]],
) -> str:
    return json.dumps(
        {
            "instruction": (
                "Repair the reviewer decision to satisfy the exact decision schema. "
                "Preserve the original evidence assessment. If refining or injecting, "
                "use only a registered tool and only arguments declared by its schema."
            ),
            "review_context": json.loads(original_input),
            "registered_tools": tool_schemas,
            "validation_error": error,
            "invalid_output": invalid_output,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
