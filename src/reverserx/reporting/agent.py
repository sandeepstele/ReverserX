"""Evidence-linked Markdown reporting for bounded agent sessions."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from reverserx.core.models import Evidence, Finding, ModelUsage, PlanStep
from reverserx.storage import Database
from reverserx.tools.base import BaseTool, ToolContext, ToolExecution


class AgentReportInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = "ReverserX Agent Analysis"
    force: bool = False


class AgentReportTool(BaseTool[AgentReportInput]):
    name = "agent_report"
    description = (
        "Render the current bounded agent session, findings, model usage, and "
        "tool-evidence locators as a project-confined Markdown report."
    )
    version = "1.0.0"
    input_model = AgentReportInput

    def execute(
        self, context: ToolContext, arguments: AgentReportInput
    ) -> ToolExecution:
        if context.database_path is None or context.session_id is None:
            raise ValueError("agent report requires database and session context")
        database = Database(context.database_path)
        session = database.get_session(context.session_id)
        if session.project_id != context.project_id:
            raise ValueError("agent session does not belong to the tool project")
        steps = database.list_plan_steps(session.id)
        session_tool_runs = {
            item.id
            for item in database.list_tool_runs(context.project_id)
            if item.session_id == session.id
        }
        evidence_by_id = {
            item.id: item
            for item in database.list_evidence(context.project_id)
            if item.tool_run_id in session_tool_runs
        }
        findings = [
            item
            for item in database.list_findings(context.project_id)
            if any(evidence_id in evidence_by_id for evidence_id in item.evidence_ids)
        ]
        usage = database.list_model_usage(session.id)
        output = (
            context.data_dir
            / "reports"
            / context.project_id
            / f"{session.id}-agent-analysis.md"
        ).resolve()
        data_root = context.data_dir.resolve()
        try:
            output.relative_to(data_root)
        except ValueError as exc:  # pragma: no cover - constructed invariant
            raise ValueError("agent report output escapes the data directory") from exc
        if output.exists() and not arguments.force:
            raise ValueError(f"agent report already exists: {output}")
        output.parent.mkdir(parents=True, exist_ok=True)
        markdown = _render(
            arguments.title,
            session.goal,
            session.status.value,
            steps,
            findings,
            evidence_by_id,
            usage,
        )
        output.write_text(markdown, encoding="utf-8")
        return ToolExecution(
            output={
                "report_path": str(output),
                "session_id": session.id,
                "finding_count": len(findings),
                "evidence_reference_count": sum(
                    len(finding.evidence_ids) for finding in findings
                ),
                "actual_cost_usd": round(
                    sum(item.actual_cost_usd or 0 for item in usage), 8
                ),
            },
            notices=(
                "Findings are model interpretations of linked evidence, not proof of "
                "runtime behavior.",
            ),
        )


def _render(
    title: str,
    goal: str,
    status: str,
    steps: list[PlanStep],
    findings: list[Finding],
    evidence_by_id: dict[str, Evidence],
    usage: list[ModelUsage],
) -> str:
    lines = [
        f"# {title.strip() or 'ReverserX Agent Analysis'}",
        "",
        "## Session",
        "",
        f"- Goal: {goal}",
        f"- Status at report generation: {status}",
        f"- Actual model cost so far: ${sum(item.actual_cost_usd or 0 for item in usage):.8f}",
        "",
        "## Plan execution",
        "",
    ]
    for step in steps:
        lines.append(
            f"- Step {step.sequence + 1}: {step.objective} "
            f"(`{step.tool_name}`, {step.status.value}, attempts={step.attempts})"
        )
    if not steps:
        lines.append("No plan steps were persisted.")
    lines.extend(["", "## Candidate findings", ""])
    for finding in findings:
        lines.extend(
            [
                f"### {finding.title}",
                "",
                finding.description,
                "",
                f"Severity: `{finding.severity.value}`; confidence: {finding.confidence:.2f}",
                "",
                "Evidence:",
                "",
            ]
        )
        for evidence_id in finding.evidence_ids:
            evidence = evidence_by_id.get(evidence_id)
            if evidence is None:
                lines.append(f"- Missing evidence record `{evidence_id}`")
            else:
                lines.append(
                    f"- `{evidence.locator}` — {evidence.summary} "
                    f"(tool run `{evidence.tool_run_id or 'none'}`)"
                )
                references = evidence.metadata.get("source_references", [])
                if isinstance(references, list):
                    for reference in references:
                        if not isinstance(reference, dict):
                            continue
                        path = reference.get("path")
                        start_line = reference.get("start_line")
                        end_line = reference.get("end_line")
                        if not isinstance(path, str) or not isinstance(start_line, int):
                            continue
                        location = f"{path}:{start_line}"
                        if isinstance(end_line, int) and end_line != start_line:
                            location += f"-{end_line}"
                        symbol = reference.get("symbol")
                        symbol_text = (
                            f" — `{symbol}`" if isinstance(symbol, str) else ""
                        )
                        lines.append(f"  - `{location}`{symbol_text}")
        lines.append("")
    if not findings:
        lines.append("No candidate findings were recorded.\n")
    lines.extend(
        [
            "## Limitations",
            "",
            "This report contains candidate findings and model interpretations linked to "
            "deterministic tool evidence. Static analysis does not prove runtime behavior. "
            "Partial decompilation, obfuscation, bounded retrieval, and tool-specific limits "
            "must remain visible during analyst review.",
            "",
        ]
    )
    return "\n".join(lines)
