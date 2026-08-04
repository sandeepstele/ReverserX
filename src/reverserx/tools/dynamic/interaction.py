"""Manual interaction checkpoint tool for agent-guided dynamic analysis."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from reverserx.tools.base import BaseTool, ToolContext, ToolExecution


class InteractionWaitInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt: str = Field(
        min_length=1,
        max_length=2_000,
        description="Instruction for the user, e.g. 'Tap the login button on the device'",
    )
    timeout_seconds: float = Field(default=120, gt=0, le=3600)


class InteractionWaitTool(BaseTool[InteractionWaitInput]):
    name = "interaction_wait"
    description = (
        "Pause the agent session and prompt the user to perform a manual action "
        "on the device (tap, navigate, login). The agent waits for confirmation."
    )
    version = "1.0.0"
    input_model = InteractionWaitInput

    def execute(
        self, context: ToolContext, arguments: InteractionWaitInput
    ) -> ToolExecution:
        # In a real interactive session, this would display the prompt and
        # wait for user input. For MVP/CLI use, return the prompt as output.
        return ToolExecution(
            output={
                "prompt": arguments.prompt,
                "timeout_seconds": arguments.timeout_seconds,
                "confirmed": False,
                "status": "prompt_displayed",
            },
            notices=(
                f"MANUAL ACTION REQUIRED: {arguments.prompt} "
                f"(timeout: {arguments.timeout_seconds}s). "
                "Confirm when done via the session control interface.",
            ),
        )
