"""Small deterministic tool used to validate the foundation end to end."""

from pydantic import BaseModel, ConfigDict, Field

from reverserx.tools.base import BaseTool, ToolContext, ToolExecution


class EchoInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=10_000)
    repeat: int = Field(default=1, ge=1, le=20)


class EchoTool(BaseTool[EchoInput]):
    name = "echo"
    description = "Return a validated message; used to verify tool execution."
    version = "1.0.0"
    input_model = EchoInput

    def execute(self, context: ToolContext, arguments: EchoInput) -> ToolExecution:
        return ToolExecution(
            output={
                "message": arguments.message,
                "repeat": arguments.repeat,
                "lines": [arguments.message] * arguments.repeat,
                "project_id": context.project_id,
            }
        )
