"""Application settings loaded from defaults, YAML, and environment variables."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from platformdirs import user_data_path
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


class SettingsError(ValueError):
    """Raised when a configuration source cannot be loaded safely."""


class Settings(BaseModel):
    """Validated runtime settings.

    Precedence, from lowest to highest, is defaults, YAML, environment, and
    explicit overrides.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    data_dir: Path = Field(
        default_factory=lambda: user_data_path("reverserx", "ReverserX")
    )
    log_level: str = "INFO"
    database_filename: str = "reverserx.sqlite3"
    artifacts_dirname: str = "artifacts"
    default_token_budget: int = Field(default=60_000, ge=1_000)
    max_agent_steps: int = Field(default=30, ge=1, le=1_000)
    max_tool_retries: int = Field(default=2, ge=0, le=20)
    max_run_cost_usd: float = Field(default=5.0, ge=0)
    hosted_models_enabled: bool = True
    anthropic_api_key: SecretStr | None = None
    deepseek_api_key: SecretStr | None = None
    openai_api_key: SecretStr | None = None

    @field_validator("data_dir", mode="before")
    @classmethod
    def expand_data_dir(cls, value: Any) -> Any:
        if isinstance(value, str):
            return Path(value).expanduser()
        return value

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(f"unsupported log level: {value}")
        return normalized

    @field_validator("database_filename", "artifacts_dirname")
    @classmethod
    def validate_relative_name(cls, value: str) -> str:
        path = Path(value)
        if path.is_absolute() or len(path.parts) != 1 or value in {"", ".", ".."}:
            raise ValueError("must be a single relative path component")
        return value

    @property
    def database_path(self) -> Path:
        return self.data_dir / self.database_filename

    @property
    def artifact_root(self) -> Path:
        return self.data_dir / self.artifacts_dirname

    @classmethod
    def from_sources(
        cls,
        config_file: Path | None = None,
        environ: Mapping[str, str] | None = None,
        overrides: Mapping[str, Any] | None = None,
    ) -> Settings:
        values: dict[str, Any] = {}
        if config_file is not None:
            values.update(_read_yaml(config_file))
        environment = environ if environ is not None else os.environ
        values.update(_read_environment(environment))
        if overrides:
            values.update(
                {key: value for key, value in overrides.items() if value is not None}
            )
        return cls.model_validate(values)

    def redacted(self) -> dict[str, Any]:
        """Return settings safe for diagnostic output and logs."""

        result = self.model_dump(mode="json")
        for name in ("anthropic_api_key", "deepseek_api_key", "openai_api_key"):
            result[name] = "***" if getattr(self, name) is not None else None
        return result


def _read_yaml(path: Path) -> dict[str, Any]:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise SettingsError(f"configuration file does not exist: {resolved}")
    try:
        raw = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise SettingsError(
            f"cannot read configuration file {resolved}: {exc}"
        ) from exc
    if raw is None:
        return {}
    if not isinstance(raw, dict) or not all(isinstance(key, str) for key in raw):
        raise SettingsError("configuration root must be a mapping with string keys")
    return dict(raw)


def _read_environment(environ: Mapping[str, str]) -> dict[str, Any]:
    mapping = {
        "REVERSERX_DATA_DIR": "data_dir",
        "REVERSERX_LOG_LEVEL": "log_level",
        "REVERSERX_DEFAULT_TOKEN_BUDGET": "default_token_budget",
        "REVERSERX_MAX_AGENT_STEPS": "max_agent_steps",
        "REVERSERX_MAX_TOOL_RETRIES": "max_tool_retries",
        "REVERSERX_MAX_RUN_COST_USD": "max_run_cost_usd",
        "REVERSERX_HOSTED_MODELS_ENABLED": "hosted_models_enabled",
        "ANTHROPIC_API_KEY": "anthropic_api_key",
        "DEEPSEEK_API_KEY": "deepseek_api_key",
        "OPENAI_API_KEY": "openai_api_key",
    }
    values: dict[str, Any] = {}
    for env_name, field_name in mapping.items():
        value = environ.get(env_name)
        if value is not None and value != "":
            values[field_name] = value
    return values
