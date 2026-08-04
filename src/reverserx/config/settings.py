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
    max_agent_input_tokens: int = Field(default=500_000, ge=1)
    max_agent_output_tokens: int = Field(default=100_000, ge=1)
    max_agent_wall_time_seconds: float = Field(default=3_600, gt=0)
    max_tool_duration_seconds: float = Field(default=900, gt=0)
    model_output_tokens_per_call: int = Field(default=4_096, ge=128)
    hosted_models_enabled: bool = True
    openai_model: str = "gpt-5.6-sol"
    openai_base_url: str = "https://api.openai.com/v1"
    openai_input_cost_per_million: float = Field(default=5, ge=0)
    openai_output_cost_per_million: float = Field(default=30, ge=0)
    openai_image_cost_per_million: float = Field(default=5, ge=0)
    ollama_model: str = "gpt-oss:20b"
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_image_support: bool = False
    deepseek_model: str = "deepseek-chat"
    deepseek_base_url: str = "https://api.deepseek.com/v1"
    deepseek_input_cost_per_million: float = Field(default=0.27, ge=0)
    deepseek_output_cost_per_million: float = Field(default=1.10, ge=0)
    # Dynamic analysis (Phase 3)
    dynamic_enabled: bool = False
    adb_executable: str = "adb"
    frida_executable: str = "frida"
    mitmproxy_executable: str = "mitmdump"
    adb_timeout_seconds: float = Field(default=30, gt=0)
    frida_script_timeout_seconds: float = Field(default=120, gt=0)
    mitmproxy_port: int = Field(default=8080, ge=1024, le=65535)
    mitmproxy_startup_timeout_seconds: float = Field(default=15, gt=0)
    max_replay_rate: float = Field(default=1.0, ge=0)
    provider_timeout_seconds: float = Field(default=120, gt=0)
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
        "REVERSERX_MAX_AGENT_INPUT_TOKENS": "max_agent_input_tokens",
        "REVERSERX_MAX_AGENT_OUTPUT_TOKENS": "max_agent_output_tokens",
        "REVERSERX_MAX_AGENT_WALL_TIME_SECONDS": "max_agent_wall_time_seconds",
        "REVERSERX_MAX_TOOL_DURATION_SECONDS": "max_tool_duration_seconds",
        "REVERSERX_MODEL_OUTPUT_TOKENS_PER_CALL": "model_output_tokens_per_call",
        "REVERSERX_HOSTED_MODELS_ENABLED": "hosted_models_enabled",
        "REVERSERX_OPENAI_MODEL": "openai_model",
        "REVERSERX_OPENAI_BASE_URL": "openai_base_url",
        "REVERSERX_OPENAI_INPUT_COST_PER_MILLION": ("openai_input_cost_per_million"),
        "REVERSERX_OPENAI_OUTPUT_COST_PER_MILLION": ("openai_output_cost_per_million"),
        "REVERSERX_OPENAI_IMAGE_COST_PER_MILLION": ("openai_image_cost_per_million"),
        "REVERSERX_OLLAMA_MODEL": "ollama_model",
        "REVERSERX_OLLAMA_BASE_URL": "ollama_base_url",
        "REVERSERX_OLLAMA_IMAGE_SUPPORT": "ollama_image_support",
        "REVERSERX_PROVIDER_TIMEOUT_SECONDS": "provider_timeout_seconds",
        "ANTHROPIC_API_KEY": "anthropic_api_key",
        "DEEPSEEK_API_KEY": "deepseek_api_key",
        "DEEPSEEK_MODEL": "deepseek_model",
        "DEEPSEEK_BASE_URL": "deepseek_base_url",
        "DEEPSEEK_INPUT_COST_PER_MILLION": "deepseek_input_cost_per_million",
        "DEEPSEEK_OUTPUT_COST_PER_MILLION": "deepseek_output_cost_per_million",
        "REVERSERX_DYNAMIC_ENABLED": "dynamic_enabled",
        "REVERSERX_ADB_EXECUTABLE": "adb_executable",
        "REVERSERX_FRIDA_EXECUTABLE": "frida_executable",
        "REVERSERX_MITMPROXY_EXECUTABLE": "mitmproxy_executable",
        "REVERSERX_ADB_TIMEOUT_SECONDS": "adb_timeout_seconds",
        "REVERSERX_FRIDA_SCRIPT_TIMEOUT_SECONDS": "frida_script_timeout_seconds",
        "REVERSERX_MITMPROXY_PORT": "mitmproxy_port",
        "REVERSERX_MITMPROXY_STARTUP_TIMEOUT_SECONDS": "mitmproxy_startup_timeout_seconds",
        "REVERSERX_MAX_REPLAY_RATE": "max_replay_rate",
        "OPENAI_API_KEY": "openai_api_key",
    }
    values: dict[str, Any] = {}
    for env_name, field_name in mapping.items():
        value = environ.get(env_name)
        if value is not None and value != "":
            values[field_name] = value
    return values
