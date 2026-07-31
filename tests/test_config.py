from pathlib import Path

import pytest

from reverserx.config import Settings, SettingsError


def test_sources_use_expected_precedence(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("log_level: warning\nmax_agent_steps: 10\n", encoding="utf-8")

    settings = Settings.from_sources(
        config,
        environ={
            "REVERSERX_LOG_LEVEL": "DEBUG",
            "ANTHROPIC_API_KEY": "highly-sensitive",
        },
        overrides={"data_dir": tmp_path / "runtime"},
    )

    assert settings.log_level == "DEBUG"
    assert settings.max_agent_steps == 10
    assert settings.data_dir == tmp_path / "runtime"
    assert settings.anthropic_api_key is not None
    assert settings.anthropic_api_key.get_secret_value() == "highly-sensitive"
    assert settings.redacted()["anthropic_api_key"] == "***"
    assert "highly-sensitive" not in str(settings.redacted())


def test_invalid_yaml_root_is_rejected(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("- invalid\n- root\n", encoding="utf-8")

    with pytest.raises(SettingsError, match="configuration root"):
        Settings.from_sources(config, environ={})


def test_storage_names_cannot_escape_data_directory() -> None:
    with pytest.raises(ValueError, match="relative path component"):
        Settings(database_filename="../outside.sqlite3")


def test_explicit_empty_environment_does_not_read_process_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("REVERSERX_LOG_LEVEL", "CRITICAL")

    settings = Settings.from_sources(environ={})

    assert settings.log_level == "INFO"
