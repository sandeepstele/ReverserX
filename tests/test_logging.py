import logging

from reverserx.utils.logging import configure_logging


def test_logging_redacts_configured_secrets(capsys: object) -> None:
    configure_logging("INFO", ["highly-sensitive"])

    logging.getLogger("test").warning("token=highly-sensitive")

    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert "highly-sensitive" not in captured.err
    assert "token=***" in captured.err
