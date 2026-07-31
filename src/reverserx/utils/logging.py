"""Central logging setup with defensive secret redaction."""

from __future__ import annotations

import logging
from collections.abc import Iterable


class SecretRedactionFilter(logging.Filter):
    def __init__(self, secrets: Iterable[str]) -> None:
        super().__init__()
        self._secrets = tuple(secret for secret in secrets if secret)

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        for secret in self._secrets:
            message = message.replace(secret, "***")
        record.msg = message
        record.args = ()
        return True


def configure_logging(level: str, secrets: Iterable[str] = ()) -> None:
    handler = logging.StreamHandler()
    handler.addFilter(SecretRedactionFilter(secrets))
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
