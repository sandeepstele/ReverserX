import pytest

from reverserx.utils.platform import _probe
from reverserx.utils.subprocess import CommandResult


def test_probe_marks_broken_executable_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "reverserx.utils.platform.shutil.which", lambda _name: "/fake/java"
    )
    monkeypatch.setattr(
        "reverserx.utils.platform.run_command",
        lambda *_args, **_kwargs: CommandResult(
            args=("/fake/java", "-version"),
            returncode=1,
            stdout="",
            stderr="Java runtime unavailable",
            duration_seconds=0.01,
        ),
    )

    result = _probe("java", ("-version",), False)

    assert not result.available
    assert result.path == "/fake/java"
    assert result.error == "Java runtime unavailable"
