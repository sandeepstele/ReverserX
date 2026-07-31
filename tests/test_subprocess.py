import sys
import threading

from reverserx.utils.subprocess import run_command


def test_command_success_and_output_capture() -> None:
    result = run_command((sys.executable, "-c", "print('ready')"))

    assert result.succeeded
    assert result.stdout.strip() == "ready"
    assert result.stderr == ""


def test_command_output_is_bounded() -> None:
    result = run_command((sys.executable, "-c", "print('x' * 10000)"), output_limit=100)

    assert len(result.stdout.encode()) <= 100
    assert result.stdout_truncated


def test_command_timeout_terminates_process() -> None:
    result = run_command(
        (sys.executable, "-c", "import time; time.sleep(5)"), timeout=0.1
    )

    assert result.timed_out
    assert not result.succeeded


def test_command_can_be_cancelled() -> None:
    cancel = threading.Event()
    cancel.set()
    result = run_command(
        (sys.executable, "-c", "import time; time.sleep(5)"),
        cancel_event=cancel,
    )

    assert result.cancelled
    assert not result.succeeded
