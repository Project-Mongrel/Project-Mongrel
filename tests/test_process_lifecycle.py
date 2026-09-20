import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from unittest.mock import Mock, patch

import pytest

from app.tools.process_lifecycle import (
    ManagedScannerProcess,
    _active_processes,
    _cleanup_active_scanners,
    run_scanner_process,
    start_scanner_process,
    terminate_scanner_process_tree,
)


class FakeProcess:
    def __init__(self, *, pid: int = 1234, returncode: int | None = None) -> None:
        self.pid = pid
        self.returncode = returncode
        self.stdout = None
        self.stderr = None
        self.stdin = None
        self.terminated = False
        self.killed = False
        self.wait_calls = 0

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.wait_calls += 1
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -signal.SIGTERM

    def kill(self):
        self.killed = True
        self.returncode = -signal.SIGKILL


@pytest.mark.skipif(os.name != "posix", reason="POSIX session behavior is authoritative")
def test_start_scanner_process_uses_new_session_and_explicit_argv() -> None:
    process = FakeProcess()
    factory = Mock(return_value=process)

    managed = start_scanner_process(["scanner", "--safe"], popen_factory=factory)

    assert managed.process is process
    factory.assert_called_once()
    assert factory.call_args.args[0] == ["scanner", "--safe"]
    assert factory.call_args.kwargs["shell"] is False
    assert factory.call_args.kwargs["start_new_session"] is True


def test_spawn_failure_is_raised_once_without_retry() -> None:
    factory = Mock(side_effect=FileNotFoundError("missing scanner"))

    with pytest.raises(FileNotFoundError, match="missing scanner"):
        start_scanner_process(["missing-scanner"], popen_factory=factory)

    factory.assert_called_once()


def test_cleanup_terminates_then_kills_owned_group_and_reaps_child() -> None:
    process = FakeProcess()
    managed = ManagedScannerProcess(process, process.pid, process.pid, True)
    signals: list[signal.Signals] = []

    with (
        patch("app.tools.process_lifecycle.os.getpgrp", return_value=9999),
        patch("app.tools.process_lifecycle.os.killpg", side_effect=lambda _pgid, sig: signals.append(sig)),
        patch("app.tools.process_lifecycle._process_group_exists", return_value=True),
    ):
        terminate_scanner_process_tree(managed, grace_seconds=0)

    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert process.wait_calls >= 1


def test_cleanup_handles_group_exit_race_without_signalling_own_group() -> None:
    process = FakeProcess(pid=2222)
    managed = ManagedScannerProcess(process, process.pid, process.pid, True)

    with (
        patch("app.tools.process_lifecycle.os.getpgrp", return_value=process.pid),
        patch("app.tools.process_lifecycle.os.killpg") as kill_group,
    ):
        terminate_scanner_process_tree(managed, grace_seconds=0)

    kill_group.assert_not_called()
    assert process.terminated is True
    assert process.wait_calls >= 1


def test_cleanup_tolerates_process_lookup_race() -> None:
    process = FakeProcess(returncode=0)
    managed = ManagedScannerProcess(process, process.pid, process.pid, True)

    with (
        patch("app.tools.process_lifecycle.os.getpgrp", return_value=9999),
        patch("app.tools.process_lifecycle.os.killpg", side_effect=ProcessLookupError),
    ):
        terminate_scanner_process_tree(managed, grace_seconds=0)

    assert process.wait_calls >= 1


def test_application_shutdown_cleans_registered_scanner() -> None:
    process = FakeProcess()
    managed = ManagedScannerProcess(process, process.pid, process.pid, True)
    _active_processes[process.pid] = managed

    with patch("app.tools.process_lifecycle.terminate_scanner_process_tree") as terminate:
        _cleanup_active_scanners()

    terminate.assert_called_once_with(managed)
    assert process.pid not in _active_processes


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")
def test_timeout_removes_child_and_grandchild_processes(tmp_path: Path) -> None:
    pid_file = tmp_path / "process-tree.pids"
    fixture = (
        "import os,pathlib,subprocess,sys,time;"
        "g=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']);"
        f"pathlib.Path({str(pid_file)!r}).write_text(f'{{os.getpid()}} {{g.pid}}');"
        "print('partial-output',flush=True);"
        "time.sleep(60)"
    )

    result = run_scanner_process(
        [sys.executable, "-c", fixture],
        timeout_seconds=0.5,
        termination_grace_seconds=0.2,
    )

    assert result.timed_out is True
    assert result.stdout.strip() == "partial-output"
    child_pid, grandchild_pid = (int(value) for value in pid_file.read_text(encoding="utf-8").split())
    assert _wait_until_gone(child_pid)
    assert _wait_until_gone(grandchild_pid)


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")
def test_requested_cancellation_stops_process_without_retry() -> None:
    cancellation = threading.Event()
    cancellation.set()

    result = run_scanner_process(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        timeout_seconds=30,
        cancellation_event=cancellation,
        termination_grace_seconds=0.1,
    )

    assert result.cancelled is True
    assert result.timed_out is False


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")
def test_in_flight_cancellation_removes_child_and_grandchild_processes(tmp_path: Path) -> None:
    pid_file = tmp_path / "cancelled-process-tree.pids"
    cancellation = threading.Event()
    fixture = (
        "import os,pathlib,subprocess,sys,time;"
        "g=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']);"
        f"pathlib.Path({str(pid_file)!r}).write_text(f'{{os.getpid()}} {{g.pid}}');"
        "print('partial-before-cancel',flush=True);"
        "time.sleep(60)"
    )

    def request_cancellation() -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not pid_file.exists():
            time.sleep(0.01)
        cancellation.set()

    requester = threading.Thread(target=request_cancellation)
    requester.start()
    try:
        result = run_scanner_process(
            [sys.executable, "-c", fixture],
            timeout_seconds=30,
            cancellation_event=cancellation,
            termination_grace_seconds=0.2,
        )
    finally:
        requester.join(timeout=2)

    assert result.cancelled is True
    assert result.timed_out is False
    assert result.stdout.strip() == "partial-before-cancel"
    child_pid, grandchild_pid = (int(value) for value in pid_file.read_text(encoding="utf-8").split())
    assert _wait_until_gone(child_pid)
    assert _wait_until_gone(grandchild_pid)


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")
def test_success_does_not_send_termination_signal() -> None:
    with patch("app.tools.process_lifecycle.os.killpg") as kill_group:
        result = run_scanner_process(
            [sys.executable, "-c", "print('done')"],
            timeout_seconds=2,
        )

    assert result.returncode == 0
    assert result.stdout.strip() == "done"
    kill_group.assert_not_called()


def _wait_until_gone(pid: int, timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        stat_path = Path(f"/proc/{pid}/stat")
        if not stat_path.exists():
            return True
        try:
            if stat_path.read_text(encoding="utf-8").split()[2] == "Z":
                return True
        except (OSError, IndexError):
            return True
        time.sleep(0.02)
    return False
