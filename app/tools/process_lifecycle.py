from __future__ import annotations

import atexit
from dataclasses import dataclass
import os
import signal
# Required for explicit argv-only scanner subprocesses; shell execution is forbidden below.
import subprocess  # nosec B404
import threading
import time
from typing import IO, Callable, Sequence


DEFAULT_TERMINATION_GRACE_SECONDS = 1.0
COMMUNICATE_POLL_SECONDS = 0.1


@dataclass
class ManagedScannerProcess:
    process: subprocess.Popen
    pid: int | None
    process_group_id: int | None
    owns_process_group: bool


@dataclass(frozen=True)
class ScannerExecution:
    stdout: str
    stderr: str
    returncode: int | None
    timed_out: bool = False
    cancelled: bool = False


_active_processes: dict[int, ManagedScannerProcess] = {}
_active_processes_lock = threading.Lock()


def start_scanner_process(
    argv: Sequence[str],
    *,
    stdout: int | IO | None = subprocess.PIPE,
    stderr: int | IO | None = subprocess.PIPE,
    text: bool = True,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    bufsize: int = -1,
    popen_factory: Callable[..., subprocess.Popen] | None = None,
) -> ManagedScannerProcess:
    """Start one scanner with an isolated POSIX session and explicit argv."""
    factory = popen_factory or subprocess.Popen
    kwargs: dict[str, object] = {
        "stdout": stdout,
        "stderr": stderr,
        "text": text,
        "cwd": cwd,
        "shell": False,
    }
    if env is not None:
        kwargs["env"] = env
    if bufsize != -1:
        kwargs["bufsize"] = bufsize
    if os.name == "posix":
        kwargs["start_new_session"] = True

    process = factory(list(argv), **kwargs)  # nosec B603
    pid = _process_pid(process)
    process_group_id = _resolve_owned_process_group(pid)
    managed = ManagedScannerProcess(
        process=process,
        pid=pid,
        process_group_id=process_group_id,
        owns_process_group=process_group_id is not None,
    )
    if pid is not None:
        with _active_processes_lock:
            _active_processes[pid] = managed
    return managed


def run_scanner_process(
    argv: Sequence[str],
    *,
    timeout_seconds: float,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    cancellation_event: threading.Event | None = None,
    termination_grace_seconds: float = DEFAULT_TERMINATION_GRACE_SECONDS,
) -> ScannerExecution:
    managed = start_scanner_process(argv, cwd=cwd, env=env)
    return communicate_with_lifecycle(
        managed,
        timeout_seconds=timeout_seconds,
        cancellation_event=cancellation_event,
        termination_grace_seconds=termination_grace_seconds,
    )


def communicate_with_lifecycle(
    managed: ManagedScannerProcess,
    *,
    timeout_seconds: float,
    cancellation_event: threading.Event | None = None,
    termination_grace_seconds: float = DEFAULT_TERMINATION_GRACE_SECONDS,
) -> ScannerExecution:
    process = managed.process
    deadline = time.monotonic() + max(0.0, float(timeout_seconds))
    timed_out = False
    cancelled = False
    stdout = ""
    stderr = ""
    try:
        while True:
            if cancellation_event is not None and cancellation_event.is_set():
                cancelled = True
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            try:
                stdout, stderr = process.communicate(timeout=min(COMMUNICATE_POLL_SECONDS, remaining))
                break
            except subprocess.TimeoutExpired:
                continue

        if timed_out or cancelled:
            terminate_scanner_process_tree(managed, grace_seconds=termination_grace_seconds)
            stdout, stderr = _bounded_communicate_after_cleanup(process, termination_grace_seconds)
        elif process.returncode not in (None, 0):
            # The direct process may have failed while a descendant remains in its group.
            terminate_scanner_process_tree(managed, grace_seconds=termination_grace_seconds)
    except BaseException:
        terminate_scanner_process_tree(managed, grace_seconds=termination_grace_seconds)
        raise
    finally:
        unregister_scanner_process(managed)
        _close_owned_pipes(process)

    return ScannerExecution(
        stdout=_coerce_text(stdout),
        stderr=_coerce_text(stderr),
        returncode=process.returncode,
        timed_out=timed_out,
        cancelled=cancelled,
    )


def terminate_scanner_process_tree(
    managed: ManagedScannerProcess,
    *,
    grace_seconds: float = DEFAULT_TERMINATION_GRACE_SECONDS,
) -> None:
    """Terminate only the scanner-owned group, then reap its direct child."""
    process = managed.process
    safe_group = _safe_owned_process_group(managed)

    if safe_group is not None:
        _signal_group(safe_group, signal.SIGTERM)
    else:
        _signal_direct_process(process, force=False)

    deadline = time.monotonic() + max(0.0, float(grace_seconds))
    while time.monotonic() < deadline:
        _reap_if_exited(process)
        if safe_group is not None:
            if not _process_group_exists(safe_group):
                break
        elif _process_has_exited(process):
            break
        time.sleep(0.02)

    if safe_group is not None and _process_group_exists(safe_group):
        _signal_group(safe_group, signal.SIGKILL)
    elif safe_group is None and not _process_has_exited(process):
        _signal_direct_process(process, force=True)

    _reap_direct_child(process, grace_seconds=max(0.1, float(grace_seconds)))


def unregister_scanner_process(managed: ManagedScannerProcess) -> None:
    if managed.pid is None:
        return
    with _active_processes_lock:
        _active_processes.pop(managed.pid, None)


def finish_scanner_process(managed: ManagedScannerProcess) -> None:
    unregister_scanner_process(managed)
    _close_owned_pipes(managed.process)


def _process_pid(process: subprocess.Popen) -> int | None:
    pid = getattr(process, "pid", None)
    return pid if isinstance(pid, int) and pid > 0 else None


def _resolve_owned_process_group(pid: int | None) -> int | None:
    if os.name != "posix" or pid is None:
        return None
    try:
        process_group_id = os.getpgid(pid)
        own_group_id = os.getpgrp()
    except (OSError, ProcessLookupError):
        return None
    if process_group_id <= 1 or process_group_id == own_group_id or process_group_id != pid:
        return None
    return process_group_id


def _safe_owned_process_group(managed: ManagedScannerProcess) -> int | None:
    process_group_id = managed.process_group_id
    if not managed.owns_process_group or process_group_id is None or process_group_id <= 1:
        return None
    try:
        if process_group_id == os.getpgrp():
            return None
    except OSError:
        return None
    if managed.pid is None or process_group_id != managed.pid:
        return None
    return process_group_id


def _signal_group(process_group_id: int, signal_number: signal.Signals) -> None:
    try:
        os.killpg(process_group_id, signal_number)
    except (ProcessLookupError, PermissionError):
        pass


def _signal_direct_process(process: subprocess.Popen, *, force: bool) -> None:
    try:
        if _process_has_exited(process):
            return
        if force or not hasattr(process, "terminate"):
            process.kill()
        else:
            process.terminate()
    except (OSError, ProcessLookupError):
        pass


def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _process_has_exited(process: subprocess.Popen) -> bool:
    poll = getattr(process, "poll", None)
    if callable(poll):
        try:
            return poll() is not None
        except OSError:
            return True
    return getattr(process, "returncode", None) is not None


def _reap_if_exited(process: subprocess.Popen) -> None:
    if not _process_has_exited(process):
        return
    try:
        process.wait(timeout=0)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _reap_direct_child(process: subprocess.Popen, *, grace_seconds: float) -> None:
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        _signal_direct_process(process, force=True)
        try:
            process.wait(timeout=grace_seconds)
        except (OSError, subprocess.TimeoutExpired):
            pass
    except OSError:
        pass


def _bounded_communicate_after_cleanup(process: subprocess.Popen, grace_seconds: float) -> tuple[object, object]:
    try:
        return process.communicate(timeout=max(0.1, float(grace_seconds)))
    except subprocess.TimeoutExpired:
        _signal_direct_process(process, force=True)
        try:
            return process.communicate(timeout=max(0.1, float(grace_seconds)))
        except (OSError, subprocess.TimeoutExpired):
            return "", ""
    except OSError:
        return "", ""


def _close_owned_pipes(process: subprocess.Popen) -> None:
    for name in ("stdin", "stdout", "stderr"):
        stream = getattr(process, name, None)
        if stream is None or getattr(stream, "closed", False):
            continue
        try:
            stream.close()
        except OSError:
            pass


def _coerce_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _cleanup_active_scanners() -> None:
    with _active_processes_lock:
        active = list(_active_processes.values())
    for managed in active:
        terminate_scanner_process_tree(managed)
        unregister_scanner_process(managed)


atexit.register(_cleanup_active_scanners)
