import asyncio
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class ActiveScan:
    user_id: int
    scan_type: str
    target: str
    task: asyncio.Task | None = None
    status_task: asyncio.Task | None = None
    status_message: object | None = None
    cancelled: bool = False
    cancellation_event: threading.Event | None = None
    cancellation_requested: bool = False
    process_cleanup_confirmed: bool = False
    terminal_status: str | None = None
    completion_event: asyncio.Event = field(default_factory=asyncio.Event)
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    progress_started_at: float = field(default_factory=time.monotonic)


_active_scans: dict[int, ActiveScan] = {}


def set_active_scan(
    user_id: int,
    scan_type: str,
    target: str,
    task: asyncio.Task | None = None,
    status_message: object | None = None,
    cancellation_event: threading.Event | None = None,
) -> ActiveScan:
    active_scan = ActiveScan(
        user_id=user_id,
        scan_type=scan_type,
        target=target,
        task=task,
        status_message=status_message,
        cancellation_event=cancellation_event,
    )
    _active_scans[user_id] = active_scan
    return active_scan


def get_active_scan(user_id: int) -> ActiveScan | None:
    return _active_scans.get(user_id)


def set_active_scan_task(user_id: int, task: asyncio.Task) -> None:
    active_scan = _active_scans.get(user_id)
    if active_scan is not None:
        active_scan.task = task


def set_active_scan_status_task(user_id: int, task: asyncio.Task) -> None:
    active_scan = _active_scans.get(user_id)
    if active_scan is not None:
        active_scan.status_task = task


def cancel_active_scan(user_id: int) -> ActiveScan | None:
    active_scan = _active_scans.get(user_id)
    if active_scan is None:
        return None

    if active_scan.process_cleanup_confirmed:
        return active_scan

    active_scan.cancelled = True
    active_scan.cancellation_requested = True
    if active_scan.cancellation_event is not None:
        active_scan.cancellation_event.set()
    elif active_scan.task is not None and not active_scan.task.done():
        # Legacy asynchronous scans (currently Nuclei) have no native runner
        # cancellation token and retain their existing task-cancellation path.
        active_scan.task.cancel()
    if active_scan.status_task is not None and not active_scan.status_task.done():
        active_scan.status_task.cancel()

    return active_scan


def mark_active_scan_process_complete(user_id: int, active_scan: ActiveScan) -> bool:
    current = _active_scans.get(user_id)
    if current is not active_scan:
        return False
    active_scan.process_cleanup_confirmed = True
    return True


def mark_active_scan_terminal(user_id: int, active_scan: ActiveScan, status: str) -> bool:
    current = _active_scans.get(user_id)
    if current is not active_scan:
        return False
    active_scan.terminal_status = str(status or "") or None
    active_scan.completion_event.set()
    return True


def clear_active_scan(user_id: int, active_scan: ActiveScan | None = None) -> None:
    current = _active_scans.get(user_id)
    if active_scan is not None and current is not active_scan:
        return
    _active_scans.pop(user_id, None)


def cancel_all_active_scans() -> list[ActiveScan]:
    """Request native cleanup for every active scanner during application shutdown."""

    active_scans = list(_active_scans.values())
    for active_scan in active_scans:
        cancel_active_scan(active_scan.user_id)
    return active_scans


def clear_all_active_scans() -> None:
    _active_scans.clear()
