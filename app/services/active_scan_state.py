import asyncio
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
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    progress_started_at: float = field(default_factory=time.monotonic)


_active_scans: dict[int, ActiveScan] = {}


def set_active_scan(
    user_id: int,
    scan_type: str,
    target: str,
    task: asyncio.Task | None = None,
    status_message: object | None = None,
) -> ActiveScan:
    active_scan = ActiveScan(
        user_id=user_id,
        scan_type=scan_type,
        target=target,
        task=task,
        status_message=status_message,
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

    active_scan.cancelled = True
    if active_scan.task is not None and not active_scan.task.done():
        active_scan.task.cancel()
    if active_scan.status_task is not None and not active_scan.status_task.done():
        active_scan.status_task.cancel()

    return active_scan


def clear_active_scan(user_id: int) -> None:
    _active_scans.pop(user_id, None)
