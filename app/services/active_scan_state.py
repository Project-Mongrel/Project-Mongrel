import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class ActiveScan:
    user_id: int
    scan_type: str
    target: str
    task: asyncio.Task | None = None
    cancelled: bool = False
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))


_active_scans: dict[int, ActiveScan] = {}


def set_active_scan(user_id: int, scan_type: str, target: str, task: asyncio.Task | None = None) -> ActiveScan:
    active_scan = ActiveScan(user_id=user_id, scan_type=scan_type, target=target, task=task)
    _active_scans[user_id] = active_scan
    return active_scan


def get_active_scan(user_id: int) -> ActiveScan | None:
    return _active_scans.get(user_id)


def set_active_scan_task(user_id: int, task: asyncio.Task) -> None:
    active_scan = _active_scans.get(user_id)
    if active_scan is not None:
        active_scan.task = task


def cancel_active_scan(user_id: int) -> ActiveScan | None:
    active_scan = _active_scans.get(user_id)
    if active_scan is None:
        return None

    active_scan.cancelled = True
    if active_scan.task is not None and not active_scan.task.done():
        active_scan.task.cancel()

    return active_scan


def clear_active_scan(user_id: int) -> None:
    _active_scans.pop(user_id, None)
