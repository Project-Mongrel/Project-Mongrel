"""Bounded SQLite contention handling for Mongrel's operational database."""

import sqlite3
import time
from collections.abc import Callable
from typing import TypeVar

SQLITE_BUSY_TIMEOUT_MS = 500
SQLITE_LOCK_RETRY_ATTEMPTS = 3
SQLITE_LOCK_RETRY_DELAY_SECONDS = 0.05


class OperationalDatabaseBusyError(RuntimeError):
    """Safe application error emitted after bounded lock recovery is exhausted."""

    def __init__(self) -> None:
        super().__init__("Mongrel's data store is temporarily busy. Please try again shortly.")


T = TypeVar("T")


def configure_operational_connection(connection: sqlite3.Connection, *, enable_wal: bool) -> None:
    connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA foreign_keys = ON")
    if enable_wal:
        connection.execute("PRAGMA journal_mode = WAL")


def run_locked_transaction(
    connection: sqlite3.Connection,
    operation: Callable[[sqlite3.Connection], T],
    *,
    attempts: int = SQLITE_LOCK_RETRY_ATTEMPTS,
    delay_seconds: float = SQLITE_LOCK_RETRY_DELAY_SECONDS,
) -> T:
    """Run one replay-safe transaction with bounded retry for lock errors only."""

    if attempts < 1:
        raise ValueError("SQLite transaction attempts must be positive.")
    for attempt in range(attempts):
        try:
            with connection:
                return operation(connection)
        except sqlite3.OperationalError as exc:
            connection.rollback()
            if not is_transient_lock_error(exc):
                raise
            if attempt + 1 >= attempts:
                raise OperationalDatabaseBusyError() from None
            time.sleep(delay_seconds)
    raise OperationalDatabaseBusyError()


def is_transient_lock_error(error: sqlite3.OperationalError) -> bool:
    message = str(error).strip().lower()
    return "database is locked" in message or "database is busy" in message or "database table is locked" in message
