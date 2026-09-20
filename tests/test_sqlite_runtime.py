import sqlite3
import threading
import time

import pytest

from app.services.assessment_store import (
    create_assessment,
    finalize_assessment_scan,
    get_user_assessment,
    list_assessment_scans,
    recover_interrupted_assessment_scans,
    start_assessment_scan,
)
from app.services.findings_store import _get_connection, close_findings_database, configure_findings_database
from app.services.sqlite_runtime import (
    SQLITE_BUSY_TIMEOUT_MS,
    OperationalDatabaseBusyError,
    configure_operational_connection,
    run_locked_transaction,
)


@pytest.fixture(autouse=True)
def isolated_database(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def _connection(path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, timeout=SQLITE_BUSY_TIMEOUT_MS / 1000, check_same_thread=False)
    configure_operational_connection(connection, enable_wal=True)
    connection.execute("CREATE TABLE IF NOT EXISTS contention_test (id INTEGER PRIMARY KEY, value TEXT)")
    connection.commit()
    return connection


def test_lock_released_during_bounded_retry_window(tmp_path) -> None:
    path = tmp_path / "released.db"
    writer = _connection(path)
    locker = _connection(path)
    locker.execute("BEGIN IMMEDIATE")
    locker.execute("INSERT INTO contention_test (id, value) VALUES (1, 'locker')")

    def release_lock() -> None:
        time.sleep(0.6)
        locker.commit()

    release_thread = threading.Thread(target=release_lock)
    release_thread.start()
    try:
        run_locked_transaction(
            writer,
            lambda connection: connection.execute(
                "INSERT INTO contention_test (id, value) VALUES (2, 'writer')"
            ),
        )
    finally:
        release_thread.join(timeout=2)
        locker.close()
        writer.close()

    verification = sqlite3.connect(path)
    assert verification.execute("SELECT COUNT(*) FROM contention_test").fetchone()[0] == 2
    verification.close()


def test_lock_retained_until_retry_exhaustion_returns_controlled_error(tmp_path) -> None:
    path = tmp_path / "retained.db"
    writer = _connection(path)
    locker = _connection(path)
    locker.execute("BEGIN IMMEDIATE")
    locker.execute("INSERT INTO contention_test (id, value) VALUES (1, 'locker')")
    try:
        with pytest.raises(OperationalDatabaseBusyError) as exc_info:
            run_locked_transaction(
                writer,
                lambda connection: connection.execute(
                    "INSERT INTO contention_test (id, value) VALUES (2, 'writer')"
                ),
                attempts=2,
                delay_seconds=0.01,
            )
        assert "temporarily busy" in str(exc_info.value)
        assert str(path) not in str(exc_info.value)
        assert "INSERT" not in str(exc_info.value)
    finally:
        locker.rollback()
        locker.close()
        writer.close()


def test_non_lock_operational_error_is_not_retried(tmp_path) -> None:
    connection = _connection(tmp_path / "non-lock.db")
    calls = 0

    def malformed_operation(active_connection: sqlite3.Connection) -> None:
        nonlocal calls
        calls += 1
        active_connection.execute("INSERT INTO table_that_does_not_exist VALUES (1)")

    try:
        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            run_locked_transaction(connection, malformed_operation)
        assert calls == 1
    finally:
        connection.close()


def test_transaction_retry_rolls_back_and_does_not_duplicate_insert(tmp_path) -> None:
    connection = _connection(tmp_path / "no-duplicate.db")
    calls = 0

    def retry_once(active_connection: sqlite3.Connection) -> None:
        nonlocal calls
        calls += 1
        active_connection.execute("INSERT INTO contention_test (id, value) VALUES (1, 'once')")
        if calls == 1:
            raise sqlite3.OperationalError("database is locked")

    try:
        run_locked_transaction(connection, retry_once, attempts=2, delay_seconds=0)
        assert calls == 2
        assert connection.execute("SELECT COUNT(*) FROM contention_test").fetchone()[0] == 1

        update_calls = 0

        def update_once(active_connection: sqlite3.Connection) -> None:
            nonlocal update_calls
            update_calls += 1
            active_connection.execute("UPDATE contention_test SET value = value || '-updated' WHERE id = 1")
            if update_calls == 1:
                raise sqlite3.OperationalError("database is busy")

        run_locked_transaction(connection, update_once, attempts=2, delay_seconds=0)
        assert update_calls == 2
        assert connection.execute("SELECT value FROM contention_test WHERE id = 1").fetchone()[0] == "once-updated"
    finally:
        connection.close()


def test_operational_connection_enables_wal_busy_timeout_and_foreign_keys() -> None:
    connection = _get_connection()
    assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == SQLITE_BUSY_TIMEOUT_MS
    assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_concurrent_completion_and_startup_interruption_remain_atomic() -> None:
    assessment = create_assessment("Concurrent recovery", user_id=101)
    running = start_assessment_scan(assessment["id"], "ffuf")
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def complete() -> None:
        try:
            barrier.wait(timeout=2)
            finalize_assessment_scan(assessment["id"], running["id"], "completed")
        except BaseException as exc:
            errors.append(exc)

    def recover() -> None:
        try:
            barrier.wait(timeout=2)
            recover_interrupted_assessment_scans()
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=complete), threading.Thread(target=recover)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert not errors
    assert all(not thread.is_alive() for thread in threads)
    scans = list_assessment_scans(assessment["id"])
    assert len(scans) == 1
    assert scans[0]["status"] in {"completed", "interrupted"}


def test_contention_hardening_preserves_assessment_ownership_isolation() -> None:
    first = create_assessment("First", user_id=201)
    second = create_assessment("Second", user_id=202)
    assert get_user_assessment(201, first["id"]) is not None
    assert get_user_assessment(201, second["id"]) is None
