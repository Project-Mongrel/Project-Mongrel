import asyncio
import inspect
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.bot.handlers.ask import cancel_handler
from app.bot.handlers.scan import _run_cancellable_scanner
from app.services.active_scan_state import cancel_active_scan, clear_active_scan, get_active_scan
from app.services.scan_manager import complete_scan_request, create_scan_request, get_scan_request


def test_native_cancellable_scanner_avoids_default_executor_and_to_thread() -> None:
    source = inspect.getsource(_run_cancellable_scanner)
    assert "to_thread" not in source
    assert "run_in_executor" not in source
    assert "daemon=True" in source
    assert "SimpleQueue" in source


@pytest.mark.parametrize("scan_type", ["bbot", "testssl", "metasploit", "ffuf"])
def test_native_scanner_cancellation_passes_exact_event_and_cleans_state(scan_type: str) -> None:
    user_id = 9400 + ["bbot", "testssl", "metasploit", "ffuf"].index(scan_type)
    clear_active_scan(user_id)
    runner_started = threading.Event()
    received_event: list[threading.Event] = []
    status_message = SimpleNamespace(edit_text=AsyncMock())
    cancel_message = SimpleNamespace(reply_text=AsyncMock())

    def runner(*args, cancellation_event: threading.Event, **kwargs):
        received_event.append(cancellation_event)
        runner_started.set()
        assert cancellation_event.wait(timeout=2)
        return {
            "success": False,
            "target": "example.com",
            "output": "",
            "error": f"{scan_type} cancelled.",
            "error_type": "cancelled",
        }

    async def run_flow() -> dict:
        task = asyncio.create_task(
            _run_cancellable_scanner(
                user_id=user_id,
                scan_type=scan_type,
                target="example.com",
                status_message=status_message,
                runner=runner,
            )
        )
        while not runner_started.is_set():
            await asyncio.sleep(0)
        active = get_active_scan(user_id)
        assert active is not None
        assert active.task is task
        assert active.cancellation_event is received_event[0]
        await cancel_handler(
            SimpleNamespace(message=cancel_message, effective_user=SimpleNamespace(id=user_id)),
            SimpleNamespace(user_data={}),
        )
        result = await asyncio.wait_for(task, timeout=3)
        assert active.process_cleanup_confirmed is True
        assert active.terminal_status == "cancelled"
        assert active.completion_event.is_set()
        return result

    result = asyncio.run(run_flow())

    assert result["error_type"] == "cancelled"
    assert received_event[0].is_set()
    assert get_active_scan(user_id) is None
    assert status_message.edit_text.await_count == 1
    assert "Cancellation requested" in status_message.edit_text.call_args.args[0]
    assert cancel_message.reply_text.await_count == 1
    assert "Waiting for scanner process cleanup" in cancel_message.reply_text.call_args.args[0]


def test_duplicate_and_unauthorized_cancellation_are_idempotent() -> None:
    user_id = 9450
    other_user_id = 9451
    clear_active_scan(user_id)
    started = threading.Event()
    release = threading.Event()

    def runner(*, cancellation_event: threading.Event):
        started.set()
        release.wait(timeout=2)
        return {
            "success": False,
            "target": "example.com",
            "error": "cancelled",
            "error_type": "cancelled",
        }

    async def run_flow() -> None:
        task = asyncio.create_task(
            _run_cancellable_scanner(
                user_id=user_id,
                scan_type="ffuf",
                target="example.com",
                status_message=None,
                runner=runner,
            )
        )
        while not started.is_set():
            await asyncio.sleep(0)
        active = get_active_scan(user_id)
        assert active is not None
        assert cancel_active_scan(other_user_id) is None
        assert active.cancellation_event is not None
        assert active.cancellation_event.is_set() is False
        assert cancel_active_scan(user_id) is active
        assert cancel_active_scan(user_id) is active
        assert active.cancellation_event.is_set() is True
        release.set()
        await asyncio.wait_for(task, timeout=3)

    asyncio.run(run_flow())
    assert get_active_scan(user_id) is None


def test_natural_completion_wins_after_process_cleanup_is_confirmed() -> None:
    user_id = 9460
    clear_active_scan(user_id)
    observed_active = []

    def runner(*, cancellation_event: threading.Event):
        observed_active.append(get_active_scan(user_id))
        return {"success": True, "target": "example.com", "output": "ok", "error": ""}

    result = asyncio.run(
        _run_cancellable_scanner(
            user_id=user_id,
            scan_type="bbot",
            target="example.com",
            status_message=None,
            runner=runner,
        )
    )

    assert result["success"] is True
    assert observed_active[0] is not None
    assert observed_active[0].process_cleanup_confirmed is True
    assert observed_active[0].terminal_status == "completed"
    assert cancel_active_scan(user_id) is None


def test_natural_completion_wins_when_late_cancellation_did_not_change_runner_result() -> None:
    user_id = 9461
    clear_active_scan(user_id)
    started = threading.Event()
    release = threading.Event()

    def runner(*, cancellation_event: threading.Event):
        started.set()
        release.wait(timeout=2)
        return {"success": True, "target": "example.com", "output": "late", "error": ""}

    async def run_flow() -> dict:
        task = asyncio.create_task(
            _run_cancellable_scanner(
                user_id=user_id,
                scan_type="testssl",
                target="example.com",
                status_message=None,
                runner=runner,
            )
        )
        while not started.is_set():
            await asyncio.sleep(0)
        active = cancel_active_scan(user_id)
        assert active is not None
        release.set()
        return await asyncio.wait_for(task, timeout=3)

    result = asyncio.run(run_flow())
    assert result["success"] is True
    assert result.get("error_type") is None


def test_runner_exception_does_not_leak_active_scan() -> None:
    user_id = 9462
    clear_active_scan(user_id)

    def runner(*, cancellation_event: threading.Event):
        raise RuntimeError("runner failed")

    with pytest.raises(RuntimeError, match="runner failed"):
        asyncio.run(
            _run_cancellable_scanner(
                user_id=user_id,
                scan_type="metasploit",
                target="example.com",
                status_message=None,
                runner=runner,
            )
        )
    assert get_active_scan(user_id) is None


def test_orchestration_task_cancellation_waits_for_native_worker_cleanup() -> None:
    user_id = 9464
    clear_active_scan(user_id)
    started = threading.Event()
    worker_finished = threading.Event()

    def runner(*, cancellation_event: threading.Event):
        started.set()
        assert cancellation_event.wait(timeout=2)
        worker_finished.set()
        return {
            "success": False,
            "target": "example.com",
            "error": "cancelled",
            "error_type": "cancelled",
        }

    async def run_flow() -> None:
        task = asyncio.create_task(
            _run_cancellable_scanner(
                user_id=user_id,
                scan_type="bbot",
                target="example.com",
                status_message=None,
                runner=runner,
            )
        )
        while not started.is_set():
            await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=3)

    asyncio.run(run_flow())
    assert worker_finished.is_set()
    assert get_active_scan(user_id) is None


def test_scan_request_uses_existing_cancelled_status_without_schema_change() -> None:
    user_id = 9463
    request = create_scan_request(user_id=user_id, scan_type="ffuf")
    complete_scan_request(
        user_id=user_id,
        scan_request_id=request.id,
        target="example.com",
        result={"success": False, "error_type": "cancelled"},
    )
    assert get_scan_request(user_id, request.id).status == "cancelled"
