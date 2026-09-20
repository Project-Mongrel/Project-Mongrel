import asyncio
import logging
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from telegram.error import BadRequest, Conflict, InvalidToken, NetworkError
from telegram.ext._utils.networkloop import network_retry_loop

from app.bot.bot import (
    GENERIC_TELEGRAM_ERROR,
    TELEGRAM_BOOTSTRAP_RETRIES,
    TELEGRAM_FATAL_ERROR_KEY,
    TelegramPollingFatalError,
    build_application,
    run_bot,
    telegram_error_handler,
    telegram_post_stop,
)
from app.core.config import Settings
from app.services.active_scan_state import get_active_scan, set_active_scan


def test_ptb_temporary_polling_failure_recovers_in_same_loop() -> None:
    calls = 0
    running = True
    errors = []

    async def get_updates() -> None:
        nonlocal calls, running
        calls += 1
        if calls == 1:
            raise NetworkError("temporary transport detail")
        running = False

    asyncio.run(
        network_retry_loop(
            action_cb=get_updates,
            on_err_cb=errors.append,
            description="test polling",
            interval=0,
            is_running=lambda: running,
            max_retries=-1,
            repeat_on_success=True,
        )
    )
    assert calls == 2
    assert len(errors) == 1


def test_ptb_repeated_temporary_failures_do_not_create_another_poller() -> None:
    calls = 0
    running = True

    async def get_updates() -> None:
        nonlocal calls, running
        calls += 1
        if calls <= 3:
            raise NetworkError("temporary")
        running = False

    asyncio.run(
        network_retry_loop(
            action_cb=get_updates,
            description="test repeated polling",
            interval=0,
            is_running=lambda: running,
            max_retries=-1,
            repeat_on_success=True,
        )
    )
    assert calls == 4


def test_handler_exception_is_safe_and_next_update_can_be_processed(caplog) -> None:
    secret_detail = "token=must-not-appear"
    failed_update = SimpleNamespace(
        callback_query=None,
        effective_message=SimpleNamespace(reply_text=AsyncMock()),
    )
    context = SimpleNamespace(error=RuntimeError(secret_detail), application=None)
    processed = []

    async def exercise() -> None:
        await telegram_error_handler(failed_update, context)
        processed.append("next-update")

    with caplog.at_level(logging.ERROR):
        asyncio.run(exercise())
    failed_update.effective_message.reply_text.assert_awaited_once_with(GENERIC_TELEGRAM_ERROR)
    assert processed == ["next-update"]
    assert secret_detail not in caplog.text


def test_run_bot_uses_one_library_poller_with_bounded_bootstrap_retries() -> None:
    application = SimpleNamespace(run_polling=Mock(), bot_data={})
    with patch("app.bot.bot.recover_interrupted_assessment_scans", return_value=0), patch(
        "app.bot.bot.build_application", return_value=application
    ) as build:
        run_bot(Settings(_env_file=None, telegram_bot_token="123456:TEST"))

    build.assert_called_once()
    application.run_polling.assert_called_once_with(
        bootstrap_retries=TELEGRAM_BOOTSTRAP_RETRIES,
        drop_pending_updates=False,
    )


def test_invalid_credentials_remain_fatal_and_sanitized() -> None:
    application = SimpleNamespace(run_polling=Mock(side_effect=InvalidToken()), bot_data={})
    with patch("app.bot.bot.recover_interrupted_assessment_scans", return_value=0), patch(
        "app.bot.bot.build_application", return_value=application
    ):
        with pytest.raises(TelegramPollingFatalError, match="authentication failed"):
            run_bot(Settings(_env_file=None, telegram_bot_token="123456:TEST"))


def test_missing_credentials_are_a_permanent_configuration_failure() -> None:
    with pytest.raises(TelegramPollingFatalError, match="credentials are not configured"):
        run_bot(Settings(_env_file=None, telegram_bot_token=""))


def test_polling_conflict_stops_one_poller_and_remains_fatal() -> None:
    application = SimpleNamespace(bot_data={}, stop_running=Mock())
    context = SimpleNamespace(error=Conflict("conflicting poller detail"), application=application)

    asyncio.run(telegram_error_handler(None, context))

    application.stop_running.assert_called_once_with()
    assert application.bot_data[TELEGRAM_FATAL_ERROR_KEY] == "conflict"


def test_permanent_telegram_api_configuration_error_stops_polling() -> None:
    application = SimpleNamespace(bot_data={}, stop_running=Mock())
    context = SimpleNamespace(error=BadRequest("permanent configuration detail"), application=application)

    asyncio.run(telegram_error_handler(None, context))

    application.stop_running.assert_called_once_with()
    assert application.bot_data[TELEGRAM_FATAL_ERROR_KEY] == "telegram_api"


def test_graceful_shutdown_requests_active_scanner_cleanup() -> None:
    user_id = 9901
    cancellation_event = threading.Event()
    set_active_scan(
        user_id=user_id,
        scan_type="ffuf",
        target="redacted-target",
        cancellation_event=cancellation_event,
    )
    with patch("app.bot.bot._cleanup_active_scanners") as cleanup:
        asyncio.run(telegram_post_stop(SimpleNamespace()))

    assert cancellation_event.is_set()
    cleanup.assert_called_once_with()
    assert get_active_scan(user_id) is None


def test_application_registration_is_stable_and_does_not_execute_scanners() -> None:
    settings = Settings(_env_file=None, telegram_bot_token="123456:TEST")
    with patch("app.bot.handlers.scan.run_nmap_scan") as scanner:
        first = build_application(settings)
        second = build_application(settings)

    assert sum(len(handlers) for handlers in first.handlers.values()) == sum(
        len(handlers) for handlers in second.handlers.values()
    )
    assert len(first.error_handlers) == 1
    scanner.assert_not_called()
