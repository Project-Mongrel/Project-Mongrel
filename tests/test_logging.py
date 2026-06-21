import logging

from app.core.logging import configure_logging, redact_telegram_bot_tokens


def test_telegram_bot_token_url_is_redacted() -> None:
    message = "POST https://api.telegram.org/bot123456:ABCDEF/sendMessage"

    assert redact_telegram_bot_tokens(message) == "POST https://api.telegram.org/bot<REDACTED>/sendMessage"


def test_non_secret_log_message_is_unchanged() -> None:
    message = "AI config: enabled=True provider=ollama"

    assert redact_telegram_bot_tokens(message) == message


def test_configured_bot_token_does_not_appear_in_formatted_log_output() -> None:
    token = "123456:ABCDEF"
    configure_logging("INFO")

    handler = logging.getLogger().handlers[0]
    record = logging.LogRecord(
        name="httpx",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="HTTP Request: POST https://api.telegram.org/bot%s/sendMessage",
        args=(token,),
        exc_info=None,
    )
    for log_filter in handler.filters:
        assert log_filter.filter(record) is True

    output = handler.format(record)
    assert token not in output
    assert "https://api.telegram.org/bot<REDACTED>/sendMessage" in output
