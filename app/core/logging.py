import logging
import re
import sys

TELEGRAM_BOT_URL_PATTERN = re.compile(r"https://api\.telegram\.org/bot[^/\s]+")
REDACTED_TELEGRAM_BOT_URL = "https://api.telegram.org/bot<REDACTED>"


def redact_telegram_bot_tokens(message: object) -> object:
    if not isinstance(message, str):
        return message

    return TELEGRAM_BOT_URL_PATTERN.sub(REDACTED_TELEGRAM_BOT_URL, message)


class TelegramTokenRedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_telegram_bot_tokens(record.getMessage())
        record.args = ()

        return True


def configure_logging(log_level: str) -> None:
    """Configure process logging for the API application."""

    redaction_filter = TelegramTokenRedactionFilter()
    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(redaction_filter)

    logging.basicConfig(
        level=log_level.upper(),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        handlers=[handler],
        force=True,
    )

    logging.getLogger().addFilter(redaction_filter)
