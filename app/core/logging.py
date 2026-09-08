import logging
import re
import sys

TELEGRAM_BOT_URL_PATTERN = re.compile(r"https://api\.telegram\.org/bot[^/\s]+")
REDACTED_TELEGRAM_BOT_URL = "https://api.telegram.org/bot<REDACTED>"
TELEGRAM_TOKEN_PATTERN = re.compile(r"\b\d{6,}:[A-Za-z0-9_-]{20,}\b")
BEARER_TOKEN_PATTERN = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]+")
SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(authorization|cookie|set-cookie|password|passwd|token|secret|api[_-]?key|"
    r"aws_access_key_id|aws_secret_access_key|aws_session_token)\b(\s*(?:=>|[:=])\s*)([^\s,;]+)"
)


def redact_telegram_bot_tokens(message: object) -> object:
    if not isinstance(message, str):
        return message

    return TELEGRAM_BOT_URL_PATTERN.sub(REDACTED_TELEGRAM_BOT_URL, message)


def redact_sensitive_text(message: object) -> object:
    """Redact common credential forms without logging their values."""

    if not isinstance(message, str):
        return message
    redacted = str(redact_telegram_bot_tokens(message))
    redacted = TELEGRAM_TOKEN_PATTERN.sub("<REDACTED_TELEGRAM_TOKEN>", redacted)
    redacted = BEARER_TOKEN_PATTERN.sub(r"\1<REDACTED>", redacted)
    return SENSITIVE_ASSIGNMENT_PATTERN.sub(lambda match: f"{match.group(1)}{match.group(2)}<REDACTED>", redacted)


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return str(redact_sensitive_text(super().format(record)))


class TelegramTokenRedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_sensitive_text(record.getMessage())
        record.args = ()

        return True


def configure_logging(log_level: str) -> None:
    """Configure process logging for the API application."""

    redaction_filter = TelegramTokenRedactionFilter()
    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(redaction_filter)
    handler.setFormatter(RedactingFormatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))

    logging.basicConfig(
        level=log_level.upper(),
        handlers=[handler],
        force=True,
    )

    logging.getLogger().addFilter(redaction_filter)
