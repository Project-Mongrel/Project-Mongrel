import asyncio
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from app.bot.bot import GENERIC_TELEGRAM_ERROR, build_application, telegram_error_handler
from app.core.config import Settings
from app.core.logging import RedactingFormatter, redact_sensitive_text


UNIT_PATH = Path("deploy/systemd/mongrel.service")
TESTSSL_ENV_EXAMPLE_PATH = Path("deploy/systemd/testssl.env.example")
TESTSSL_DROP_IN_PATH = Path("deploy/systemd/mongrel.service.d/testssl-env.conf")
FFUF_ENV_EXAMPLE_PATH = Path("deploy/systemd/ffuf.env.example")
FFUF_DROP_IN_PATH = Path("deploy/systemd/mongrel.service.d/ffuf-env.conf")


def test_systemd_unit_uses_explicit_non_root_runtime_and_venv():
    unit = UNIT_PATH.read_text(encoding="utf-8")
    assert "User=mongrel" in unit
    assert "User=root" not in unit
    assert "WorkingDirectory=/home/mongrel/Project-Mongrel" in unit
    assert "ExecStart=/home/mongrel/Project-Mongrel/.venv/bin/python -m app.bot.bot" in unit
    assert "EnvironmentFile=/etc/mongrel/mongrel.env" in unit
    assert "TELEGRAM_BOT_TOKEN=" not in unit


def test_testssl_configuration_default_and_explicit_override(monkeypatch):
    monkeypatch.delenv("TESTSSL_SCAN_TIMEOUT_SECONDS", raising=False)
    assert Settings(_env_file=None).testssl_scan_timeout_seconds == 600
    assert Settings(_env_file=None, testssl_scan_timeout_seconds=37).testssl_scan_timeout_seconds == 37


def test_production_testssl_override_uses_absolute_path_and_safe_timeout():
    lines = [
        line
        for line in TESTSSL_ENV_EXAMPLE_PATH.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    assert lines == [
        "TESTSSL_PATH=/opt/testssl.sh/testssl.sh",
        "TESTSSL_SCAN_TIMEOUT_SECONDS=600",
    ]
    assignments = [line.partition("=") for line in lines]
    assert all(not name.endswith(("TOKEN", "PASSWORD", "KEY")) for name, _, _value in assignments)


def test_testssl_drop_in_loads_override_after_primary_environment_file():
    unit = UNIT_PATH.read_text(encoding="utf-8")
    drop_in = TESTSSL_DROP_IN_PATH.read_text(encoding="utf-8")
    assert "EnvironmentFile=/etc/mongrel/mongrel.env" in unit
    assert drop_in.splitlines() == ["[Service]", "EnvironmentFile=/etc/mongrel/testssl.env"]


def test_production_ffuf_override_uses_managed_seclists_symlinks():
    lines = [
        line
        for line in FFUF_ENV_EXAMPLE_PATH.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    assert lines == [
        "FFUF_WORDLIST_STANDARD_PATH=/home/mongrel/wordlists/ffuf-standard.txt",
        "FFUF_WORDLIST_DEEP_PATH=/home/mongrel/wordlists/ffuf-deep.txt",
    ]
    documentation = FFUF_ENV_EXAMPLE_PATH.read_text(encoding="utf-8")
    assert "symlinks to SecLists" in documentation
    assert "readable by the mongrel service user" in documentation
    portable_lines = [
        line
        for line in Path(".env.example").read_text(encoding="utf-8").splitlines()
        if line.startswith(("FFUF_WORDLIST_STANDARD_PATH=", "FFUF_WORDLIST_DEEP_PATH="))
    ]
    assert portable_lines == [
        "FFUF_WORDLIST_STANDARD_PATH=",
        "FFUF_WORDLIST_DEEP_PATH=",
    ]


def test_ffuf_drop_in_loads_override_after_primary_environment_file():
    unit = UNIT_PATH.read_text(encoding="utf-8")
    drop_in = FFUF_DROP_IN_PATH.read_text(encoding="utf-8")
    assert "EnvironmentFile=/etc/mongrel/mongrel.env" in unit
    assert drop_in.splitlines() == ["[Service]", "EnvironmentFile=/etc/mongrel/ffuf.env"]


def test_systemd_unit_has_restart_shutdown_and_boot_controls():
    unit = UNIT_PATH.read_text(encoding="utf-8")
    for directive in (
        "Restart=on-failure", "RestartSec=5s", "StartLimitIntervalSec=120", "StartLimitBurst=5",
        "KillSignal=SIGTERM", "KillMode=control-group", "TimeoutStopSec=30s", "SendSIGKILL=yes",
        "WantedBy=multi-user.target", "StandardOutput=journal", "StandardError=journal",
    ):
        assert directive in unit


def test_systemd_unit_has_compatible_security_baseline():
    unit = UNIT_PATH.read_text(encoding="utf-8")
    for directive in (
        "PrivateTmp=true", "ProtectSystem=strict", "ProtectHome=read-only", "ProtectKernelTunables=true",
        "ProtectKernelModules=true", "ProtectKernelLogs=true", "ProtectControlGroups=true",
        "RestrictSUIDSGID=true", "LockPersonality=true", "RestrictRealtime=true", "UMask=0077",
        "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN", "AmbientCapabilities=",
    ):
        assert directive in unit
    assert "CAP_SYS_ADMIN" not in unit
    assert "0.0.0.0" not in unit


def test_logging_redacts_common_secret_forms_and_traceback_text():
    telegram_token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"
    message = (
        f"url=https://api.telegram.org/bot{telegram_token}/getMe token={telegram_token} "
        "Authorization: Bearer abc.def.ghi cookie=session-value AWS_SECRET_ACCESS_KEY=cloud-secret"
    )
    redacted = str(redact_sensitive_text(message))
    assert telegram_token not in redacted
    assert "abc.def.ghi" not in redacted
    assert "session-value" not in redacted
    assert "cloud-secret" not in redacted
    assert redacted.count("<REDACTED") >= 4

    record = logging.LogRecord("test", logging.ERROR, __file__, 1, "password=trace-secret", (), None)
    rendered = RedactingFormatter("%(message)s").format(record)
    assert "trace-secret" not in rendered


def test_application_registers_generic_error_handler():
    application = build_application(Settings(telegram_bot_token="123456789:test-token-value"))
    assert telegram_error_handler in application.error_handlers


def test_unhandled_telegram_error_response_is_generic():
    update = SimpleNamespace(callback_query=None, effective_message=SimpleNamespace(reply_text=AsyncMock()))
    context = SimpleNamespace(error=RuntimeError("token=should-not-reach-telegram"))
    asyncio.run(telegram_error_handler(update, context))
    update.effective_message.reply_text.assert_awaited_once_with(GENERIC_TELEGRAM_ERROR)
    assert "should-not-reach-telegram" not in GENERIC_TELEGRAM_ERROR
