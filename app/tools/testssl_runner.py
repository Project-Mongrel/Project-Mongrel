import logging
from pathlib import Path
# Required to run authorized local testssl.sh subprocesses.
import subprocess  # nosec B404
import re
import shutil
import tempfile
import time
from urllib.parse import urlparse

from app.core.config import get_settings
from app.services.target_normalizer import normalize_for_httpx
from app.tools.nmap_runner import DANGEROUS_SHELL_CHARACTERS

logger = logging.getLogger(__name__)
TESTSSL_NOT_AVAILABLE_ERROR = "testssl.sh executable was not found."
TESTSSL_TIMEOUT_ERROR = "testssl.sh scan timed out. Try a smaller target or run manually with an approved scope."
MAX_TESTSSL_CONNECT_TIMEOUT_SECONDS = 30
MAX_TESTSSL_OPENSSL_TIMEOUT_SECONDS = 30
MAX_TESTSSL_OUTPUT_BYTES = 2_000_000
MAX_TESTSSL_JSON_BYTES = 5_000_000
ALLOWED_TESTSSL_IP_MODES = {"", "one", "4", "6"}
ALLOWED_TESTSSL_STARTTLS_PROTOCOLS = {
    "",
    "ftp",
    "smtp",
    "pop3",
    "imap",
    "xmpp",
    "sieve",
    "xmpp-server",
    "telnet",
    "ldap",
    "irc",
    "lmtp",
    "nntp",
    "postgres",
    "mysql",
}
SAFE_TESTSSL_VALUE_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]+$")
ANSI_CONTROL_PATTERN = re.compile(r"(?:\x1B\[[0-?]*[ -/]*[@-~]|\x1B[@-_][0-?]*[ -/]*[@-~]|[\x00-\x08\x0B\x0C\x0E-\x1F\x7F])")
MAX_TESTSSL_ERROR_BYTES = 2_000


def run_testssl_scan(target: str) -> dict[str, object]:
    validated_target = _validate_target(target)
    settings = get_settings()
    executable = _resolve_testssl_executable(settings.testssl_path)
    working_directory = Path.cwd().resolve()
    if executable is None:
        logger.warning("testssl.sh executable missing. Checked PATH lookup and candidate paths: %s", [str(candidate) for candidate in _testssl_executable_candidates()])
        return _result(
            target=validated_target,
            success=False,
            error=TESTSSL_NOT_AVAILABLE_ERROR,
            error_type="missing_binary",
            elapsed_seconds=0,
            command=None,
            working_directory=working_directory,
        )

    with tempfile.NamedTemporaryFile(prefix="mongrel-testssl-", suffix=".json", delete=False) as json_file:
        json_path = Path(json_file.name)

    try:
        command = _build_testssl_command(executable, validated_target, json_path, settings)
    except ValueError as exc:
        logger.warning("testssl.sh configuration rejected: target=%s error=%s", validated_target, exc)
        try:
            json_path.unlink(missing_ok=True)
        except OSError:
            logger.warning("Unable to remove temporary testssl.sh JSON artifact after config rejection: %s", json_path)
        return _result(
            target=validated_target,
            success=False,
            error=str(exc),
            error_type="invalid_configuration",
            elapsed_seconds=0,
            command=None,
            working_directory=working_directory,
        )
    start_time = time.monotonic()
    logger.info("testssl.sh scan started: target=%s timeout=%s", validated_target, settings.testssl_scan_timeout_seconds)
    logger.info("testssl.sh subprocess argv: %r", command)
    try:
        completed = subprocess.run(  # nosec B603
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=settings.testssl_scan_timeout_seconds,
            cwd=str(working_directory),
            shell=False,
            check=False,
        )
        json_output, json_truncated = _read_bounded_text(
            json_path,
            _bounded_int(
                getattr(settings, "testssl_max_json_bytes", 2_000_000),
                minimum=10_000,
                maximum=MAX_TESTSSL_JSON_BYTES,
                default=2_000_000,
            ),
        )
    except subprocess.TimeoutExpired as exc:
        elapsed_seconds = time.monotonic() - start_time
        logger.warning("testssl.sh scan timed out: target=%s elapsed_seconds=%.2f", validated_target, elapsed_seconds)
        return _result(
            target=validated_target,
            success=False,
            output=exc.stdout or "",
            error=exc.stderr or TESTSSL_TIMEOUT_ERROR,
            error_type="timeout",
            elapsed_seconds=elapsed_seconds,
            command=command,
            working_directory=working_directory,
            json_output="",
        )
    except FileNotFoundError:
        elapsed_seconds = time.monotonic() - start_time
        logger.warning("testssl.sh executable missing: target=%s elapsed_seconds=%.2f", validated_target, elapsed_seconds)
        return _result(
            target=validated_target,
            success=False,
            error=TESTSSL_NOT_AVAILABLE_ERROR,
            error_type="missing_binary",
            elapsed_seconds=elapsed_seconds,
            command=command,
            working_directory=working_directory,
        )
    except OSError as exc:
        elapsed_seconds = time.monotonic() - start_time
        logger.warning("testssl.sh execution failed: target=%s elapsed_seconds=%.2f error=%s", validated_target, elapsed_seconds, exc)
        return _result(
            target=validated_target,
            success=False,
            error="testssl.sh execution failed.",
            error_type="execution_failed",
            elapsed_seconds=elapsed_seconds,
            command=command,
            working_directory=working_directory,
        )
    finally:
        try:
            json_path.unlink(missing_ok=True)
        except OSError:
            logger.warning("Unable to remove temporary testssl.sh JSON artifact: %s", json_path)

    elapsed_seconds = time.monotonic() - start_time
    stdout, stdout_truncated = _bounded_text(
        completed.stdout or "",
        _bounded_int(
            getattr(settings, "testssl_max_output_bytes", 500_000),
            minimum=10_000,
            maximum=MAX_TESTSSL_OUTPUT_BYTES,
            default=500_000,
        ),
        label="stdout",
    )
    stderr, stderr_truncated = _bounded_text(
        completed.stderr or "",
        _bounded_int(
            getattr(settings, "testssl_max_output_bytes", 500_000),
            minimum=10_000,
            maximum=MAX_TESTSSL_OUTPUT_BYTES,
            default=500_000,
        ),
        label="stderr",
    )
    output_truncated = bool(stdout_truncated or stderr_truncated or json_truncated)
    logger.info(
        "testssl.sh scan completed: target=%s elapsed_seconds=%.2f stdout_len=%s stderr_len=%s json_len=%s exit_code=%s",
        validated_target,
        elapsed_seconds,
        len(stdout),
        len(stderr),
        len(json_output),
        completed.returncode,
    )
    return _result(
        target=validated_target,
        success=completed.returncode == 0 and bool(json_output.strip()) and not json_truncated,
        output=stdout,
        error=(
            "testssl.sh JSON output exceeded the configured bounded result size."
            if json_truncated
            else stderr if completed.returncode == 0
            else _failure_error(stderr, stdout)
        ),
        error_type="output_too_large" if json_truncated else None if completed.returncode == 0 and json_output.strip() else "execution_failed",
        returncode=completed.returncode,
        elapsed_seconds=elapsed_seconds,
        command=command,
        working_directory=working_directory,
        json_output=json_output,
        output_truncated=output_truncated,
    )


def _validate_target(target: str) -> str:
    raw_target = str(target or "").strip()
    if any(character in raw_target for character in DANGEROUS_SHELL_CHARACTERS):
        raise ValueError("testssl.sh target contains unsupported shell characters.")
    if "://" in raw_target:
        parsed_raw = urlparse(raw_target)
        if parsed_raw.scheme.lower() not in {"http", "https"} or not parsed_raw.hostname:
            raise ValueError("testssl.sh target must include a hostname or IP address.")
        normalized = raw_target
    else:
        normalized = normalize_for_httpx(target)
    parsed = urlparse(normalized)
    host = parsed.hostname or ""
    if not host:
        raise ValueError("testssl.sh target must include a hostname or IP address.")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("testssl.sh target must include a valid port.") from exc
    display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{display_host}:{port}"


def _resolve_testssl_executable(configured_path: str = "testssl.sh") -> str | None:
    if configured_path and configured_path != "testssl.sh":
        return configured_path
    path_executable = shutil.which("testssl.sh")
    if path_executable:
        return path_executable
    for candidate in _testssl_executable_candidates():
        if candidate.is_file():
            return str(candidate)
    return None


def _testssl_executable_candidates() -> tuple[Path, Path, Path, Path]:
    return (
        Path("/usr/local/bin/testssl.sh"),
        Path("/usr/bin/testssl.sh"),
        Path("testssl.sh"),
        Path(".venv") / "bin" / "testssl.sh",
    )


def _build_testssl_command(executable: str, target: str, json_path: Path, settings: object | None = None) -> list[str]:
    openssl_timeout = _bounded_int(
        getattr(settings, "testssl_openssl_timeout_seconds", 5),
        minimum=1,
        maximum=MAX_TESTSSL_OPENSSL_TIMEOUT_SECONDS,
        default=5,
    )
    ip_mode = _normalize_option_value(getattr(settings, "testssl_ip_mode", ""), field_name="testssl IP mode", allowed=ALLOWED_TESTSSL_IP_MODES)
    starttls_protocol = _normalize_option_value(
        getattr(settings, "testssl_starttls_protocol", ""),
        field_name="testssl STARTTLS protocol",
        allowed=ALLOWED_TESTSSL_STARTTLS_PROTOCOLS,
    )

    command = [
        executable,
        "--jsonfile-pretty",
        str(json_path),
        "--warnings",
        "batch",
        "--openssl-timeout",
        str(openssl_timeout),
        "--quiet",
    ]
    if ip_mode == "4":
        command.append("-4")
    elif ip_mode == "6":
        command.append("-6")
    elif ip_mode == "one":
        command.extend(["--ip", "one"])
    if starttls_protocol:
        command.extend(["--starttls", starttls_protocol])
    if bool(getattr(settings, "testssl_ids_friendly", False)):
        command.append("--ids-friendly")
    command.append(target)
    return command


def _bounded_int(value: object, *, minimum: int, maximum: int, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _normalize_option_value(raw_value: object, *, field_name: str, allowed: set[str]) -> str:
    value = str(raw_value or "").strip().lower()
    if value not in allowed:
        raise ValueError(f"{field_name} contains unsupported value.")
    if value and (any(character in value for character in DANGEROUS_SHELL_CHARACTERS) or not SAFE_TESTSSL_VALUE_PATTERN.fullmatch(value)):
        raise ValueError(f"{field_name} contains unsupported characters.")
    return value


def _read_bounded_text(path: Path, max_bytes: int) -> tuple[str, bool]:
    if not path.exists():
        return "", False
    raw = path.read_bytes()
    text, truncated = _bounded_text(raw.decode("utf-8", errors="replace"), max_bytes, label="json")
    return text, truncated


def _bounded_text(text: str, max_bytes: int, *, label: str) -> tuple[str, bool]:
    encoded = str(text or "").encode("utf-8", errors="ignore")
    if len(encoded) <= max_bytes:
        return str(text or ""), False
    truncated = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return f"{truncated}\n[{label} truncated at {max_bytes} bytes]", True


def _failure_error(stderr: str, stdout: str) -> str:
    diagnostic = stderr or stdout or "testssl.sh did not complete successfully."
    diagnostic = ANSI_CONTROL_PATTERN.sub("", str(diagnostic)).strip()
    if not diagnostic:
        return "testssl.sh did not complete successfully."
    encoded = diagnostic.encode("utf-8", errors="ignore")
    if len(encoded) <= MAX_TESTSSL_ERROR_BYTES:
        return diagnostic
    truncated = encoded[:MAX_TESTSSL_ERROR_BYTES].decode("utf-8", errors="ignore").rstrip()
    return f"{truncated}...[truncated]"


def _result(
    *,
    target: str,
    success: bool,
    output: str = "",
    error: str = "",
    error_type: str | None,
    returncode: int | None = None,
    elapsed_seconds: float,
    command: list[str] | None,
    working_directory: Path,
    json_output: str = "",
    output_truncated: bool = False,
) -> dict[str, object]:
    return {
        "target": target,
        "success": success,
        "output": output,
        "json_output": json_output,
        "error": error,
        "error_type": error_type,
        "returncode": returncode,
        "exit_code": returncode,
        "elapsed_seconds": elapsed_seconds,
        "command": command,
        "working_directory": str(working_directory),
        "stdout_len": len(output or ""),
        "stderr_len": len(error or ""),
        "json_len": len(json_output or ""),
        "output_truncated": output_truncated,
    }
