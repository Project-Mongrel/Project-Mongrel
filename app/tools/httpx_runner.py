import logging
from pathlib import Path
# Required to run authorized local httpx subprocesses.
import subprocess  # nosec B404
import re
import shutil
import time

from app.core.config import get_settings
from app.services.target_normalizer import normalize_for_httpx
from app.tools.nmap_runner import DANGEROUS_SHELL_CHARACTERS

logger = logging.getLogger(__name__)
HTTPX_NOT_AVAILABLE_ERROR = "httpx executable was not found."
HTTPX_TIMEOUT_ERROR = "httpx scan timed out. Try a smaller target or reduce the scan scope."
MAX_HTTPX_THREADS = 100
MAX_HTTPX_RATE_LIMIT = 500
MAX_HTTPX_REQUEST_TIMEOUT_SECONDS = 30
MAX_HTTPX_RETRIES = 5
MAX_HTTPX_REDIRECTS = 10
MAX_HTTPX_RESPONSE_SIZE_BYTES = 5_000_000
SAFE_HTTPX_PORTS_PATTERN = re.compile(r"^[A-Za-z0-9:,\-]{1,200}$")


def run_httpx_scan(target: str) -> dict[str, object]:
    validated_target = _validate_target(target)
    settings = get_settings()
    executable = _resolve_httpx_executable(settings.httpx_path)
    working_directory = Path.cwd().resolve()
    if executable is None:
        logger.warning(
            "httpx executable missing. Checked PATH lookup and candidate paths: %s",
            [str(candidate) for candidate in _httpx_executable_candidates()],
        )
        return _result(
            target=validated_target,
            success=False,
            error=HTTPX_NOT_AVAILABLE_ERROR,
            error_type="missing_binary",
            elapsed_seconds=0,
            command=None,
            working_directory=working_directory,
        )

    try:
        command = _build_httpx_command(
            executable,
            validated_target,
            threads=settings.httpx_threads,
            rate_limit=settings.httpx_rate_limit,
            request_timeout_seconds=settings.httpx_request_timeout_seconds,
            retries=settings.httpx_retries,
            ports=settings.httpx_ports,
            max_redirects=settings.httpx_max_redirects,
            max_response_size_bytes=settings.httpx_max_response_size_bytes,
        )
    except ValueError as exc:
        logger.warning("httpx configuration rejected: target=%s error=%s", validated_target, exc)
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
    logger.info("httpx scan started: target=%s timeout=%s", validated_target, settings.httpx_scan_timeout_seconds)
    logger.info("httpx subprocess argv: %r", command)
    try:
        completed = subprocess.run(  # nosec B603
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=settings.httpx_scan_timeout_seconds,
            cwd=str(working_directory),
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed_seconds = time.monotonic() - start_time
        logger.warning("httpx scan timed out: target=%s elapsed_seconds=%.2f", validated_target, elapsed_seconds)
        return _result(
            target=validated_target,
            success=False,
            output=exc.stdout or "",
            error=exc.stderr or HTTPX_TIMEOUT_ERROR,
            error_type="timeout",
            elapsed_seconds=elapsed_seconds,
            command=command,
            working_directory=working_directory,
        )
    except FileNotFoundError:
        elapsed_seconds = time.monotonic() - start_time
        logger.warning("httpx executable missing: target=%s elapsed_seconds=%.2f", validated_target, elapsed_seconds)
        return _result(
            target=validated_target,
            success=False,
            error=HTTPX_NOT_AVAILABLE_ERROR,
            error_type="missing_binary",
            elapsed_seconds=elapsed_seconds,
            command=command,
            working_directory=working_directory,
        )
    except OSError as exc:
        elapsed_seconds = time.monotonic() - start_time
        logger.warning("httpx execution failed: target=%s elapsed_seconds=%.2f error=%s", validated_target, elapsed_seconds, exc)
        return _result(
            target=validated_target,
            success=False,
            error="httpx execution failed.",
            error_type="execution_failed",
            elapsed_seconds=elapsed_seconds,
            command=command,
            working_directory=working_directory,
        )
    except Exception:
        elapsed_seconds = time.monotonic() - start_time
        logger.exception("httpx runner error: target=%s elapsed_seconds=%.2f", validated_target, elapsed_seconds)
        return _result(
            target=validated_target,
            success=False,
            error="httpx runner error.",
            error_type="runner_error",
            elapsed_seconds=elapsed_seconds,
            command=command,
            working_directory=working_directory,
        )

    elapsed_seconds = time.monotonic() - start_time
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    logger.info(
        "httpx scan completed: target=%s elapsed_seconds=%.2f stdout_len=%s stderr_len=%s exit_code=%s",
        validated_target,
        elapsed_seconds,
        len(stdout),
        len(stderr),
        completed.returncode,
    )
    return _result(
        target=validated_target,
        success=completed.returncode == 0,
        output=stdout,
        error=stderr,
        error_type=None if completed.returncode == 0 else "execution_failed",
        returncode=completed.returncode,
        elapsed_seconds=elapsed_seconds,
        command=command,
        working_directory=working_directory,
    )


def _validate_target(target: str) -> str:
    if any(character in str(target or "") for character in DANGEROUS_SHELL_CHARACTERS):
        raise ValueError("httpx target contains unsupported shell characters.")
    return normalize_for_httpx(target)


def _resolve_httpx_executable(configured_path: str = "httpx") -> str | None:
    if configured_path and configured_path != "httpx":
        return configured_path

    path_executable = shutil.which("httpx")
    if path_executable:
        return path_executable

    for candidate in _httpx_executable_candidates():
        if candidate.is_file():
            return str(candidate)
    return None


def _httpx_executable_candidates() -> tuple[Path, Path, Path, Path, Path]:
    return (
        Path("/usr/local/bin/httpx"),
        Path("/usr/bin/httpx"),
        Path.home() / "go" / "bin" / "httpx",
        Path(".venv") / "Scripts" / "httpx.exe",
        Path(".venv") / "bin" / "httpx",
    )


def _build_httpx_command(
    executable: str,
    target: str,
    *,
    threads: int = 25,
    rate_limit: int = 100,
    request_timeout_seconds: int = 10,
    retries: int = 1,
    ports: str = "http:80,8080,8000,8888,https:443,8443",
    max_redirects: int = 3,
    max_response_size_bytes: int = 1_000_000,
) -> list[str]:
    safe_threads = _bounded_int(threads, minimum=1, maximum=MAX_HTTPX_THREADS, default=25)
    safe_rate_limit = _bounded_int(rate_limit, minimum=1, maximum=MAX_HTTPX_RATE_LIMIT, default=100)
    safe_timeout = _bounded_int(request_timeout_seconds, minimum=1, maximum=MAX_HTTPX_REQUEST_TIMEOUT_SECONDS, default=10)
    safe_retries = _bounded_int(retries, minimum=0, maximum=MAX_HTTPX_RETRIES, default=1)
    safe_redirects = _bounded_int(max_redirects, minimum=0, maximum=MAX_HTTPX_REDIRECTS, default=3)
    safe_response_size = _bounded_int(
        max_response_size_bytes,
        minimum=1_024,
        maximum=MAX_HTTPX_RESPONSE_SIZE_BYTES,
        default=1_000_000,
    )
    safe_ports = _normalize_httpx_ports(ports)

    command = [
        executable,
        "-u",
        target,
        "-json",
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-server",
        "-content-length",
        "-content-type",
        "-location",
        "-response-time",
        "-method",
        "-ip",
        "-cdn",
        "-cname",
        "-asn",
        "-probe",
        "-tls-probe",
        "-tls-grab",
        "-follow-host-redirects",
        "-maxr",
        str(safe_redirects),
        "-t",
        str(safe_threads),
        "-rl",
        str(safe_rate_limit),
        "-timeout",
        str(safe_timeout),
        "-retries",
        str(safe_retries),
        "-rstr",
        str(safe_response_size),
        "-ob",
    ]
    if safe_ports:
        command.extend(["-ports", safe_ports])
    return command


def _bounded_int(value: object, *, minimum: int, maximum: int, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _normalize_httpx_ports(raw_ports: object) -> str:
    raw = str(raw_ports or "").strip()
    if not raw:
        return ""
    if any(character in raw for character in DANGEROUS_SHELL_CHARACTERS):
        raise ValueError("httpx ports configuration contains unsupported shell characters.")
    if not SAFE_HTTPX_PORTS_PATTERN.fullmatch(raw):
        raise ValueError("httpx ports configuration contains unsupported characters.")

    parts: list[str] = []
    seen: set[str] = set()
    for part in raw.split(","):
        cleaned = part.strip()
        if not cleaned:
            continue
        if cleaned.lower() in seen:
            continue
        seen.add(cleaned.lower())
        parts.append(cleaned)
    if len(parts) > 50:
        raise ValueError("httpx ports configuration exceeds the bounded port list size.")
    return ",".join(parts)


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
) -> dict[str, object]:
    return {
        "target": target,
        "success": success,
        "output": output,
        "error": error,
        "error_type": error_type,
        "returncode": returncode,
        "exit_code": returncode,
        "elapsed_seconds": elapsed_seconds,
        "command": command,
        "working_directory": str(working_directory),
        "stdout_len": len(output or ""),
        "stderr_len": len(error or ""),
    }
