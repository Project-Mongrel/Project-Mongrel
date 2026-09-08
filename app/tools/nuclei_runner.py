import logging
from pathlib import Path
# Required to run authorized local Nuclei subprocesses.
import subprocess  # nosec B404
import re
import shutil
import threading
import time

from app.core.config import get_settings
from app.tools.nmap_runner import DANGEROUS_SHELL_CHARACTERS
from app.services.target_normalizer import normalize_for_nuclei

logger = logging.getLogger(__name__)
NUCLEI_NOT_AVAILABLE_ERROR = "Nuclei executable was not found."
NUCLEI_TIMEOUT_ERROR = "Execution time limit reached."
NUCLEI_DEFAULT_PROCESS_TIMEOUT_SECONDS = 600
MAX_NUCLEI_PROCESS_TIMEOUT_SECONDS = 1800
MAX_NUCLEI_RATE_LIMIT = 300
MAX_NUCLEI_CONCURRENCY = 50
MAX_NUCLEI_BULK_SIZE = 50
MAX_NUCLEI_REQUEST_TIMEOUT = 30
MAX_NUCLEI_RETRIES = 5
MAX_NUCLEI_REDIRECTS = 10
MAX_NUCLEI_RESPONSE_SIZE_READ = 5_000_000
MAX_NUCLEI_OUTPUT_BYTES = 5_000_000
ALLOWED_NUCLEI_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}
ALLOWED_NUCLEI_PROTOCOL_TYPES = {"dns", "http", "ssl", "tcp", "websocket", "whois"}
SAFE_FILTER_PATTERN = re.compile(r"^[A-Za-z0-9_.:/\\,\-*]+$")


def _validate_target(target: str) -> str:
    if any(character in target for character in DANGEROUS_SHELL_CHARACTERS):
        raise ValueError("Nuclei target contains unsupported shell characters.")

    normalized_target = normalize_for_nuclei(target)

    return normalized_target


def run_nuclei_scan(target: str) -> dict[str, object]:
    validated_target = _validate_target(target)
    settings = get_settings()
    executable = _resolve_nuclei_executable(settings.nuclei_path)
    working_directory = Path.cwd().resolve()
    logger.info("Nuclei target normalized: raw_target=%s normalized_target=%s", target, validated_target)
    logger.info("Nuclei resolved executable: %s", executable)
    if executable is None:
        logger.warning(
            "Nuclei executable missing. Checked PATH lookup and candidate paths: %s",
            [str(candidate) for candidate in _nuclei_executable_candidates()],
        )
        return {
            "target": validated_target,
            "success": False,
            "output": "",
            "error": NUCLEI_NOT_AVAILABLE_ERROR,
            "error_type": "missing_binary",
            "returncode": None,
            "elapsed_seconds": 0,
            "command": None,
            "working_directory": str(working_directory),
            "stdout_len": 0,
            "stderr_len": 0,
            "exit_code": None,
        }

    try:
        command = _build_nuclei_command(executable, validated_target, settings)
    except ValueError as exc:
        logger.warning("Nuclei configuration rejected: target=%s error=%s", validated_target, exc)
        return {
            "target": validated_target,
            "success": False,
            "output": "",
            "error": str(exc),
            "error_type": "invalid_configuration",
            "returncode": None,
            "elapsed_seconds": 0,
            "command": None,
            "working_directory": str(working_directory),
            "stdout_len": 0,
            "stderr_len": len(str(exc)),
            "exit_code": None,
        }
    start_time = time.monotonic()
    logger.info(
        "Nuclei scan started: target=%s timeout=%s rate_limit=%s request_timeout=%s retries=%s",
        validated_target,
        _nuclei_process_timeout(settings),
        settings.nuclei_rate_limit,
        settings.nuclei_request_timeout,
        settings.nuclei_retries,
    )
    logger.info("Nuclei subprocess prepared: arg_count=%s", len(command))
    logger.info("Nuclei working directory: %s", working_directory)
    process_timeout_seconds = _nuclei_process_timeout(settings)
    logger.info("Nuclei subprocess timeout: %s", process_timeout_seconds)

    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    try:
        # Command uses explicit args list, shell=False, and a validated target.
        process = subprocess.Popen(  # nosec B603
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=str(working_directory),
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed_seconds = time.monotonic() - start_time
        logger.warning(
            "Nuclei scan timed out: target=%s elapsed_seconds=%.2f stdout_len=%s stderr_len=%s",
            validated_target,
            elapsed_seconds,
            len(exc.stdout or ""),
            len(exc.stderr or ""),
        )
        return {
            "target": validated_target,
            "success": False,
            "output": exc.stdout or "",
            "error": exc.stderr or NUCLEI_TIMEOUT_ERROR,
            "error_type": "timeout",
            "returncode": None,
            "exit_code": None,
            "elapsed_seconds": elapsed_seconds,
            "command": command,
            "working_directory": str(working_directory),
            "stdout_len": len(exc.stdout or ""),
            "stderr_len": len(exc.stderr or ""),
        }
    except FileNotFoundError:
        elapsed_seconds = time.monotonic() - start_time
        logger.warning(
            "Nuclei executable missing: target=%s elapsed_seconds=%.2f stdout_len=0 stderr_len=0",
            validated_target,
            elapsed_seconds,
        )
        return {
            "target": validated_target,
            "success": False,
            "output": "",
            "error": NUCLEI_NOT_AVAILABLE_ERROR,
            "error_type": "missing_binary",
            "returncode": None,
            "exit_code": None,
            "elapsed_seconds": elapsed_seconds,
            "command": command,
            "working_directory": str(working_directory),
            "stdout_len": 0,
            "stderr_len": 0,
        }
    except OSError as exc:
        elapsed_seconds = time.monotonic() - start_time
        logger.warning(
            "Nuclei execution failed: target=%s elapsed_seconds=%.2f error=%s",
            validated_target,
            elapsed_seconds,
            exc,
        )
        return {
            "target": validated_target,
            "success": False,
            "output": "",
            "error": "Nuclei execution failed.",
            "error_type": "execution_failed",
            "returncode": None,
            "exit_code": None,
            "elapsed_seconds": elapsed_seconds,
            "command": command,
            "working_directory": str(working_directory),
            "stdout_len": 0,
            "stderr_len": 0,
        }
    except Exception:
        elapsed_seconds = time.monotonic() - start_time
        logger.exception("Nuclei runner error: target=%s elapsed_seconds=%.2f", validated_target, elapsed_seconds)
        return {
            "target": validated_target,
            "success": False,
            "output": "",
            "error": "Nuclei runner error.",
            "error_type": "runner_error",
            "returncode": None,
            "exit_code": None,
            "elapsed_seconds": elapsed_seconds,
            "command": command,
            "working_directory": str(working_directory),
            "stdout_len": 0,
            "stderr_len": 0,
        }

    max_output_bytes = _bounded_int(
        getattr(settings, "nuclei_max_output_bytes", 2_000_000),
        minimum=10_000,
        maximum=MAX_NUCLEI_OUTPUT_BYTES,
        default=2_000_000,
    )
    stdout_thread = _start_stream_thread(process.stdout, stdout_lines, "stdout", max_output_bytes)
    stderr_thread = _start_stream_thread(process.stderr, stderr_lines, "stderr", max_output_bytes)
    try:
        returncode = process.wait(timeout=process_timeout_seconds)
    except subprocess.TimeoutExpired:
        logger.warning("Nuclei scan timed out after %ss", process_timeout_seconds)
        process.kill()
        returncode = process.wait()
        _join_stream_thread(stdout_thread, "stdout")
        _join_stream_thread(stderr_thread, "stderr")
        elapsed_seconds = time.monotonic() - start_time
        stdout = "\n".join(stdout_lines)
        stderr = "\n".join(stderr_lines)
        logger.warning(
            "Nuclei scan timed out: target=%s elapsed_seconds=%.2f stdout_len=%s stderr_len=%s exit_code=%s",
            validated_target,
            elapsed_seconds,
            len(stdout),
            len(stderr),
            returncode,
        )
        return {
            "target": validated_target,
            "success": False,
            "partial": bool(stdout.strip()),
            "timed_out": True,
            "scan_completed": False,
            "output": stdout,
            "error": stderr or NUCLEI_TIMEOUT_ERROR,
            "error_type": "timeout",
            "timeout_seconds": process_timeout_seconds,
            "timeout_reason": NUCLEI_TIMEOUT_ERROR,
            "returncode": returncode,
            "exit_code": returncode,
            "elapsed_seconds": elapsed_seconds,
            "command": command,
            "working_directory": str(working_directory),
            "stdout_len": len(stdout),
            "stderr_len": len(stderr),
        }

    logger.info("Nuclei process exited: exit_code=%s", returncode)
    _join_stream_thread(stdout_thread, "stdout")
    _join_stream_thread(stderr_thread, "stderr")
    elapsed_seconds = time.monotonic() - start_time
    stdout = "\n".join(stdout_lines)
    stderr = "\n".join(stderr_lines)
    logger.info(
        "Nuclei scan completed: target=%s elapsed_seconds=%.2f stdout_len=%s stderr_len=%s exit_code=%s",
        validated_target,
        elapsed_seconds,
        len(stdout),
        len(stderr),
        returncode,
    )
    return {
        "target": validated_target,
        "success": returncode == 0,
        "partial": False,
        "timed_out": False,
        "scan_completed": returncode == 0,
        "output": stdout,
        "error": stderr,
        "error_type": None if returncode == 0 else "execution_failed",
        "returncode": returncode,
        "exit_code": returncode,
        "elapsed_seconds": elapsed_seconds,
        "command": command,
        "working_directory": str(working_directory),
        "stdout_len": len(stdout),
        "stderr_len": len(stderr),
    }


def _resolve_nuclei_executable(configured_path: str = "nuclei") -> str | None:
    if configured_path and configured_path != "nuclei":
        return configured_path

    path_executable = shutil.which("nuclei")
    if path_executable:
        return path_executable

    for candidate in _nuclei_executable_candidates():
        if candidate.is_file():
            return str(candidate)

    logger.warning(
        "Nuclei executable not found in PATH or candidate paths: %s",
        [str(candidate) for candidate in _nuclei_executable_candidates()],
    )
    return None


def _nuclei_executable_candidates() -> tuple[Path, Path, Path, Path, Path]:
    return (
        Path("/usr/local/bin/nuclei"),
        Path("/usr/bin/nuclei"),
        Path.home() / "go" / "bin" / "nuclei",
        Path(".venv") / "Scripts" / "nuclei.exe",
        Path(".venv") / "bin" / "nuclei",
    )


def _build_nuclei_command(executable: str, target: str, settings: object) -> list[str]:
    severities = _normalize_filter_csv(
        getattr(settings, "nuclei_severities", "info,low,medium,high,critical"),
        allowed=ALLOWED_NUCLEI_SEVERITIES,
        field_name="nuclei severities",
        default="info,low,medium,high,critical",
    )
    exclude_severities = _normalize_filter_csv(
        getattr(settings, "nuclei_exclude_severities", ""),
        allowed=ALLOWED_NUCLEI_SEVERITIES,
        field_name="nuclei excluded severities",
    )
    protocol_types = _normalize_filter_csv(
        getattr(settings, "nuclei_protocol_types", "http,ssl,dns,tcp,whois"),
        allowed=ALLOWED_NUCLEI_PROTOCOL_TYPES,
        field_name="nuclei protocol types",
        default="http,ssl,dns,tcp,whois",
    )
    tags = _normalize_filter_csv(getattr(settings, "nuclei_tags", "exposure,misconfig,tech,panel,headers"), field_name="nuclei tags")
    exclude_tags = _normalize_filter_csv(getattr(settings, "nuclei_exclude_tags", ""), field_name="nuclei excluded tags")
    template_ids = _normalize_filter_csv(getattr(settings, "nuclei_template_ids", ""), field_name="nuclei template ids")
    exclude_template_ids = _normalize_filter_csv(
        getattr(settings, "nuclei_exclude_template_ids", ""),
        field_name="nuclei excluded template ids",
    )
    template_paths = _normalize_filter_csv(getattr(settings, "nuclei_template_paths", ""), field_name="nuclei template paths")
    template_profile = _normalize_single_value(getattr(settings, "nuclei_template_profile", ""), field_name="nuclei template profile")
    rate_limit = _bounded_int(getattr(settings, "nuclei_rate_limit", 25), minimum=1, maximum=MAX_NUCLEI_RATE_LIMIT, default=25)
    concurrency = _bounded_int(getattr(settings, "nuclei_concurrency", 10), minimum=1, maximum=MAX_NUCLEI_CONCURRENCY, default=10)
    bulk_size = _bounded_int(getattr(settings, "nuclei_bulk_size", 10), minimum=1, maximum=MAX_NUCLEI_BULK_SIZE, default=10)
    request_timeout = _bounded_int(
        getattr(settings, "nuclei_request_timeout", 5),
        minimum=1,
        maximum=MAX_NUCLEI_REQUEST_TIMEOUT,
        default=5,
    )
    retries = _bounded_int(getattr(settings, "nuclei_retries", 1), minimum=0, maximum=MAX_NUCLEI_RETRIES, default=1)
    max_redirects = _bounded_int(getattr(settings, "nuclei_max_redirects", 3), minimum=0, maximum=MAX_NUCLEI_REDIRECTS, default=3)
    response_size_read = _bounded_int(
        getattr(settings, "nuclei_response_size_read", 1_048_576),
        minimum=1_024,
        maximum=MAX_NUCLEI_RESPONSE_SIZE_READ,
        default=1_048_576,
    )

    command = [
        executable,
        "-u",
        target,
        "-jsonl",
        "-silent",
        "-no-color",
        "-omit-raw",
        "-omit-template",
        "-disable-update-check",
        "-severity",
        severities,
        "-type",
        protocol_types,
        "-follow-host-redirects",
        "-max-redirects",
        str(max_redirects),
        "-rate-limit",
        str(rate_limit),
        "-concurrency",
        str(concurrency),
        "-bulk-size",
        str(bulk_size),
        "-timeout",
        str(request_timeout),
        "-retries",
        str(retries),
        "-response-size-read",
        str(response_size_read),
        "-no-stdin",
    ]
    if tags:
        command.extend(["-tags", tags])
    if exclude_tags:
        command.extend(["-exclude-tags", exclude_tags])
    if exclude_severities:
        command.extend(["-exclude-severity", exclude_severities])
    if template_ids:
        command.extend(["-template-id", template_ids])
    if exclude_template_ids:
        command.extend(["-exclude-id", exclude_template_ids])
    if template_paths:
        command.extend(["-templates", template_paths])
    if template_profile:
        command.extend(["-profile", template_profile])
    return command


def _nuclei_process_timeout(settings: object) -> int:
    return _bounded_int(
        getattr(settings, "nuclei_scan_timeout_seconds", NUCLEI_DEFAULT_PROCESS_TIMEOUT_SECONDS),
        minimum=60,
        maximum=MAX_NUCLEI_PROCESS_TIMEOUT_SECONDS,
        default=NUCLEI_DEFAULT_PROCESS_TIMEOUT_SECONDS,
    )


def _bounded_int(value: object, *, minimum: int, maximum: int, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _normalize_filter_csv(
    raw_value: object,
    *,
    field_name: str,
    allowed: set[str] | None = None,
    default: str = "",
) -> str:
    raw = str(raw_value if raw_value not in (None, "") else default).strip()
    if not raw:
        return ""
    if any(character in raw for character in DANGEROUS_SHELL_CHARACTERS) or not SAFE_FILTER_PATTERN.fullmatch(raw):
        raise ValueError(f"{field_name} contains unsupported characters.")
    values: list[str] = []
    seen: set[str] = set()
    for part in raw.split(","):
        cleaned = part.strip()
        if not cleaned:
            continue
        normalized = cleaned.lower()
        if allowed is not None and normalized not in allowed:
            raise ValueError(f"{field_name} contains unsupported value: {cleaned}.")
        if normalized in seen:
            continue
        seen.add(normalized)
        values.append(cleaned)
    if len(values) > 100:
        raise ValueError(f"{field_name} exceeds the bounded list size.")
    return ",".join(values)


def _normalize_single_value(raw_value: object, *, field_name: str) -> str:
    raw = str(raw_value or "").strip()
    if not raw:
        return ""
    if "," in raw:
        raise ValueError(f"{field_name} must be a single configured value.")
    return _normalize_filter_csv(raw, field_name=field_name)


def _start_stream_thread(pipe: object, lines: list[str], stream_name: str, max_output_bytes: int) -> threading.Thread:
    thread = threading.Thread(target=_stream_output, args=(pipe, lines, stream_name, max_output_bytes), daemon=True)
    thread.start()
    return thread


def _stream_output(pipe: object, lines: list[str], stream_name: str, max_output_bytes: int) -> None:
    if pipe is None:
        return

    current_size = 0
    truncated = False
    try:
        for line in pipe:
            cleaned_line = str(line).rstrip("\r\n")
            line_size = len(cleaned_line.encode("utf-8", errors="ignore"))
            if current_size + line_size <= max_output_bytes:
                lines.append(cleaned_line)
                current_size += line_size
            elif not truncated:
                remaining = max(0, max_output_bytes - current_size)
                if remaining:
                    lines.append(cleaned_line[:remaining])
                lines.append(f"[{stream_name} truncated at {max_output_bytes} bytes]")
                truncated = True
            logger.info("Nuclei %s: %s", stream_name, _truncate_stream_line(cleaned_line))
    finally:
        close = getattr(pipe, "close", None)
        if close is not None:
            close()


def _join_stream_thread(thread: threading.Thread, stream_name: str) -> None:
    thread.join(timeout=5)
    if thread.is_alive():
        logger.warning("Nuclei %s stream reader still running after process exit.", stream_name)


def _truncate_stream_line(line: str, limit: int = 1000) -> str:
    if len(line) <= limit:
        return line

    return f"{line[:limit]}... [truncated {len(line) - limit} chars]"
