import logging
from pathlib import Path
# Required to run authorized local Nuclei subprocesses.
import subprocess  # nosec B404
import shutil
import threading
import time
from urllib.parse import urlparse

from app.core.config import get_settings
from app.tools.nmap_runner import DANGEROUS_SHELL_CHARACTERS

logger = logging.getLogger(__name__)
NUCLEI_NOT_AVAILABLE_ERROR = "Nuclei executable was not found."
NUCLEI_TIMEOUT_ERROR = "Nuclei fast scan timed out. Try a smaller target or use a deeper scan profile later."


def _validate_target(target: str) -> str:
    normalized_target = _normalize_nuclei_target(target)
    if not normalized_target:
        raise ValueError("Nuclei target cannot be empty.")

    if any(character in normalized_target for character in DANGEROUS_SHELL_CHARACTERS):
        raise ValueError("Nuclei target contains unsupported shell characters.")

    return normalized_target


def _normalize_nuclei_target(target: str) -> str:
    stripped_target = target.strip()
    if not stripped_target:
        return stripped_target

    parsed_target = urlparse(stripped_target)
    if parsed_target.scheme:
        if parsed_target.scheme not in {"http", "https"} or not parsed_target.hostname:
            raise ValueError("Nuclei target must be a valid http or https URL or hostname.")

        return stripped_target

    if "://" in stripped_target:
        raise ValueError("Nuclei target must be a valid http or https URL or hostname.")

    return f"https://{stripped_target}"


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

    command = _build_nuclei_command(executable, validated_target, settings)
    start_time = time.monotonic()
    logger.info(
        "Nuclei scan started: target=%s timeout=%s rate_limit=%s request_timeout=%s retries=%s",
        validated_target,
        settings.nuclei_scan_timeout_seconds,
        settings.nuclei_rate_limit,
        settings.nuclei_request_timeout,
        settings.nuclei_retries,
    )
    logger.info("Nuclei subprocess argv: %r", command)
    logger.info("Nuclei working directory: %s", working_directory)
    logger.info("Nuclei subprocess timeout: %s", settings.nuclei_scan_timeout_seconds)

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

    stdout_thread = _start_stream_thread(process.stdout, stdout_lines, "stdout")
    stderr_thread = _start_stream_thread(process.stderr, stderr_lines, "stderr")
    try:
        returncode = process.wait(timeout=settings.nuclei_scan_timeout_seconds)
    except subprocess.TimeoutExpired:
        logger.warning("Nuclei scan timed out after %ss: argv=%r cwd=%s", settings.nuclei_scan_timeout_seconds, command, working_directory)
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
            "output": stdout,
            "error": stderr or NUCLEI_TIMEOUT_ERROR,
            "error_type": "timeout",
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
    return [
        executable,
        "-u",
        target,
        "-jsonl",
        "-silent",
        "-severity",
        "low,medium,high,critical",
        "-tags",
        settings.nuclei_tags,
        "-rate-limit",
        str(settings.nuclei_rate_limit),
        "-timeout",
        str(settings.nuclei_request_timeout),
        "-retries",
        str(settings.nuclei_retries),
    ]


def _start_stream_thread(pipe: object, lines: list[str], stream_name: str) -> threading.Thread:
    thread = threading.Thread(target=_stream_output, args=(pipe, lines, stream_name), daemon=True)
    thread.start()
    return thread


def _stream_output(pipe: object, lines: list[str], stream_name: str) -> None:
    if pipe is None:
        return

    try:
        for line in pipe:
            cleaned_line = str(line).rstrip("\r\n")
            lines.append(cleaned_line)
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
