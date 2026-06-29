import logging
from pathlib import Path
# Required to run authorized local Nuclei subprocesses.
import subprocess  # nosec B404
import shutil
import time

from app.core.config import get_settings
from app.tools.nmap_runner import DANGEROUS_SHELL_CHARACTERS
from app.tools.target_normalizer import normalize_target

logger = logging.getLogger(__name__)
NUCLEI_NOT_AVAILABLE_ERROR = "Nuclei executable was not found."
NUCLEI_TIMEOUT_ERROR = "Nuclei fast scan timed out. Try a smaller target or use a deeper scan profile later."


def _validate_target(target: str) -> str:
    normalized_target = normalize_target(target)
    if not normalized_target:
        raise ValueError("Nuclei target cannot be empty.")

    if any(character in normalized_target for character in DANGEROUS_SHELL_CHARACTERS):
        raise ValueError("Nuclei target contains unsupported shell characters.")

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

    try:
        # Command uses explicit args list, shell=False, and a validated target.
        completed_process = subprocess.run(  # nosec B603
            command,
            capture_output=True,
            text=True,
            timeout=settings.nuclei_scan_timeout_seconds,
            check=False,
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
            "elapsed_seconds": elapsed_seconds,
            "command": command,
            "working_directory": str(working_directory),
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
            "elapsed_seconds": elapsed_seconds,
            "command": command,
            "working_directory": str(working_directory),
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
            "elapsed_seconds": elapsed_seconds,
            "command": command,
            "working_directory": str(working_directory),
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
            "elapsed_seconds": elapsed_seconds,
            "command": command,
            "working_directory": str(working_directory),
        }

    elapsed_seconds = time.monotonic() - start_time
    logger.info(
        "Nuclei scan completed: target=%s elapsed_seconds=%.2f stdout_len=%s stderr_len=%s exit_code=%s",
        validated_target,
        elapsed_seconds,
        len(completed_process.stdout or ""),
        len(completed_process.stderr or ""),
        completed_process.returncode,
    )
    return {
        "target": validated_target,
        "success": completed_process.returncode == 0,
        "output": completed_process.stdout,
        "error": completed_process.stderr,
        "error_type": None if completed_process.returncode == 0 else "execution_failed",
        "returncode": completed_process.returncode,
        "elapsed_seconds": elapsed_seconds,
        "command": command,
        "working_directory": str(working_directory),
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
