import logging
from pathlib import Path
# Required to run authorized local httpx subprocesses.
import subprocess  # nosec B404
import shutil
import time

from app.core.config import get_settings
from app.services.target_normalizer import normalize_for_httpx
from app.tools.nmap_runner import DANGEROUS_SHELL_CHARACTERS

logger = logging.getLogger(__name__)
HTTPX_NOT_AVAILABLE_ERROR = "httpx executable was not found."
HTTPX_TIMEOUT_ERROR = "httpx scan timed out. Try a smaller target or reduce the scan scope."


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

    command = _build_httpx_command(executable, validated_target)
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


def _build_httpx_command(executable: str, target: str) -> list[str]:
    return [
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
        "-location",
        "-tls-probe",
    ]


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
