import logging
from pathlib import Path
# Required to run authorized local testssl.sh subprocesses.
import subprocess  # nosec B404
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

    command = _build_testssl_command(executable, validated_target, json_path)
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
        json_output = json_path.read_text(encoding="utf-8") if json_path.exists() else ""
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
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
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
        success=completed.returncode == 0 and bool(json_output.strip()),
        output=stdout,
        error=stderr if completed.returncode == 0 else (stderr or "testssl.sh did not complete successfully."),
        error_type=None if completed.returncode == 0 and json_output.strip() else "execution_failed",
        returncode=completed.returncode,
        elapsed_seconds=elapsed_seconds,
        command=command,
        working_directory=working_directory,
        json_output=json_output,
    )


def _validate_target(target: str) -> str:
    if any(character in str(target or "") for character in DANGEROUS_SHELL_CHARACTERS):
        raise ValueError("testssl.sh target contains unsupported shell characters.")
    normalized = normalize_for_httpx(target)
    parsed = urlparse(normalized)
    host = parsed.hostname or ""
    if not host:
        raise ValueError("testssl.sh target must include a hostname or IP address.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{host}:{port}"


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


def _build_testssl_command(executable: str, target: str, json_path: Path) -> list[str]:
    return [
        executable,
        "--jsonfile-pretty",
        str(json_path),
        "--warnings",
        "batch",
        "--openssl-timeout",
        "5",
        "--connect-timeout",
        "5",
        "--quiet",
        target,
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
    json_output: str = "",
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
    }
