import logging
from pathlib import Path
# Required to run authorized local Gitleaks subprocesses.
import subprocess  # nosec B404
import shutil
import tempfile
import time

from app.core.config import get_settings
from app.tools.nmap_runner import DANGEROUS_SHELL_CHARACTERS

logger = logging.getLogger(__name__)
GITLEAKS_NOT_AVAILABLE_ERROR = "Gitleaks executable was not found."
GITLEAKS_TIMEOUT_ERROR = "Gitleaks scan timed out. Try a smaller artifact directory."


def run_gitleaks_scan(scope: str) -> dict[str, object]:
    scan_path = _validate_scan_scope(scope)
    settings = get_settings()
    executable = _resolve_gitleaks_executable(settings.gitleaks_path)
    working_directory = Path.cwd().resolve()
    if executable is None:
        logger.warning("Gitleaks executable missing. Checked PATH lookup and candidate paths: %s", [str(candidate) for candidate in _gitleaks_executable_candidates()])
        return _result(
            target=str(scan_path),
            success=False,
            error=GITLEAKS_NOT_AVAILABLE_ERROR,
            error_type="missing_binary",
            elapsed_seconds=0,
            command=None,
            working_directory=working_directory,
        )

    with tempfile.NamedTemporaryFile(prefix="mongrel-gitleaks-", suffix=".json", delete=False) as json_file:
        json_path = Path(json_file.name)

    command = _build_gitleaks_command(executable, scan_path, json_path)
    start_time = time.monotonic()
    logger.info("Gitleaks scan started: scope=%s timeout=%s", scan_path, settings.gitleaks_scan_timeout_seconds)
    logger.info("Gitleaks subprocess argv: %r", command)
    try:
        completed = subprocess.run(  # nosec B603
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=settings.gitleaks_scan_timeout_seconds,
            cwd=str(working_directory),
            shell=False,
            check=False,
        )
        json_output = json_path.read_text(encoding="utf-8") if json_path.exists() else ""
    except subprocess.TimeoutExpired as exc:
        elapsed_seconds = time.monotonic() - start_time
        logger.warning("Gitleaks scan timed out: scope=%s elapsed_seconds=%.2f", scan_path, elapsed_seconds)
        return _result(
            target=str(scan_path),
            success=False,
            output=exc.stdout or "",
            error=exc.stderr or GITLEAKS_TIMEOUT_ERROR,
            error_type="timeout",
            elapsed_seconds=elapsed_seconds,
            command=command,
            working_directory=working_directory,
        )
    except FileNotFoundError:
        elapsed_seconds = time.monotonic() - start_time
        logger.warning("Gitleaks executable missing: scope=%s elapsed_seconds=%.2f", scan_path, elapsed_seconds)
        return _result(
            target=str(scan_path),
            success=False,
            error=GITLEAKS_NOT_AVAILABLE_ERROR,
            error_type="missing_binary",
            elapsed_seconds=elapsed_seconds,
            command=command,
            working_directory=working_directory,
        )
    except OSError as exc:
        elapsed_seconds = time.monotonic() - start_time
        logger.warning("Gitleaks execution failed: scope=%s elapsed_seconds=%.2f error=%s", scan_path, elapsed_seconds, exc)
        return _result(
            target=str(scan_path),
            success=False,
            error="Gitleaks execution failed.",
            error_type="execution_failed",
            elapsed_seconds=elapsed_seconds,
            command=command,
            working_directory=working_directory,
        )
    finally:
        try:
            json_path.unlink(missing_ok=True)
        except OSError:
            logger.warning("Unable to remove temporary Gitleaks JSON artifact: %s", json_path)

    elapsed_seconds = time.monotonic() - start_time
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    success = completed.returncode in {0, 1}
    return _result(
        target=str(scan_path),
        success=success,
        output=stdout,
        json_output=json_output,
        error=stderr if success else (stderr or "Gitleaks did not complete successfully."),
        error_type=None if success else "execution_failed",
        returncode=completed.returncode,
        elapsed_seconds=elapsed_seconds,
        command=command,
        working_directory=working_directory,
    )


def _validate_scan_scope(scope: str) -> Path:
    if any(character in str(scope or "") for character in DANGEROUS_SHELL_CHARACTERS):
        raise ValueError("Gitleaks scope contains unsupported shell characters.")
    raw_path = Path(str(scope or "").strip())
    if not str(raw_path):
        raise ValueError("Gitleaks scope is required.")
    resolved = raw_path.expanduser().resolve()
    if not resolved.exists() or not resolved.is_dir():
        raise ValueError("Gitleaks scope must be an existing directory.")
    allowed_roots = _allowed_scan_roots()
    if not any(_is_relative_to(resolved, root) for root in allowed_roots):
        raise ValueError("Gitleaks scope must stay inside an approved workspace or artifact directory.")
    if resolved.anchor == str(resolved):
        raise ValueError("Gitleaks scope cannot be a filesystem root.")
    return resolved


def _allowed_scan_roots() -> tuple[Path, ...]:
    cwd = Path.cwd().resolve()
    return (
        cwd,
        cwd / "data",
        cwd / "uploads",
        cwd / "artifacts",
        Path(tempfile.gettempdir()).resolve(),
    )


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _resolve_gitleaks_executable(configured_path: str = "gitleaks") -> str | None:
    if configured_path and configured_path != "gitleaks":
        return configured_path
    path_executable = shutil.which("gitleaks")
    if path_executable:
        return path_executable
    for candidate in _gitleaks_executable_candidates():
        if candidate.is_file():
            return str(candidate)
    return None


def _gitleaks_executable_candidates() -> tuple[Path, Path, Path, Path]:
    return (
        Path("/usr/local/bin/gitleaks"),
        Path("/usr/bin/gitleaks"),
        Path(".venv") / "Scripts" / "gitleaks.exe",
        Path(".venv") / "bin" / "gitleaks",
    )


def _build_gitleaks_command(executable: str, scan_path: Path, json_path: Path) -> list[str]:
    return [
        executable,
        "dir",
        str(scan_path),
        "--report-format",
        "json",
        "--report-path",
        str(json_path),
        "--no-banner",
    ]


def _result(
    *,
    target: str,
    success: bool,
    output: str = "",
    json_output: str = "",
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
