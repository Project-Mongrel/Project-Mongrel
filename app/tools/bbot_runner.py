import logging
from pathlib import Path
# Required to run authorized local BBOT subprocesses.
import subprocess  # nosec B404
import time
import shutil

from app.tools.nmap_runner import DANGEROUS_SHELL_CHARACTERS
from app.tools.target_normalizer import normalize_target

BBOT_TIMEOUT_SECONDS = 180
BBOT_OUTPUT_DIR = Path("data") / "bbot"
BBOT_NOT_AVAILABLE_ERROR = "BBOT is not installed or not available on PATH."
BBOT_RUNTIME_INCOMPATIBLE_ERROR = "\n".join(
    [
        "BBOT is installed but cannot run in this Windows environment.",
        "BBOT requires a Linux-compatible runtime for this scan mode.",
        "",
        "Recommended options:",
        "- Run Mongrel under WSL, Kali, or Linux.",
        "- Use a future Linux tool worker for BBOT execution.",
    ]
)
logger = logging.getLogger(__name__)


def is_bbot_available() -> bool:
    return _resolve_bbot_executable() is not None


def run_bbot_scan(target: str) -> dict[str, object]:
    validated_target = _validate_target(target)
    output_dir = BBOT_OUTPUT_DIR / _safe_output_name(validated_target)
    output_dir.mkdir(parents=True, exist_ok=True)
    executable = _resolve_bbot_executable()
    if executable is None:
        return {
            "target": validated_target,
            "success": False,
            "output": "",
            "error": BBOT_NOT_AVAILABLE_ERROR,
            "error_type": "missing_binary",
            "returncode": None,
            "elapsed_seconds": 0,
            "output_dir": str(output_dir),
        }

    command = _build_bbot_command(executable, validated_target, output_dir)
    started_at = time.monotonic()
    logger.info("BBOT recon started: target=%s output_dir=%s", validated_target, output_dir)

    try:
        # Command uses explicit args list, shell=False, and a validated target.
        completed_process = subprocess.run(  # nosec B603
            command,
            capture_output=True,
            text=True,
            timeout=BBOT_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed_seconds = time.monotonic() - started_at
        return {
            "target": validated_target,
            "success": False,
            "output": exc.stdout or "",
            "error": exc.stderr or "BBOT recon timed out.",
            "error_type": "timeout",
            "returncode": None,
            "elapsed_seconds": elapsed_seconds,
            "output_dir": str(output_dir),
        }
    except FileNotFoundError:
        elapsed_seconds = time.monotonic() - started_at
        return {
            "target": validated_target,
            "success": False,
            "output": "",
            "error": BBOT_NOT_AVAILABLE_ERROR,
            "error_type": "missing_binary",
            "returncode": None,
            "elapsed_seconds": elapsed_seconds,
            "output_dir": str(output_dir),
        }

    elapsed_seconds = time.monotonic() - started_at
    success = completed_process.returncode == 0
    stdout = completed_process.stdout or ""
    stderr = completed_process.stderr or ""
    if not success and _is_runtime_incompatible_error(stdout, stderr):
        logger.error(
            "BBOT runtime incompatible: target=%s returncode=%s stdout=%s stderr=%s",
            validated_target,
            completed_process.returncode,
            stdout,
            stderr,
        )
        return {
            "target": validated_target,
            "success": False,
            "output": "",
            "error": BBOT_RUNTIME_INCOMPATIBLE_ERROR,
            "error_type": "runtime_incompatible",
            "returncode": completed_process.returncode,
            "elapsed_seconds": elapsed_seconds,
            "output_dir": str(output_dir),
        }

    return {
        "target": validated_target,
        "success": success,
        "output": stdout,
        "error": stderr or ("" if success else "BBOT recon failed."),
        "error_type": None if success else "bbot_failed",
        "returncode": completed_process.returncode,
        "elapsed_seconds": elapsed_seconds,
        "output_dir": str(output_dir),
    }


def _validate_target(target: str) -> str:
    normalized_target = normalize_target(target)
    if not normalized_target:
        raise ValueError("BBOT target cannot be empty.")

    if any(character in normalized_target for character in DANGEROUS_SHELL_CHARACTERS):
        raise ValueError("BBOT target contains unsupported shell characters.")

    return normalized_target


def _safe_output_name(target: str) -> str:
    return "".join(character if character.isalnum() or character in {".", "-", "_"} else "_" for character in target)


def _resolve_bbot_executable() -> str | None:
    path_executable = shutil.which("bbot")
    if path_executable:
        return path_executable

    for candidate in _local_bbot_candidates():
        if candidate.is_file():
            return str(candidate)

    return None


def _local_bbot_candidates() -> tuple[Path, Path]:
    return (
        Path(".venv") / "Scripts" / "bbot.exe",
        Path(".venv") / "bin" / "bbot",
    )


def _build_bbot_command(executable: str, target: str, output_dir: Path) -> list[str]:
    return [executable, "-t", target, "-p", "subdomain-enum", "-o", str(output_dir), "-y"]


def _is_runtime_incompatible_error(stdout: str, stderr: str) -> bool:
    combined_output = f"{stdout}\n{stderr}".lower()
    return (
        "modulenotfounderror" in combined_output
        and (
            "no module named 'fcntl'" in combined_output
            or 'no module named "fcntl"' in combined_output
            or "no module named 'resource'" in combined_output
            or 'no module named "resource"' in combined_output
        )
    )
