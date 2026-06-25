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
logger = logging.getLogger(__name__)


def is_bbot_available() -> bool:
    return shutil.which("bbot") is not None


def run_bbot_scan(target: str) -> dict[str, object]:
    validated_target = _validate_target(target)
    output_dir = BBOT_OUTPUT_DIR / _safe_output_name(validated_target)
    output_dir.mkdir(parents=True, exist_ok=True)
    command = ["bbot", "-t", validated_target, "-p", "subdomain-enum", "-o", str(output_dir), "-y"]
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
            "error": "BBOT is not installed or not available on PATH.",
            "returncode": None,
            "elapsed_seconds": elapsed_seconds,
            "output_dir": str(output_dir),
        }

    elapsed_seconds = time.monotonic() - started_at
    success = completed_process.returncode == 0
    return {
        "target": validated_target,
        "success": success,
        "output": completed_process.stdout or "",
        "error": completed_process.stderr or ("" if success else "BBOT recon failed."),
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
