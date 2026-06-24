import logging
import subprocess
import time

from app.core.config import get_settings
from app.tools.nmap_runner import DANGEROUS_SHELL_CHARACTERS
from app.tools.target_normalizer import normalize_target

logger = logging.getLogger(__name__)


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
    logger.info("Nuclei target normalized: raw_target=%s normalized_target=%s", target, validated_target)
    command = [
        settings.nuclei_path,
        "-u",
        validated_target,
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
    start_time = time.monotonic()
    logger.info(
        "Nuclei scan started: target=%s timeout=%s rate_limit=%s request_timeout=%s retries=%s",
        validated_target,
        settings.nuclei_scan_timeout_seconds,
        settings.nuclei_rate_limit,
        settings.nuclei_request_timeout,
        settings.nuclei_retries,
    )

    try:
        completed_process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=settings.nuclei_scan_timeout_seconds,
            check=False,
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
            "error": exc.stderr or "Nuclei fast scan timed out. Try a smaller target or use a deeper scan profile later.",
            "returncode": None,
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
            "error": "Nuclei executable was not found.",
            "returncode": None,
        }

    elapsed_seconds = time.monotonic() - start_time
    logger.info(
        "Nuclei scan completed: target=%s elapsed_seconds=%.2f stdout_len=%s stderr_len=%s",
        validated_target,
        elapsed_seconds,
        len(completed_process.stdout or ""),
        len(completed_process.stderr or ""),
    )
    return {
        "target": validated_target,
        "success": completed_process.returncode == 0,
        "output": completed_process.stdout,
        "error": completed_process.stderr,
        "returncode": completed_process.returncode,
    }
