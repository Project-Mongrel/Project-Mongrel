import logging
import subprocess

from app.tools.target_normalizer import normalize_target

NMAP_TIMEOUT_SECONDS = 60
logger = logging.getLogger(__name__)
DANGEROUS_SHELL_CHARACTERS: frozenset[str] = frozenset(
    {
        ";",
        "&",
        "|",
        "`",
        "$",
        "(",
        ")",
        "<",
        ">",
        "\n",
        "\r",
    }
)


def _validate_target(target: str) -> str:
    normalized_target = normalize_target(target)
    if not normalized_target:
        raise ValueError("Nmap target cannot be empty.")

    if any(character in normalized_target for character in DANGEROUS_SHELL_CHARACTERS):
        raise ValueError("Nmap target contains unsupported shell characters.")

    return normalized_target


def run_nmap_scan(target: str) -> dict[str, object]:
    """Run a conservative local Nmap scan and return captured process output."""

    validated_target = _validate_target(target)
    logger.info("Nmap target normalized: raw_target=%s normalized_target=%s", target, validated_target)
    command = ["nmap", "-Pn", "-T3", validated_target]

    try:
        completed_process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=NMAP_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "target": validated_target,
            "success": False,
            "output": exc.stdout or "",
            "error": exc.stderr or "Nmap scan timed out.",
            "returncode": None,
        }
    except FileNotFoundError:
        return {
            "target": validated_target,
            "success": False,
            "output": "",
            "error": "Nmap executable was not found.",
            "returncode": None,
        }

    return {
        "target": validated_target,
        "success": completed_process.returncode == 0,
        "output": completed_process.stdout,
        "error": completed_process.stderr,
        "returncode": completed_process.returncode,
    }
