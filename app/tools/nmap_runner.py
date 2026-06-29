import logging
# Required to run authorized local Nmap subprocesses.
import subprocess  # nosec B404

from app.services.target_normalizer import normalize_for_nmap

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
    if any(character in target for character in DANGEROUS_SHELL_CHARACTERS):
        raise ValueError("Nmap target contains unsupported shell characters.")

    normalized_target = normalize_for_nmap(target)

    return normalized_target


def run_nmap_scan(target: str) -> dict[str, object]:
    """Run a conservative local Nmap scan and return captured process output."""

    validated_target = _validate_target(target)
    logger.info("Nmap target normalized: raw_target=%s normalized_target=%s", target, validated_target)
    command = ["nmap", "-Pn", "-T3", validated_target]

    try:
        # Command uses explicit args list, shell=False, and a validated target.
        completed_process = subprocess.run(  # nosec B603
            command,
            capture_output=True,
            text=True,
            timeout=NMAP_TIMEOUT_SECONDS,
            check=False,
            shell=False,
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
