import subprocess

from app.core.config import get_settings
from app.tools.nmap_runner import DANGEROUS_SHELL_CHARACTERS

NUCLEI_TIMEOUT_SECONDS = 120


def _validate_target(target: str) -> str:
    normalized_target = target.strip()
    if not normalized_target:
        raise ValueError("Nuclei target cannot be empty.")

    if any(character in normalized_target for character in DANGEROUS_SHELL_CHARACTERS):
        raise ValueError("Nuclei target contains unsupported shell characters.")

    return normalized_target


def run_nuclei_scan(target: str) -> dict[str, object]:
    validated_target = _validate_target(target)
    settings = get_settings()
    command = [settings.nuclei_path, "-u", validated_target, "-jsonl", "-silent"]

    try:
        completed_process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=NUCLEI_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "target": validated_target,
            "success": False,
            "output": exc.stdout or "",
            "error": exc.stderr or "Nuclei scan timed out.",
            "returncode": None,
        }
    except FileNotFoundError:
        return {
            "target": validated_target,
            "success": False,
            "output": "",
            "error": "Nuclei executable was not found.",
            "returncode": None,
        }

    return {
        "target": validated_target,
        "success": completed_process.returncode == 0,
        "output": completed_process.stdout,
        "error": completed_process.stderr,
        "returncode": completed_process.returncode,
    }
