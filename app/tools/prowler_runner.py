import logging
import re
import shutil
import subprocess  # nosec B404
import time
from pathlib import Path

from app.core.config import get_settings
from app.tools.nmap_runner import DANGEROUS_SHELL_CHARACTERS

logger = logging.getLogger(__name__)

ALLOWED_PROWLER_PROVIDERS = frozenset({"aws", "azure", "gcp"})
PROWLER_NOT_AVAILABLE_ERROR = "Prowler executable was not found."
PROWLER_TIMEOUT_ERROR = "Prowler scan timed out."
PROWLER_GENERIC_FAILURE_ERROR = "Prowler did not complete successfully. Review sanitized logs and VPS cloud credential configuration."

_CREDENTIAL_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(aws_secret_access_key|secret_access_key|access_token|refresh_token|client_secret|password)\s*[:=]\s*[^,\s]+"),
    re.compile(r"(?i)(authorization:\s*bearer\s+)[a-z0-9._\-]+"),
)
_ANSI_ESCAPE_PATTERN = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_BARE_ANSI_CODE_PATTERN = re.compile(r"\[[0-9;]{1,12}m")
_CONTROL_CHARACTER_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def run_prowler_scan(provider: str, output_dir: str | Path, output_filename: str = "mongrel-prowler") -> dict[str, object]:
    normalized_provider = normalize_prowler_provider(provider)
    output_path = _validate_output_directory(output_dir)
    normalized_filename = _validate_output_filename(output_filename)
    settings = get_settings()
    executable = _resolve_prowler_executable(settings.prowler_binary)
    working_directory = Path.cwd().resolve()
    if executable is None:
        logger.warning("Prowler executable missing. Checked PATH and configured binary.")
        return _result(
            provider=normalized_provider,
            success=False,
            error=PROWLER_NOT_AVAILABLE_ERROR,
            error_type="missing_binary",
            elapsed_seconds=0,
            command=None,
            output_dir=output_path,
            output_filename=normalized_filename,
            working_directory=working_directory,
        )

    command = build_prowler_command(executable, normalized_provider, output_path, normalized_filename)
    start_time = time.monotonic()
    logger.info("Prowler scan started: provider=%s output_dir=%s timeout=%s", normalized_provider, output_path, settings.prowler_timeout_seconds)
    try:
        completed = subprocess.run(  # nosec B603
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=settings.prowler_timeout_seconds,
            cwd=str(working_directory),
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed_seconds = time.monotonic() - start_time
        logger.warning("Prowler scan timed out: provider=%s elapsed_seconds=%.2f", normalized_provider, elapsed_seconds)
        return _result(
            provider=normalized_provider,
            success=False,
            output=redact_prowler_text(exc.stdout or ""),
            error=redact_prowler_text(exc.stderr or PROWLER_TIMEOUT_ERROR),
            error_type="timeout",
            elapsed_seconds=elapsed_seconds,
            command=command,
            output_dir=output_path,
            output_filename=normalized_filename,
            working_directory=working_directory,
        )
    except FileNotFoundError:
        elapsed_seconds = time.monotonic() - start_time
        logger.warning("Prowler executable missing during execution: provider=%s elapsed_seconds=%.2f", normalized_provider, elapsed_seconds)
        return _result(
            provider=normalized_provider,
            success=False,
            error=PROWLER_NOT_AVAILABLE_ERROR,
            error_type="missing_binary",
            elapsed_seconds=elapsed_seconds,
            command=command,
            output_dir=output_path,
            output_filename=normalized_filename,
            working_directory=working_directory,
        )
    except OSError as exc:
        elapsed_seconds = time.monotonic() - start_time
        logger.warning("Prowler execution failed: provider=%s elapsed_seconds=%.2f error=%s", normalized_provider, elapsed_seconds, redact_prowler_text(str(exc)))
        return _result(
            provider=normalized_provider,
            success=False,
            error="Prowler execution failed.",
            error_type="execution_failed",
            elapsed_seconds=elapsed_seconds,
            command=command,
            output_dir=output_path,
            output_filename=normalized_filename,
            working_directory=working_directory,
        )

    elapsed_seconds = time.monotonic() - start_time
    stdout = redact_prowler_text(completed.stdout or "")
    stderr = redact_prowler_text(completed.stderr or "")
    error = ""
    error_type = None
    if completed.returncode != 0:
        error = summarize_prowler_failure(normalized_provider, stdout=stdout, stderr=stderr)
        error_type = "missing_credentials" if _is_no_credentials_failure(f"{stdout}\n{stderr}") else "execution_failed"
    return _result(
        provider=normalized_provider,
        success=completed.returncode == 0,
        output=stdout,
        error=stderr if completed.returncode == 0 else error,
        error_type=error_type,
        returncode=completed.returncode,
        elapsed_seconds=elapsed_seconds,
        command=command,
        output_dir=output_path,
        output_filename=normalized_filename,
        output_files=[str(path) for path in _discover_json_outputs(output_path, normalized_filename)],
        working_directory=working_directory,
    )


def build_prowler_command(executable: str, provider: str, output_dir: Path, output_filename: str) -> list[str]:
    normalized_provider = normalize_prowler_provider(provider)
    normalized_filename = _validate_output_filename(output_filename)
    return [
        executable,
        normalized_provider,
        "--output-formats",
        "json-ocsf",
        "--output-directory",
        str(output_dir),
        "--output-filename",
        normalized_filename,
    ]


def normalize_prowler_provider(provider: str) -> str:
    normalized = str(provider or "").strip().lower()
    if normalized not in ALLOWED_PROWLER_PROVIDERS:
        raise ValueError("Unsupported Prowler provider.")
    return normalized


def redact_prowler_text(text: str) -> str:
    redacted = _strip_prowler_terminal_noise(str(text or ""))
    for pattern in _CREDENTIAL_PATTERNS:
        redacted = pattern.sub(lambda match: f"{match.group(1)}<REDACTED>" if match.groups() else "<REDACTED>", redacted)
    return _remove_prowler_banner_lines(redacted)


def summarize_prowler_failure(provider: str, *, stdout: str = "", stderr: str = "") -> str:
    text = redact_prowler_text(f"{stdout}\n{stderr}")
    if _is_no_credentials_failure(text):
        return f"Cloud credentials were not available for {normalize_prowler_provider(provider).upper()} on the Mongrel VPS."

    for line in text.splitlines():
        cleaned = line.strip()
        if not cleaned or _is_internal_diagnostic_line(cleaned):
            continue
        return cleaned[:500]
    return PROWLER_GENERIC_FAILURE_ERROR


def _is_no_credentials_failure(text: str) -> bool:
    normalized = str(text or "").lower()
    indicators = (
        "nocredentialserror",
        "no credentials",
        "unable to locate credentials",
        "could not locate credentials",
        "credentials were not found",
        "credential configuration was not found",
        "missing credentials",
    )
    return any(indicator in normalized for indicator in indicators)


def _is_internal_diagnostic_line(line: str) -> bool:
    normalized = line.strip().lower()
    return (
        normalized.startswith("[file:")
        or normalized.startswith("[module:")
        or normalized.startswith("file \"")
        or normalized.startswith("traceback ")
    )


def _strip_prowler_terminal_noise(text: str) -> str:
    stripped = _ANSI_ESCAPE_PATTERN.sub("", text)
    stripped = _BARE_ANSI_CODE_PATTERN.sub("", stripped)
    return _CONTROL_CHARACTER_PATTERN.sub("", stripped)


def _remove_prowler_banner_lines(text: str) -> str:
    return "\n".join(line for line in str(text or "").splitlines() if not _is_prowler_banner_line(line))


def _is_prowler_banner_line(line: str) -> bool:
    cleaned = line.strip()
    if not cleaned:
        return False
    lower = cleaned.lower()
    if "prowler banner" in lower:
        return True
    if cleaned in {"_", "__", "___"}:
        return True
    if len(cleaned) <= 120 and not re.search(r"[A-Za-z0-9]", cleaned):
        return True
    if len(cleaned) <= 120 and re.fullmatch(r"[_/\\|`'\".,:;~^*+=<>()\[\]{}\-\s]+", cleaned):
        return True
    compact = cleaned.replace(" ", "")
    if len(cleaned) <= 120 and compact:
        punctuation_count = len(re.findall(r"[_/\\|`'\".,:;~^*+=<>()\[\]{}\-\s]", cleaned))
        alnum_count = len(re.findall(r"[A-Za-z0-9]", cleaned))
        if punctuation_count >= max(6, alnum_count * 2):
            return True
    return False


def _validate_output_directory(output_dir: str | Path) -> Path:
    raw_path = Path(output_dir)
    path_text = str(raw_path)
    if not path_text.strip():
        raise ValueError("Prowler output directory is required.")
    if any(character in path_text for character in DANGEROUS_SHELL_CHARACTERS):
        raise ValueError("Prowler output directory contains unsupported shell characters.")
    resolved = raw_path.expanduser().resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    if not resolved.is_dir():
        raise ValueError("Prowler output directory must be a directory.")
    return resolved


def _validate_output_filename(output_filename: str) -> str:
    filename = str(output_filename or "").strip()
    if not filename:
        raise ValueError("Prowler output filename is required.")
    if any(character in filename for character in DANGEROUS_SHELL_CHARACTERS):
        raise ValueError("Prowler output filename contains unsupported shell characters.")
    if any(character in filename for character in ("/", "\\")):
        raise ValueError("Prowler output filename cannot contain path separators.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", filename):
        raise ValueError("Prowler output filename contains unsupported characters.")
    if len(filename) > 120:
        raise ValueError("Prowler output filename is too long.")
    return filename


def _resolve_prowler_executable(configured_binary: str = "prowler") -> str | None:
    if configured_binary and configured_binary != "prowler":
        return configured_binary
    return shutil.which("prowler")


def _discover_json_outputs(output_dir: Path, output_filename: str) -> list[Path]:
    candidates = sorted(output_dir.glob(f"{output_filename}*.json"))
    return [path for path in candidates if path.is_file()]


def _result(
    *,
    provider: str,
    success: bool,
    output: str = "",
    error: str = "",
    error_type: str | None,
    returncode: int | None = None,
    elapsed_seconds: float,
    command: list[str] | None,
    output_dir: Path,
    output_filename: str,
    working_directory: Path,
    output_files: list[str] | None = None,
) -> dict[str, object]:
    return {
        "provider": provider,
        "success": success,
        "output": output,
        "error": error,
        "error_type": error_type,
        "returncode": returncode,
        "exit_code": returncode,
        "elapsed_seconds": elapsed_seconds,
        "command": command,
        "output_dir": str(output_dir),
        "output_filename": output_filename,
        "output_files": output_files or [],
        "working_directory": str(working_directory),
        "stdout_len": len(output or ""),
        "stderr_len": len(error or ""),
    }
