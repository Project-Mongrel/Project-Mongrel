import logging
import re
from pathlib import Path
# Required to run authorized local Katana subprocesses.
import subprocess  # nosec B404
import shutil
import time

from app.core.config import get_settings
from app.services.target_normalizer import normalize_for_katana
from app.tools.nmap_runner import DANGEROUS_SHELL_CHARACTERS

logger = logging.getLogger(__name__)
KATANA_NOT_AVAILABLE_ERROR = "Katana executable was not found."
KATANA_TIMEOUT_ERROR = "Katana crawl timed out. Try a smaller target or reduce crawl depth."
MAX_KATANA_DEPTH = 10
MAX_KATANA_CONCURRENCY = 50
MAX_KATANA_RATE_LIMIT = 300
MAX_KATANA_CRAWL_DURATION_SECONDS = 900
MAX_KATANA_RESPONSE_SIZE_BYTES = 8_388_608
KATANA_FIELD_SCOPES = frozenset({"fqdn", "dn", "rdn"})
KATANA_KNOWN_FILE_VALUES = frozenset({"all", "robotstxt", "sitemapxml"})
SAFE_KATANA_KNOWN_FILE_PATTERN = re.compile(r"^[A-Za-z0-9,]{1,64}$")
ANSI_CONTROL_PATTERN = re.compile(r"(?:\x1B\[[0-?]*[ -/]*[@-~]|\x1B[@-_][0-?]*[ -/]*[@-~]|[\x00-\x08\x0B\x0C\x0E-\x1F\x7F])")
MAX_KATANA_ERROR_BYTES = 2_000


def run_katana_scan(target: str) -> dict[str, object]:
    validated_target = _validate_target(target)
    settings = get_settings()
    executable = _resolve_katana_executable(settings.katana_path)
    working_directory = Path.cwd().resolve()
    if executable is None:
        logger.warning(
            "Katana executable missing. Checked PATH lookup and candidate paths: %s",
            [str(candidate) for candidate in _katana_executable_candidates()],
        )
        return _result(
            target=validated_target,
            success=False,
            error=KATANA_NOT_AVAILABLE_ERROR,
            error_type="missing_binary",
            elapsed_seconds=0,
            command=None,
            working_directory=working_directory,
        )

    try:
        command = _build_katana_command(
            executable,
            validated_target,
            crawl_depth=settings.katana_crawl_depth,
            concurrency=settings.katana_concurrency,
            rate_limit=settings.katana_rate_limit,
            crawl_duration_seconds=settings.katana_crawl_duration_seconds,
            max_response_size_bytes=settings.katana_max_response_size_bytes,
            field_scope=settings.katana_field_scope,
            known_files=settings.katana_known_files,
            js_crawl=settings.katana_js_crawl,
            form_extraction=settings.katana_form_extraction,
        )
    except ValueError as exc:
        return _result(
            target=validated_target,
            success=False,
            error=str(exc),
            error_type="invalid_configuration",
            elapsed_seconds=0,
            command=None,
            working_directory=working_directory,
        )
    start_time = time.monotonic()
    logger.info(
        "Katana crawl started: target=%s timeout=%s depth=%s",
        validated_target,
        settings.katana_scan_timeout_seconds,
        settings.katana_crawl_depth,
    )
    logger.info("Katana subprocess prepared: arg_count=%s", len(command))
    try:
        completed = subprocess.run(  # nosec B603
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=settings.katana_scan_timeout_seconds,
            cwd=str(working_directory),
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed_seconds = time.monotonic() - start_time
        logger.warning("Katana crawl timed out: target=%s elapsed_seconds=%.2f", validated_target, elapsed_seconds)
        return _result(
            target=validated_target,
            success=False,
            output=exc.stdout or "",
            error=exc.stderr or KATANA_TIMEOUT_ERROR,
            error_type="timeout",
            elapsed_seconds=elapsed_seconds,
            command=command,
            working_directory=working_directory,
        )
    except FileNotFoundError:
        elapsed_seconds = time.monotonic() - start_time
        logger.warning("Katana executable missing: target=%s elapsed_seconds=%.2f", validated_target, elapsed_seconds)
        return _result(
            target=validated_target,
            success=False,
            error=KATANA_NOT_AVAILABLE_ERROR,
            error_type="missing_binary",
            elapsed_seconds=elapsed_seconds,
            command=command,
            working_directory=working_directory,
        )
    except OSError as exc:
        elapsed_seconds = time.monotonic() - start_time
        logger.warning("Katana execution failed: target=%s elapsed_seconds=%.2f error=%s", validated_target, elapsed_seconds, exc)
        return _result(
            target=validated_target,
            success=False,
            error="Katana execution failed.",
            error_type="execution_failed",
            elapsed_seconds=elapsed_seconds,
            command=command,
            working_directory=working_directory,
        )
    except Exception:
        elapsed_seconds = time.monotonic() - start_time
        logger.exception("Katana runner error: target=%s elapsed_seconds=%.2f", validated_target, elapsed_seconds)
        return _result(
            target=validated_target,
            success=False,
            error="Katana runner error.",
            error_type="runner_error",
            elapsed_seconds=elapsed_seconds,
            command=command,
            working_directory=working_directory,
        )

    elapsed_seconds = time.monotonic() - start_time
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    logger.info(
        "Katana crawl completed: target=%s elapsed_seconds=%.2f stdout_len=%s stderr_len=%s exit_code=%s",
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
        error="" if completed.returncode == 0 else _failure_error(stderr, stdout),
        error_type=None if completed.returncode == 0 else "execution_failed",
        returncode=completed.returncode,
        elapsed_seconds=elapsed_seconds,
        command=command,
        working_directory=working_directory,
    )


def _validate_target(target: str) -> str:
    if any(character in str(target or "") for character in DANGEROUS_SHELL_CHARACTERS):
        raise ValueError("Katana target contains unsupported shell characters.")
    return normalize_for_katana(target)


def _resolve_katana_executable(configured_path: str = "katana") -> str | None:
    if configured_path and configured_path != "katana":
        return configured_path

    path_executable = shutil.which("katana")
    if path_executable:
        return path_executable

    for candidate in _katana_executable_candidates():
        if candidate.is_file():
            return str(candidate)
    return None


def _katana_executable_candidates() -> tuple[Path, Path, Path, Path, Path]:
    return (
        Path("/usr/local/bin/katana"),
        Path("/usr/bin/katana"),
        Path.home() / "go" / "bin" / "katana",
        Path(".venv") / "Scripts" / "katana.exe",
        Path(".venv") / "bin" / "katana",
    )


def _build_katana_command(
    executable: str,
    target: str,
    crawl_depth: int = 3,
    *,
    concurrency: int = 10,
    rate_limit: int = 50,
    crawl_duration_seconds: int = 120,
    max_response_size_bytes: int = 4_194_304,
    field_scope: str = "fqdn",
    known_files: str = "robotstxt,sitemapxml",
    js_crawl: bool = True,
    form_extraction: bool = True,
) -> list[str]:
    depth = _bounded_int(crawl_depth, default=3, minimum=1, maximum=MAX_KATANA_DEPTH)
    safe_concurrency = _bounded_int(concurrency, default=10, minimum=1, maximum=MAX_KATANA_CONCURRENCY)
    safe_rate_limit = _bounded_int(rate_limit, default=50, minimum=1, maximum=MAX_KATANA_RATE_LIMIT)
    safe_duration = _bounded_int(crawl_duration_seconds, default=120, minimum=1, maximum=MAX_KATANA_CRAWL_DURATION_SECONDS)
    safe_response_size = _bounded_int(max_response_size_bytes, default=4_194_304, minimum=1, maximum=MAX_KATANA_RESPONSE_SIZE_BYTES)
    safe_scope = _normalize_field_scope(field_scope)
    safe_known_files = _normalize_known_files(known_files)
    command = [
        executable,
        "-u",
        target,
        "-j",
        "-silent",
        "-nc",
        "-d",
        str(depth),
        "-c",
        str(safe_concurrency),
        "-rl",
        str(safe_rate_limit),
        "-ct",
        f"{safe_duration}s",
        "-mrs",
        str(safe_response_size),
        "-fs",
        safe_scope,
        "-ob",
    ]
    if js_crawl:
        command.append("-jc")
    if form_extraction:
        command.append("-fx")
    for known_file in safe_known_files:
        command.extend(["-kf", known_file])
    return command


def _bounded_int(value: object, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value if value not in (None, "") else default)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def _normalize_field_scope(value: object) -> str:
    scope = str(value or "fqdn").strip().lower()
    if scope not in KATANA_FIELD_SCOPES:
        raise ValueError("Katana field scope configuration is malformed.")
    return scope


def _normalize_known_files(value: object) -> list[str]:
    raw = str(value or "").strip().lower()
    if not raw:
        return []
    if not SAFE_KATANA_KNOWN_FILE_PATTERN.fullmatch(raw):
        raise ValueError("Katana known-files configuration is malformed.")
    values = []
    for item in raw.split(","):
        cleaned = item.strip()
        if not cleaned:
            continue
        if cleaned not in KATANA_KNOWN_FILE_VALUES:
            raise ValueError("Katana known-files configuration is malformed.")
        if cleaned not in values:
            values.append(cleaned)
    if "all" in values:
        return ["all"]
    return values


def _failure_error(stderr: str, stdout: str) -> str:
    diagnostic = stderr or stdout or "Katana crawl failed."
    diagnostic = ANSI_CONTROL_PATTERN.sub("", str(diagnostic)).strip()
    if not diagnostic:
        return "Katana crawl failed."
    encoded = diagnostic.encode("utf-8", errors="ignore")
    if len(encoded) <= MAX_KATANA_ERROR_BYTES:
        return diagnostic
    truncated = encoded[:MAX_KATANA_ERROR_BYTES].decode("utf-8", errors="ignore").rstrip()
    return f"{truncated}...[truncated]"


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
