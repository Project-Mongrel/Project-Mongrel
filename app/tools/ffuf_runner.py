import logging
import math
import re
from pathlib import Path
import shutil
import threading
import time
from urllib.parse import urlparse, urlunparse

from app.core.config import get_settings
from app.services.target_normalizer import normalize_for_ffuf
from app.tools.nmap_runner import DANGEROUS_SHELL_CHARACTERS
from app.tools.process_lifecycle import run_scanner_process

logger = logging.getLogger(__name__)
FFUF_NOT_AVAILABLE_ERROR = "ffuf executable was not found."
FFUF_TIMEOUT_ERROR = "ffuf hidden-content discovery timed out."
FFUF_WORDLIST_MISSING_ERROR = "ffuf wordlist was not found."
DEFAULT_FFUF_WORDLIST = Path("app/resources/wordlists/ffuf_default.txt")
FFUF_MATCH_STATUS_CODES = "200-299,300-399,401,403,405,407,409,429,500-599"
MAX_FFUF_THREADS = 50
MAX_FFUF_RATE_LIMIT = 500
# Deep runs reserve a bounded 20-minute margin beyond the rate-limit floor for
# DNS, target latency, retries, filtering, and process overhead.
FFUF_DEEP_TIMEOUT_MARGIN_SECONDS = 1200
SAFE_FFUF_EXTENSION_PATTERN = re.compile(r"^\.[A-Za-z0-9]{1,16}$")
FFUF_PROFILE_QUICK = "quick"
FFUF_PROFILE_STANDARD = "standard"
FFUF_PROFILE_DEEP = "deep"
FFUF_PROFILE_CUSTOM = "custom"
FFUF_PROFILE_LABELS = {
    FFUF_PROFILE_QUICK: "Quick",
    FFUF_PROFILE_STANDARD: "Standard",
    FFUF_PROFILE_DEEP: "Deep",
    FFUF_PROFILE_CUSTOM: "Custom",
}
FFUF_PROFILE_SOURCE_LABELS = {
    FFUF_PROFILE_QUICK: "Bundled smoke-test wordlist",
    FFUF_PROFILE_STANDARD: "Configured Standard external wordlist",
    FFUF_PROFILE_DEEP: "Configured Deep external wordlist",
    FFUF_PROFILE_CUSTOM: "Configured Custom wordlist",
}
FFUF_PROFILE_ENV_VARS = {
    FFUF_PROFILE_STANDARD: "FFUF_WORDLIST_STANDARD_PATH",
    FFUF_PROFILE_DEEP: "FFUF_WORDLIST_DEEP_PATH",
    FFUF_PROFILE_CUSTOM: "FFUF_WORDLIST_PATH",
}


def run_ffuf_scan(
    target: str,
    profile: str | None = None,
    *,
    cancellation_event: threading.Event | None = None,
) -> dict[str, object]:
    validated_target = _validate_target(target)
    settings = get_settings()
    executable = _resolve_ffuf_executable(settings.ffuf_path)
    working_directory = Path.cwd().resolve()
    wordlist_info = resolve_ffuf_profile_wordlist(profile, settings=settings, working_directory=working_directory)
    wordlist_path = wordlist_info["wordlist_path"]
    wordlist_count = int(wordlist_info["wordlist_count"] or 0)
    timeout_seconds = resolve_ffuf_profile_timeout(
        profile,
        settings=settings,
        wordlist_count=wordlist_count,
    )

    if cancellation_event is not None and cancellation_event.is_set():
        return _result(
            target=validated_target,
            success=False,
            error="ffuf scan cancelled.",
            error_type="cancelled",
            elapsed_seconds=0,
            command=None,
            working_directory=working_directory,
            wordlist_path=wordlist_path,
            wordlist_count=wordlist_count,
            fuzz_url=None,
            profile_info=wordlist_info,
            timeout_seconds=timeout_seconds,
        )

    if executable is None:
        logger.warning("ffuf executable missing. Checked PATH and candidate paths: %s", [str(candidate) for candidate in _ffuf_executable_candidates()])
        return _result(
            target=validated_target,
            success=False,
            error=FFUF_NOT_AVAILABLE_ERROR,
            error_type="missing_binary",
            elapsed_seconds=0,
            command=None,
            working_directory=working_directory,
            wordlist_path=wordlist_path,
            wordlist_count=wordlist_count,
            fuzz_url=None,
            profile_info=wordlist_info,
            timeout_seconds=timeout_seconds,
        )
    if wordlist_path is None:
        logger.warning("ffuf wordlist missing: profile=%s configured=%s", wordlist_info["profile"], wordlist_info["configured_path"])
        return _result(
            target=validated_target,
            success=False,
            error=str(wordlist_info["error"] or FFUF_WORDLIST_MISSING_ERROR),
            error_type="missing_wordlist",
            elapsed_seconds=0,
            command=None,
            working_directory=working_directory,
            wordlist_path=None,
            wordlist_count=0,
            fuzz_url=None,
            profile_info=wordlist_info,
            timeout_seconds=timeout_seconds,
        )

    fuzz_url = _build_fuzz_url(validated_target)
    try:
        command = _build_ffuf_command(
            executable,
            fuzz_url,
            wordlist_path,
            threads=settings.ffuf_threads,
            rate_limit=settings.ffuf_rate_limit,
            extensions=settings.ffuf_extensions,
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
            wordlist_path=wordlist_path,
            wordlist_count=wordlist_count,
            fuzz_url=fuzz_url,
            profile_info=wordlist_info,
            timeout_seconds=timeout_seconds,
        )
    start_time = time.monotonic()
    logger.info("ffuf scan started: target=%s timeout=%s profile=%s wordlist_count=%s", validated_target, timeout_seconds, wordlist_info["profile"], wordlist_count)
    logger.info("ffuf subprocess prepared: arg_count=%s", len(command))
    try:
        completed = run_scanner_process(
            command,
            timeout_seconds=timeout_seconds,
            cwd=str(working_directory),
            cancellation_event=cancellation_event,
        )
        if completed.timed_out or completed.cancelled:
            elapsed_seconds = time.monotonic() - start_time
            error_type = "cancelled" if completed.cancelled else "timeout"
            logger.warning("ffuf scan %s: target=%s elapsed_seconds=%.2f", error_type, validated_target, elapsed_seconds)
            return _result(
                target=validated_target,
                success=False,
                output=completed.stdout,
                error=completed.stderr or ("ffuf scan cancelled." if completed.cancelled else FFUF_TIMEOUT_ERROR),
                error_type=error_type,
                returncode=completed.returncode,
                elapsed_seconds=elapsed_seconds,
                command=command,
                working_directory=working_directory,
                wordlist_path=wordlist_path,
                wordlist_count=wordlist_count,
                fuzz_url=fuzz_url,
                profile_info=wordlist_info,
                timeout_seconds=timeout_seconds,
            )
    except FileNotFoundError:
        elapsed_seconds = time.monotonic() - start_time
        return _result(
            target=validated_target,
            success=False,
            error=FFUF_NOT_AVAILABLE_ERROR,
            error_type="missing_binary",
            elapsed_seconds=elapsed_seconds,
            command=command,
            working_directory=working_directory,
            wordlist_path=wordlist_path,
            wordlist_count=wordlist_count,
            fuzz_url=fuzz_url,
            profile_info=wordlist_info,
            timeout_seconds=timeout_seconds,
        )
    except OSError as exc:
        elapsed_seconds = time.monotonic() - start_time
        logger.warning("ffuf execution failed: target=%s elapsed_seconds=%.2f error=%s", validated_target, elapsed_seconds, exc)
        return _result(
            target=validated_target,
            success=False,
            error="ffuf execution failed.",
            error_type="execution_failed",
            elapsed_seconds=elapsed_seconds,
            command=command,
            working_directory=working_directory,
            wordlist_path=wordlist_path,
            wordlist_count=wordlist_count,
            fuzz_url=fuzz_url,
            profile_info=wordlist_info,
            timeout_seconds=timeout_seconds,
        )

    elapsed_seconds = time.monotonic() - start_time
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    logger.info(
        "ffuf scan completed: target=%s elapsed_seconds=%.2f stdout_len=%s stderr_len=%s exit_code=%s",
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
        error=stderr,
        error_type=None if completed.returncode == 0 else "execution_failed",
        returncode=completed.returncode,
        elapsed_seconds=elapsed_seconds,
        command=command,
        working_directory=working_directory,
        wordlist_path=wordlist_path,
        wordlist_count=wordlist_count,
        fuzz_url=fuzz_url,
        profile_info=wordlist_info,
        timeout_seconds=timeout_seconds,
    )


def _validate_target(target: str) -> str:
    if any(character in str(target or "") for character in DANGEROUS_SHELL_CHARACTERS):
        raise ValueError("ffuf target contains unsupported shell characters.")
    return normalize_for_ffuf(target)


def _resolve_ffuf_executable(configured_path: str = "ffuf") -> str | None:
    if configured_path and configured_path != "ffuf":
        return configured_path
    path_executable = shutil.which("ffuf")
    if path_executable:
        return path_executable
    for candidate in _ffuf_executable_candidates():
        if candidate.is_file():
            return str(candidate)
    return None


def _ffuf_executable_candidates() -> tuple[Path, Path, Path, Path, Path]:
    return (
        Path("/usr/local/bin/ffuf"),
        Path("/usr/bin/ffuf"),
        Path.home() / "go" / "bin" / "ffuf",
        Path(".venv") / "Scripts" / "ffuf.exe",
        Path(".venv") / "bin" / "ffuf",
    )


def _resolve_wordlist_path(configured_path: Path | str, working_directory: Path | None = None) -> Path | None:
    candidate = Path(configured_path or DEFAULT_FFUF_WORDLIST)
    if candidate.is_file():
        return candidate
    rooted = (working_directory or Path.cwd()).resolve() / candidate
    if rooted.is_file():
        return rooted
    return None


def normalize_ffuf_profile(profile: str | None) -> str:
    normalized = str(profile or FFUF_PROFILE_CUSTOM).strip().lower()
    if normalized not in FFUF_PROFILE_LABELS:
        return FFUF_PROFILE_CUSTOM
    return normalized


def resolve_ffuf_profile_wordlist(profile: str | None = None, *, settings: object | None = None, working_directory: Path | None = None) -> dict[str, object]:
    resolved_settings = settings or get_settings()
    working_directory = (working_directory or Path.cwd()).resolve()
    normalized_profile = normalize_ffuf_profile(profile)
    configured_path = _configured_wordlist_for_profile(resolved_settings, normalized_profile)
    wordlist_path = _resolve_wordlist_path(configured_path, working_directory) if configured_path else None
    wordlist_count = _count_wordlist_entries(wordlist_path) if wordlist_path is not None else 0
    env_var = FFUF_PROFILE_ENV_VARS.get(normalized_profile)
    error = ""
    if wordlist_path is None:
        if env_var and not configured_path:
            error = f"ffuf {FFUF_PROFILE_LABELS[normalized_profile]} profile wordlist is not configured ({env_var})."
        else:
            configured_label = str(configured_path or "")
            error = f"ffuf {FFUF_PROFILE_LABELS[normalized_profile]} profile wordlist was not found: {configured_label}"
    return {
        "profile": normalized_profile,
        "profile_label": FFUF_PROFILE_LABELS[normalized_profile],
        "source_label": FFUF_PROFILE_SOURCE_LABELS[normalized_profile],
        "env_var": env_var,
        "configured_path": str(configured_path or ""),
        "wordlist_path": wordlist_path,
        "wordlist_count": wordlist_count,
        "available": wordlist_path is not None,
        "error": error,
    }


def resolve_ffuf_profile_timeout(
    profile: str | None = None,
    *,
    settings: object | None = None,
    wordlist_count: int = 0,
) -> int:
    resolved_settings = settings or get_settings()
    normalized_profile = normalize_ffuf_profile(profile)
    if normalized_profile == FFUF_PROFILE_QUICK:
        return max(1, int(getattr(resolved_settings, "ffuf_quick_scan_timeout_seconds", 30) or 30))
    if normalized_profile == FFUF_PROFILE_DEEP:
        configured_timeout = max(
            1,
            int(getattr(resolved_settings, "ffuf_deep_scan_timeout_seconds", 2400) or 2400),
        )
        bounded_rate = max(
            1,
            min(int(getattr(resolved_settings, "ffuf_rate_limit", 25) or 25), MAX_FFUF_RATE_LIMIT),
        )
        request_floor = math.ceil(max(0, int(wordlist_count or 0)) / bounded_rate)
        return max(configured_timeout, request_floor + FFUF_DEEP_TIMEOUT_MARGIN_SECONDS)
    return max(1, int(getattr(resolved_settings, "ffuf_scan_timeout_seconds", 120) or 120))


def _configured_wordlist_for_profile(settings: object, profile: str) -> Path | str | None:
    if profile == FFUF_PROFILE_QUICK:
        return DEFAULT_FFUF_WORDLIST
    if profile == FFUF_PROFILE_STANDARD:
        return getattr(settings, "ffuf_wordlist_standard_path", None)
    if profile == FFUF_PROFILE_DEEP:
        return getattr(settings, "ffuf_wordlist_deep_path", None)
    return getattr(settings, "ffuf_wordlist_path", DEFAULT_FFUF_WORDLIST)


def _count_wordlist_entries(path: Path) -> int:
    try:
        return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.strip().startswith("#"))
    except OSError:
        return 0


def _build_fuzz_url(target: str) -> str:
    parsed = urlparse(target)
    if "FUZZ" in target:
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", parsed.query, ""))
    base_path = parsed.path.rstrip("/")
    fuzz_path = f"{base_path}/FUZZ" if base_path else "/FUZZ"
    return urlunparse((parsed.scheme, parsed.netloc, fuzz_path, "", "", ""))


def _build_ffuf_command(executable: str, fuzz_url: str, wordlist_path: Path, *, threads: int = 5, rate_limit: int = 25, extensions: str = "") -> list[str]:
    safe_threads = max(1, min(int(threads or 5), MAX_FFUF_THREADS))
    safe_rate_limit = max(1, min(int(rate_limit or 25), MAX_FFUF_RATE_LIMIT))
    command = [
        executable,
        "-u",
        fuzz_url,
        "-w",
        str(wordlist_path),
        "-of",
        "json",
        "-s",
        "-t",
        str(safe_threads),
        "-rate",
        str(safe_rate_limit),
        "-mc",
        FFUF_MATCH_STATUS_CODES,
    ]
    safe_extensions = _normalize_ffuf_extensions(extensions)
    if safe_extensions:
        command.extend(["-e", ",".join(safe_extensions)])
    return command


def _normalize_ffuf_extensions(raw_extensions: object) -> list[str]:
    normalized: list[str] = []
    for item in str(raw_extensions or "").split(","):
        extension = item.strip().lower()
        if not extension:
            continue
        if not extension.startswith("."):
            extension = f".{extension}"
        if not SAFE_FFUF_EXTENSION_PATTERN.fullmatch(extension):
            raise ValueError("ffuf extension configuration is malformed.")
        if extension not in normalized:
            normalized.append(extension)
        if len(normalized) >= 20:
            break
    return normalized


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
    wordlist_path: Path | None,
    wordlist_count: int,
    fuzz_url: str | None,
    profile_info: dict[str, object] | None = None,
    timeout_seconds: int | None = None,
) -> dict[str, object]:
    profile_info = profile_info or {}
    return {
        "target": target,
        "success": success,
        "output": output,
        "error": error,
        "error_type": error_type,
        "returncode": returncode,
        "exit_code": returncode,
        "elapsed_seconds": elapsed_seconds,
        "timeout_seconds": timeout_seconds,
        "command": command,
        "working_directory": str(working_directory),
        "stdout_len": len(output or ""),
        "stderr_len": len(error or ""),
        "wordlist_path": str(wordlist_path) if wordlist_path else None,
        "wordlist_count": wordlist_count,
        "wordlist_source": profile_info.get("source_label") or "",
        "wordlist_configured_path": profile_info.get("configured_path") or "",
        "ffuf_profile": profile_info.get("profile") or FFUF_PROFILE_CUSTOM,
        "ffuf_profile_label": profile_info.get("profile_label") or FFUF_PROFILE_LABELS[FFUF_PROFILE_CUSTOM],
        "fuzz_url": fuzz_url,
    }
