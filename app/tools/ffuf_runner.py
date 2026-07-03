import logging
from pathlib import Path
# Required to run authorized local ffuf subprocesses.
import subprocess  # nosec B404
import shutil
import time
from urllib.parse import urlparse, urlunparse

from app.core.config import get_settings
from app.services.target_normalizer import normalize_for_ffuf
from app.tools.nmap_runner import DANGEROUS_SHELL_CHARACTERS

logger = logging.getLogger(__name__)
FFUF_NOT_AVAILABLE_ERROR = "ffuf executable was not found."
FFUF_TIMEOUT_ERROR = "ffuf hidden-content discovery timed out."
FFUF_WORDLIST_MISSING_ERROR = "ffuf wordlist was not found."
DEFAULT_FFUF_WORDLIST = Path("app/resources/wordlists/ffuf_default.txt")


def run_ffuf_scan(target: str) -> dict[str, object]:
    validated_target = _validate_target(target)
    settings = get_settings()
    executable = _resolve_ffuf_executable(settings.ffuf_path)
    working_directory = Path.cwd().resolve()
    wordlist_path = _resolve_wordlist_path(settings.ffuf_wordlist_path, working_directory)
    wordlist_count = _count_wordlist_entries(wordlist_path) if wordlist_path is not None else 0

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
        )
    if wordlist_path is None:
        logger.warning("ffuf wordlist missing: configured=%s", settings.ffuf_wordlist_path)
        return _result(
            target=validated_target,
            success=False,
            error=FFUF_WORDLIST_MISSING_ERROR,
            error_type="missing_wordlist",
            elapsed_seconds=0,
            command=None,
            working_directory=working_directory,
            wordlist_path=None,
            wordlist_count=0,
            fuzz_url=None,
        )

    fuzz_url = _build_fuzz_url(validated_target)
    command = _build_ffuf_command(
        executable,
        fuzz_url,
        wordlist_path,
        threads=settings.ffuf_threads,
        rate_limit=settings.ffuf_rate_limit,
    )
    start_time = time.monotonic()
    logger.info("ffuf scan started: target=%s timeout=%s wordlist_count=%s", validated_target, settings.ffuf_scan_timeout_seconds, wordlist_count)
    logger.info("ffuf subprocess argv: %r", command)
    try:
        completed = subprocess.run(  # nosec B603
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=settings.ffuf_scan_timeout_seconds,
            cwd=str(working_directory),
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed_seconds = time.monotonic() - start_time
        logger.warning("ffuf scan timed out: target=%s elapsed_seconds=%.2f", validated_target, elapsed_seconds)
        return _result(
            target=validated_target,
            success=False,
            output=exc.stdout or "",
            error=exc.stderr or FFUF_TIMEOUT_ERROR,
            error_type="timeout",
            elapsed_seconds=elapsed_seconds,
            command=command,
            working_directory=working_directory,
            wordlist_path=wordlist_path,
            wordlist_count=wordlist_count,
            fuzz_url=fuzz_url,
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


def _count_wordlist_entries(path: Path) -> int:
    try:
        return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.strip().startswith("#"))
    except OSError:
        return 0


def _build_fuzz_url(target: str) -> str:
    parsed = urlparse(target)
    base_path = parsed.path.rstrip("/")
    fuzz_path = f"{base_path}/FUZZ" if base_path else "/FUZZ"
    return urlunparse((parsed.scheme, parsed.netloc, fuzz_path, "", "", ""))


def _build_ffuf_command(executable: str, fuzz_url: str, wordlist_path: Path, *, threads: int = 5, rate_limit: int = 25) -> list[str]:
    safe_threads = max(1, min(int(threads or 5), 10))
    safe_rate_limit = max(1, min(int(rate_limit or 25), 50))
    return [
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
        "200,204,301,302,307,308,401,403,500",
    ]


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
        "wordlist_path": str(wordlist_path) if wordlist_path else None,
        "wordlist_count": wordlist_count,
        "fuzz_url": fuzz_url,
    }
