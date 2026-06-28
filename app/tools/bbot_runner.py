import logging
from pathlib import Path
# Required to run authorized local BBOT subprocesses.
import subprocess  # nosec B404
import threading
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
    output_dir = (BBOT_OUTPUT_DIR / _safe_output_name(validated_target)).resolve()
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
            "command": None,
            "working_directory": str(Path.cwd().resolve()),
        }

    command = _build_bbot_command(executable, validated_target, output_dir)
    working_directory = Path.cwd().resolve()
    started_at = time.monotonic()
    logger.info("BBOT recon started: target=%s output_dir=%s", validated_target, output_dir)
    logger.info("BBOT subprocess argv: %r", command)
    logger.info("BBOT working directory: %s", working_directory)

    try:
        # Command uses explicit args list, shell=False, and a validated target.
        process = subprocess.Popen(  # nosec B603
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=str(working_directory),
            shell=False,
        )
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
            "command": command,
            "working_directory": str(working_directory),
        }

    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    stdout_thread = _start_stream_thread(process.stdout, stdout_lines, "stdout")
    stderr_thread = _start_stream_thread(process.stderr, stderr_lines, "stderr")

    try:
        returncode = process.wait(timeout=BBOT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        logger.error("BBOT recon timed out after %ss: argv=%r cwd=%s", BBOT_TIMEOUT_SECONDS, command, working_directory)
        process.kill()
        returncode = process.wait()
        _join_stream_thread(stdout_thread, "stdout")
        _join_stream_thread(stderr_thread, "stderr")
        elapsed_seconds = time.monotonic() - started_at
        return {
            "target": validated_target,
            "success": False,
            "output": "\n".join(stdout_lines),
            "error": "\n".join(stderr_lines) or "BBOT recon timed out.",
            "error_type": "timeout",
            "returncode": returncode,
            "elapsed_seconds": elapsed_seconds,
            "output_dir": str(output_dir),
            "command": command,
            "working_directory": str(working_directory),
        }

    logger.info("BBOT process exited normally: returncode=%s", returncode)
    _join_stream_thread(stdout_thread, "stdout")
    _join_stream_thread(stderr_thread, "stderr")
    logger.info("BBOT output stream readers completed after process exit.")
    elapsed_seconds = time.monotonic() - started_at
    success = returncode == 0
    stdout = "\n".join(stdout_lines)
    stderr = "\n".join(stderr_lines)
    if not success and _is_runtime_incompatible_error(stdout, stderr):
        logger.error(
            "BBOT runtime incompatible: target=%s returncode=%s stdout=%s stderr=%s",
            validated_target,
            returncode,
            stdout,
            stderr,
        )
        return {
            "target": validated_target,
            "success": False,
            "output": "",
            "error": BBOT_RUNTIME_INCOMPATIBLE_ERROR,
            "error_type": "runtime_incompatible",
            "returncode": returncode,
            "elapsed_seconds": elapsed_seconds,
            "output_dir": str(output_dir),
            "command": command,
            "working_directory": str(working_directory),
        }

    json_output, json_output_paths = _read_bbot_json_output(output_dir)
    combined_output = _combine_output(stdout, json_output)
    return {
        "target": validated_target,
        "success": success,
        "output": combined_output,
        "error": stderr or ("" if success else "BBOT recon failed."),
        "error_type": None if success else "bbot_failed",
        "returncode": returncode,
        "elapsed_seconds": elapsed_seconds,
        "output_dir": str(output_dir),
        "command": command,
        "working_directory": str(working_directory),
        "json_output_paths": json_output_paths,
        "json_output_found": bool(json_output_paths),
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


def _start_stream_thread(pipe: object, lines: list[str], stream_name: str) -> threading.Thread:
    thread = threading.Thread(target=_stream_output, args=(pipe, lines, stream_name), daemon=True)
    thread.start()
    return thread


def _stream_output(pipe: object, lines: list[str], stream_name: str) -> None:
    if pipe is None:
        return

    try:
        for line in pipe:
            cleaned_line = str(line).rstrip("\r\n")
            lines.append(cleaned_line)
            logger.info("BBOT %s: %s", stream_name, cleaned_line)
    finally:
        close = getattr(pipe, "close", None)
        if close is not None:
            close()


def _join_stream_thread(thread: threading.Thread, stream_name: str) -> None:
    thread.join(timeout=5)
    if thread.is_alive():
        logger.warning("BBOT %s stream reader still running after process exit.", stream_name)


def _read_bbot_json_output(output_dir: Path) -> tuple[str, list[str]]:
    json_files = sorted(
        path
        for path in output_dir.rglob("*")
        if path.is_file() and path.suffix.lower() in {".json", ".jsonl", ".ndjson"}
    )
    if not json_files:
        logger.warning("BBOT JSON output path not found under %s", output_dir)
        return "", []

    file_contents = []
    paths = []
    for json_file in json_files:
        paths.append(str(json_file))
        logger.info("BBOT JSON output path exists: %s", json_file)
        try:
            content = json_file.read_text(encoding="utf-8", errors="replace").strip()
        except OSError as exc:
            logger.warning("Unable to read BBOT JSON output %s: %s", json_file, exc)
            continue
        if content:
            file_contents.append(content)

    return "\n".join(file_contents), paths


def _combine_output(stdout: str, json_output: str) -> str:
    parts = [part for part in (stdout.strip(), json_output.strip()) if part]
    return "\n".join(parts)
