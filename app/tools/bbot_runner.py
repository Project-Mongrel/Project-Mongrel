import logging
from pathlib import Path
# Required to run authorized local BBOT subprocesses.
import subprocess  # nosec B404
import re
import threading
import time
import shutil
from uuid import uuid4

from app.core.config import get_settings
from app.tools.nmap_runner import DANGEROUS_SHELL_CHARACTERS
from app.services.target_normalizer import normalize_for_bbot

BBOT_TIMEOUT_SECONDS = 600
BBOT_OUTPUT_DIR = Path("data") / "bbot"
BBOT_NOT_AVAILABLE_ERROR = "BBOT is not installed or not available on PATH."
BBOT_UNAPPROVED_PROFILE_ERROR = (
    "Configured BBOT profile is materially aggressive or intrusive and requires an explicit approval workflow before execution."
)
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
MAX_BBOT_TIMEOUT_SECONDS = 1800
MAX_BBOT_SCOPE_DISTANCE = 2
MAX_BBOT_DNS_THREADS = 50
MAX_BBOT_DNS_BRUTE_THREADS = 500
MAX_BBOT_DNS_TIMEOUT_SECONDS = 20
MAX_BBOT_DNS_RETRIES = 5
MAX_BBOT_WEB_TIMEOUT_SECONDS = 30
MAX_BBOT_WEB_RETRIES = 5
MAX_BBOT_WEB_SPIDER_DISTANCE = 2
MAX_BBOT_WEB_SPIDER_DEPTH = 4
MAX_BBOT_WEB_LINKS_PER_PAGE = 50
MAX_BBOT_OUTPUT_BYTES = 5_000_000
MAX_BBOT_JSON_FILES = 100
SAFE_BBOT_VALUE_PATTERN = re.compile(r"^[A-Za-z0-9_.:/\\,-]+$")
ANSI_CONTROL_PATTERN = re.compile(r"(?:\x1B\[[0-?]*[ -/]*[@-~]|\x1B[@-_][0-?]*[ -/]*[@-~]|[\x00-\x08\x0B\x0C\x0E-\x1F\x7F])")
ALLOWED_BBOT_PRESETS = {
    "subdomain-enum",
    "email-enum",
    "cloud-enum",
    "code-enum",
    "web-basic",
    "spider",
}
AGGRESSIVE_BBOT_PRESETS = {
    "web-thorough",
    "kitchen-sink",
    "dirbust-light",
    "paramminer",
    "web-screenshots",
    "baddns-intense",
}
ALLOWED_BBOT_MODULES = {
    "anubisdb",
    "bufferoverrun",
    "certspotter",
    "crt",
    "dnsdumpster",
    "hackertarget",
    "rapiddns",
    "securitytrails",
    "subdomaincenter",
    "urlscan",
    "wayback",
    "wafw00f",
    "robots",
    "securitytxt",
    "sslcert",
    "http",
}
AGGRESSIVE_BBOT_MODULES = {
    "portscan",
    "nuclei",
    "webbrute",
    "lightfuzz",
    "paramminer_getparams",
    "paramminer_headers",
    "paramminer_cookies",
    "baddns",
    "generic_ssrf",
    "git_clone",
    "gitdumper",
}
ALLOWED_BBOT_FLAGS = {
    "passive",
    "safe",
    "subdomain-enum",
    "email-enum",
    "cloud-enum",
    "code-enum",
    "web",
    "web-basic",
    "active",
}
AGGRESSIVE_BBOT_FLAGS = {"aggressive", "invasive", "loud", "deadly", "web-heavy", "web-screenshots", "portscan"}
logger = logging.getLogger(__name__)


def is_bbot_available() -> bool:
    return _resolve_bbot_executable(get_settings().bbot_binary) is not None


def check_bbot_readiness() -> dict[str, object]:
    settings = get_settings()
    executable = _resolve_bbot_executable(settings.bbot_binary)
    if executable is None:
        return {"ready": False, "error": BBOT_NOT_AVAILABLE_ERROR, "executable": None, "version": ""}
    try:
        completed = subprocess.run(  # nosec B603
            [executable, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            shell=False,
            check=False,
        )
    except (FileNotFoundError, OSError):
        return {"ready": False, "error": BBOT_NOT_AVAILABLE_ERROR, "executable": executable, "version": ""}
    version_text = _bounded_text((completed.stdout or completed.stderr or "").strip(), 500, label="version")[0]
    return {
        "ready": completed.returncode == 0,
        "error": "" if completed.returncode == 0 else "BBOT version check failed.",
        "executable": executable,
        "version": version_text,
    }


def run_bbot_scan(target: str) -> dict[str, object]:
    validated_target = _validate_target(target)
    settings = get_settings()
    output_dir = _run_output_dir(validated_target)
    output_dir.mkdir(parents=True, exist_ok=True)
    executable = _resolve_bbot_executable(settings.bbot_binary)
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

    try:
        command = _build_bbot_command(executable, validated_target, output_dir, settings)
    except ValueError as exc:
        return {
            "target": validated_target,
            "success": False,
            "output": "",
            "error": str(exc),
            "error_type": "invalid_configuration",
            "returncode": None,
            "elapsed_seconds": 0,
            "output_dir": str(output_dir),
            "command": None,
            "working_directory": str(Path.cwd().resolve()),
        }
    working_directory = Path.cwd().resolve()
    timeout_seconds = _bounded_int(
        getattr(settings, "bbot_scan_timeout_seconds", BBOT_TIMEOUT_SECONDS),
        minimum=10,
        maximum=MAX_BBOT_TIMEOUT_SECONDS,
        default=BBOT_TIMEOUT_SECONDS,
    )
    max_output_bytes = _bounded_int(
        getattr(settings, "bbot_max_output_bytes", 2_000_000),
        minimum=10_000,
        maximum=MAX_BBOT_OUTPUT_BYTES,
        default=2_000_000,
    )
    started_at = time.monotonic()
    logger.info("BBOT recon started: target=%s output_dir=%s timeout=%s", validated_target, output_dir, timeout_seconds)
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
    stdout_thread = _start_stream_thread(process.stdout, stdout_lines, "stdout", max_output_bytes)
    stderr_thread = _start_stream_thread(process.stderr, stderr_lines, "stderr", max_output_bytes)

    try:
        returncode = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        logger.error("BBOT recon timed out after %ss: argv=%r cwd=%s", timeout_seconds, command, working_directory)
        process.kill()
        returncode = process.wait()
        _join_stream_thread(stdout_thread, "stdout")
        _join_stream_thread(stderr_thread, "stderr")
        elapsed_seconds = time.monotonic() - started_at
        stdout = "\n".join(stdout_lines)
        stderr = "\n".join(stderr_lines)
        json_output, json_output_paths, json_truncated = _read_bbot_json_output(output_dir, settings)
        return {
            "target": validated_target,
            "success": False,
            "output": _combine_output(stdout, json_output),
            "error": stderr or "BBOT recon timed out.",
            "error_type": "timeout",
            "returncode": returncode,
            "elapsed_seconds": elapsed_seconds,
            "output_dir": str(output_dir),
            "command": command,
            "working_directory": str(working_directory),
            "json_output_paths": json_output_paths,
            "json_output_found": bool(json_output_paths),
            "output_truncated": _is_truncated(stdout) or _is_truncated(stderr) or json_truncated,
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

    json_output, json_output_paths, json_truncated = _read_bbot_json_output(output_dir, settings)
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
        "output_truncated": _is_truncated(stdout) or _is_truncated(stderr) or json_truncated,
    }


def _validate_target(target: str) -> str:
    if any(character in target for character in DANGEROUS_SHELL_CHARACTERS):
        raise ValueError("BBOT target contains unsupported shell characters.")

    normalized_target = normalize_for_bbot(target)

    return normalized_target


def _safe_output_name(target: str) -> str:
    return "".join(character if character.isalnum() or character in {".", "-", "_"} else "_" for character in target)


def _run_output_dir(target: str) -> Path:
    return (BBOT_OUTPUT_DIR / _safe_output_name(target) / f"run-{uuid4().hex}").resolve()


def _resolve_bbot_executable(configured_path: str = "bbot") -> str | None:
    if configured_path and configured_path != "bbot":
        return configured_path
    path_executable = shutil.which("bbot")
    if path_executable:
        return path_executable

    for candidate in _system_bbot_candidates():
        if candidate.is_file():
            return str(candidate)

    return None


def _system_bbot_candidates() -> tuple[Path, Path, Path]:
    return (
        Path("/usr/local/bin/bbot"),
        Path("/usr/bin/bbot"),
        Path.home() / ".local" / "bin" / "bbot",
    )


def _build_bbot_command(executable: str, target: str, output_dir: Path, settings: object | None = None) -> list[str]:
    presets = _normalize_bbot_values(
        getattr(settings, "bbot_presets", "subdomain-enum"),
        field_name="BBOT presets",
        allowed=ALLOWED_BBOT_PRESETS,
        aggressive=AGGRESSIVE_BBOT_PRESETS,
        default="subdomain-enum",
    )
    modules = _normalize_bbot_values(
        getattr(settings, "bbot_modules", ""),
        field_name="BBOT modules",
        allowed=ALLOWED_BBOT_MODULES,
        aggressive=AGGRESSIVE_BBOT_MODULES,
    )
    require_flags = _normalize_bbot_values(
        getattr(settings, "bbot_require_flags", "passive"),
        field_name="BBOT required flags",
        allowed=ALLOWED_BBOT_FLAGS,
        aggressive=AGGRESSIVE_BBOT_FLAGS,
        default="passive",
    )
    exclude_flags = _normalize_bbot_values(
        getattr(settings, "bbot_exclude_flags", "loud,invasive,deadly,web-heavy,web-screenshots,portscan"),
        field_name="BBOT excluded flags",
        allowed=ALLOWED_BBOT_FLAGS | AGGRESSIVE_BBOT_FLAGS,
        default="loud,invasive,deadly,web-heavy,web-screenshots,portscan",
    )
    command = [
        executable,
        "-t",
        target,
        "-o",
        str(output_dir),
        "-y",
        "--json",
        "-om",
        "json",
        "stdout",
    ]
    if presets:
        command.extend(["-p", *presets])
    if modules:
        command.extend(["-m", *modules])
    if require_flags:
        command.extend(["-rf", *require_flags])
    if exclude_flags:
        command.extend(["-ef", *exclude_flags])
    command.extend(_bbot_config_args(settings))
    return command


def _bbot_config_args(settings: object | None = None) -> list[str]:
    config_values = {
        "scope.search_distance": _bounded_int(getattr(settings, "bbot_scope_search_distance", 0), minimum=0, maximum=MAX_BBOT_SCOPE_DISTANCE, default=0),
        "scope.report_distance": _bounded_int(getattr(settings, "bbot_scope_report_distance", 0), minimum=0, maximum=MAX_BBOT_SCOPE_DISTANCE, default=0),
        "dns.threads": _bounded_int(getattr(settings, "bbot_dns_threads", 10), minimum=1, maximum=MAX_BBOT_DNS_THREADS, default=10),
        "dns.brute_threads": _bounded_int(getattr(settings, "bbot_dns_brute_threads", 100), minimum=1, maximum=MAX_BBOT_DNS_BRUTE_THREADS, default=100),
        "dns.timeout": _bounded_int(getattr(settings, "bbot_dns_timeout_seconds", 5), minimum=1, maximum=MAX_BBOT_DNS_TIMEOUT_SECONDS, default=5),
        "dns.retries": _bounded_int(getattr(settings, "bbot_dns_retries", 1), minimum=0, maximum=MAX_BBOT_DNS_RETRIES, default=1),
        "web.http_timeout": _bounded_int(getattr(settings, "bbot_web_http_timeout_seconds", 10), minimum=1, maximum=MAX_BBOT_WEB_TIMEOUT_SECONDS, default=10),
        "web.http_retries": _bounded_int(getattr(settings, "bbot_web_http_retries", 1), minimum=0, maximum=MAX_BBOT_WEB_RETRIES, default=1),
        "web.spider_distance": _bounded_int(getattr(settings, "bbot_web_spider_distance", 0), minimum=0, maximum=MAX_BBOT_WEB_SPIDER_DISTANCE, default=0),
        "web.spider_depth": _bounded_int(getattr(settings, "bbot_web_spider_depth", 1), minimum=0, maximum=MAX_BBOT_WEB_SPIDER_DEPTH, default=1),
        "web.spider_links_per_page": _bounded_int(getattr(settings, "bbot_web_spider_links_per_page", 10), minimum=1, maximum=MAX_BBOT_WEB_LINKS_PER_PAGE, default=10),
    }
    args = ["-c"]
    args.extend(f"{key}={value}" for key, value in config_values.items())
    return args


def _normalize_bbot_values(
    raw_value: object,
    *,
    field_name: str,
    allowed: set[str],
    aggressive: set[str] | None = None,
    default: str = "",
) -> list[str]:
    raw = str(raw_value if raw_value not in (None, "") else default).strip()
    if not raw:
        return []
    values: list[str] = []
    seen: set[str] = set()
    aggressive = aggressive or set()
    for part in raw.split(","):
        cleaned = part.strip()
        if not cleaned:
            continue
        normalized = cleaned.lower()
        if any(character in cleaned for character in DANGEROUS_SHELL_CHARACTERS) or not SAFE_BBOT_VALUE_PATTERN.fullmatch(cleaned):
            raise ValueError(f"{field_name} contains unsupported characters.")
        if normalized in aggressive:
            raise ValueError(BBOT_UNAPPROVED_PROFILE_ERROR)
        if normalized not in allowed:
            raise ValueError(f"{field_name} contains unsupported value: {cleaned}.")
        if normalized in seen:
            continue
        seen.add(normalized)
        values.append(cleaned)
    if len(values) > 25:
        raise ValueError(f"{field_name} exceeds the bounded list size.")
    return values


def _bounded_int(value: object, *, minimum: int, maximum: int, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


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


def _start_stream_thread(pipe: object, lines: list[str], stream_name: str, max_output_bytes: int) -> threading.Thread:
    thread = threading.Thread(target=_stream_output, args=(pipe, lines, stream_name, max_output_bytes), daemon=True)
    thread.start()
    return thread


def _stream_output(pipe: object, lines: list[str], stream_name: str, max_output_bytes: int) -> None:
    if pipe is None:
        return

    current_size = 0
    truncated = False
    try:
        for line in pipe:
            cleaned_line = _strip_ansi_control(str(line).rstrip("\r\n"))
            if not truncated:
                bounded_line, line_truncated = _bounded_text(cleaned_line, max(0, max_output_bytes - current_size), label=stream_name)
                if bounded_line:
                    lines.append(bounded_line)
                    current_size += len(bounded_line.encode("utf-8", errors="ignore"))
                if line_truncated or current_size >= max_output_bytes:
                    lines.append(f"[{stream_name} truncated at {max_output_bytes} bytes]")
                    truncated = True
            logger.info("BBOT %s: %s", stream_name, cleaned_line)
    finally:
        close = getattr(pipe, "close", None)
        if close is not None:
            close()


def _join_stream_thread(thread: threading.Thread, stream_name: str) -> None:
    thread.join(timeout=5)
    if thread.is_alive():
        logger.warning("BBOT %s stream reader still running after process exit.", stream_name)


def _read_bbot_json_output(output_dir: Path, settings: object | None = None) -> tuple[str, list[str], bool]:
    json_files = sorted(
        path
        for path in output_dir.rglob("*")
        if path.is_file() and path.suffix.lower() in {".json", ".jsonl", ".ndjson"}
    )
    if not json_files:
        logger.warning("BBOT JSON output path not found under %s", output_dir)
        return "", [], False

    file_contents = []
    paths = []
    max_json_files = _bounded_int(getattr(settings, "bbot_max_json_files", 25), minimum=1, maximum=MAX_BBOT_JSON_FILES, default=25)
    max_output_bytes = _bounded_int(
        getattr(settings, "bbot_max_output_bytes", 2_000_000),
        minimum=10_000,
        maximum=MAX_BBOT_OUTPUT_BYTES,
        default=2_000_000,
    )
    total_size = 0
    truncated = len(json_files) > max_json_files
    for json_file in json_files[:max_json_files]:
        paths.append(str(json_file))
        logger.info("BBOT JSON output path exists: %s", json_file)
        try:
            content = json_file.read_text(encoding="utf-8", errors="replace").strip()
        except OSError as exc:
            logger.warning("Unable to read BBOT JSON output %s: %s", json_file, exc)
            continue
        if content:
            remaining = max_output_bytes - total_size
            bounded_content, content_truncated = _bounded_text(content, remaining, label="json")
            if bounded_content:
                file_contents.append(bounded_content)
                total_size += len(bounded_content.encode("utf-8", errors="ignore"))
            truncated = truncated or content_truncated
            if total_size >= max_output_bytes:
                truncated = True
                break

    return "\n".join(file_contents), paths, truncated


def _combine_output(stdout: str, json_output: str) -> str:
    parts = [part for part in (stdout.strip(), json_output.strip()) if part]
    return "\n".join(parts)


def _bounded_text(text: str, max_bytes: int, *, label: str) -> tuple[str, bool]:
    encoded = str(text or "").encode("utf-8", errors="ignore")
    if max_bytes <= 0:
        return "", True
    if len(encoded) <= max_bytes:
        return str(text or ""), False
    return f"{encoded[:max_bytes].decode('utf-8', errors='ignore')}\n[{label} truncated at {max_bytes} bytes]", True


def _is_truncated(text: str) -> bool:
    return "truncated at" in str(text or "")


def _strip_ansi_control(text: object) -> str:
    return ANSI_CONTROL_PATTERN.sub("", str(text or ""))
