import os
import re
import shutil
import subprocess  # nosec B404
import time
from pathlib import Path

from app.core.config import get_settings
from app.tools.nmap_runner import DANGEROUS_SHELL_CHARACTERS

TSHARK_NOT_AVAILABLE_ERROR = "TShark is not installed or configured. Set TSHARK_BINARY to the tshark path on the VPS."
TSHARK_TIMEOUT_ERROR = "TShark offline PCAP analysis timed out."
TSHARK_VERSION_TIMEOUT_SECONDS = 10
SUPPORTED_CAPTURE_SUFFIXES = frozenset({".pcap", ".pcapng"})
TSHARK_FIELDS = (
    "frame.time_epoch",
    "frame.len",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "dns.qry.name",
    "dns.resp.name",
    "dns.a",
    "dns.aaaa",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.response.code",
    "tls.handshake.extensions_server_name",
    "tls.handshake.version",
)
_CONTROL_CHARACTER_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def run_tshark_offline_analysis(capture_file: str | Path) -> dict[str, object]:
    try:
        capture_path = validate_tshark_capture_path(capture_file)
    except ValueError as exc:
        return _result(success=False, capture_file=str(capture_file or ""), error=str(exc), error_type="invalid_capture", elapsed_seconds=0, command=None)

    settings = get_settings()
    readiness = check_tshark_readiness(run_version_check=False)
    executable = str(readiness.get("resolved_binary") or "")
    if readiness.get("ready") is not True:
        return _result(success=False, capture_file=str(capture_path), error=TSHARK_NOT_AVAILABLE_ERROR, error_type="missing_binary", elapsed_seconds=0, command=None)

    command = build_tshark_offline_command(executable, capture_path)
    start_time = time.monotonic()
    try:
        completed = subprocess.run(  # nosec B603
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=int(settings.tshark_timeout_seconds),
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - start_time
        output, output_truncated = _bounded_text(exc.stdout or "", int(settings.tshark_max_output_bytes))
        error, error_truncated = _bounded_text(exc.stderr or TSHARK_TIMEOUT_ERROR, int(settings.tshark_max_output_bytes))
        return _result(
            success=False,
            capture_file=str(capture_path),
            output=output,
            error=error,
            error_type="timeout",
            returncode=None,
            elapsed_seconds=elapsed,
            command=command,
            output_truncated=output_truncated,
            error_truncated=error_truncated,
        )
    except FileNotFoundError:
        elapsed = time.monotonic() - start_time
        return _result(success=False, capture_file=str(capture_path), error=TSHARK_NOT_AVAILABLE_ERROR, error_type="missing_binary", elapsed_seconds=elapsed, command=command)
    except OSError:
        elapsed = time.monotonic() - start_time
        return _result(success=False, capture_file=str(capture_path), error="TShark offline PCAP analysis failed.", error_type="execution_failed", elapsed_seconds=elapsed, command=command)

    elapsed = time.monotonic() - start_time
    output, output_truncated = _bounded_text(completed.stdout or "", int(settings.tshark_max_output_bytes))
    error, error_truncated = _bounded_text(completed.stderr or "", int(settings.tshark_max_output_bytes))
    return _result(
        success=completed.returncode == 0,
        capture_file=str(capture_path),
        output=output,
        error=error,
        error_type=None if completed.returncode == 0 else "execution_failed",
        returncode=completed.returncode,
        elapsed_seconds=elapsed,
        command=command,
        output_truncated=output_truncated,
        error_truncated=error_truncated,
    )


def validate_tshark_capture_path(capture_file: str | Path) -> Path:
    raw = str(capture_file or "").strip()
    if not raw:
        raise ValueError("TShark capture file is required.")
    if "\x00" in raw or any(character in raw for character in DANGEROUS_SHELL_CHARACTERS):
        raise ValueError("TShark capture path contains unsupported shell characters.")
    path = Path(raw).expanduser()
    if path.suffix.lower() not in SUPPORTED_CAPTURE_SUFFIXES:
        raise ValueError("TShark capture file must be a .pcap or .pcapng file.")
    resolved = path.resolve()
    if not resolved.exists():
        raise ValueError("TShark capture file does not exist.")
    if resolved.is_dir():
        raise ValueError("TShark capture path must be a file, not a directory.")
    if not resolved.is_file():
        raise ValueError("TShark capture path must be a regular file.")
    return resolved


def build_tshark_offline_command(executable: str, capture_file: str | Path) -> list[str]:
    capture_path = validate_tshark_capture_path(capture_file)
    command = [
        str(executable),
        "-r",
        str(capture_path),
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
    ]
    for field in TSHARK_FIELDS:
        command.extend(["-e", field])
    return command


def check_tshark_readiness(*, run_version_check: bool = False) -> dict[str, object]:
    settings = get_settings()
    configured_binary = str(settings.tshark_binary or "tshark").strip() or "tshark"
    executable = _resolve_tshark_executable(configured_binary)
    if executable is None:
        return {
            "ready": False,
            "error": TSHARK_NOT_AVAILABLE_ERROR,
            "error_type": "missing_binary",
            "configured_binary": configured_binary,
            "resolved_binary": None,
        }
    if not run_version_check:
        return {
            "ready": True,
            "error": "",
            "error_type": None,
            "configured_binary": configured_binary,
            "resolved_binary": executable,
        }
    try:
        completed = subprocess.run(  # nosec B603
            [executable, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=TSHARK_VERSION_TIMEOUT_SECONDS,
            shell=False,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {
            "ready": False,
            "error": "TShark readiness check failed.",
            "error_type": "version_check_failed",
            "configured_binary": configured_binary,
            "resolved_binary": executable,
        }
    version = _bounded_text((completed.stdout or completed.stderr or "").strip(), 500)[0]
    if completed.returncode != 0:
        return {
            "ready": False,
            "error": "TShark readiness check failed.",
            "error_type": "version_check_failed",
            "configured_binary": configured_binary,
            "resolved_binary": executable,
            "version": version,
        }
    return {
        "ready": True,
        "error": "",
        "error_type": None,
        "configured_binary": configured_binary,
        "resolved_binary": executable,
        "version": version,
    }


def _resolve_tshark_executable(configured_binary: str = "tshark") -> str | None:
    configured = str(configured_binary or "tshark").strip() or "tshark"
    if configured != "tshark":
        path = Path(configured).expanduser()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
        return None
    return shutil.which("tshark")


def _bounded_text(text: object, limit: int) -> tuple[str, bool]:
    value = _CONTROL_CHARACTER_PATTERN.sub("", str(text or "").replace("\r", ""))
    if len(value.encode("utf-8", errors="ignore")) <= limit:
        return value, False
    encoded = value.encode("utf-8", errors="ignore")[: max(0, limit)]
    return encoded.decode("utf-8", errors="ignore"), True


def _result(
    *,
    success: bool,
    capture_file: str,
    output: str = "",
    error: str = "",
    error_type: str | None,
    returncode: int | None = None,
    elapsed_seconds: float,
    command: list[str] | None,
    output_truncated: bool = False,
    error_truncated: bool = False,
) -> dict[str, object]:
    return {
        "source": "tshark",
        "success": success,
        "capture_file": capture_file,
        "output": output,
        "error": error,
        "error_type": error_type,
        "returncode": returncode,
        "exit_code": returncode,
        "elapsed_seconds": elapsed_seconds,
        "command": command,
        "output_truncated": output_truncated,
        "error_truncated": error_truncated,
        "stdout_len": len(output or ""),
        "stderr_len": len(error or ""),
    }
