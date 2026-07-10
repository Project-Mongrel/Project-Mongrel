import logging
import re
import subprocess  # nosec B404
import tempfile
import time
from pathlib import Path

from app.core.config import get_settings
from app.parsers.tshark_parser import normalize_tshark_result
from app.services.tshark_approval import TSharkApprovalError, mark_tshark_capture_status, require_approved_tshark_capture
from app.tools.tshark_runner import TSHARK_NOT_AVAILABLE_ERROR, check_tshark_readiness, run_tshark_offline_analysis

logger = logging.getLogger(__name__)

TSHARK_LIVE_TIMEOUT_ERROR = "TShark live capture timed out."
TSHARK_PERMISSION_ERROR = "TShark live capture could not start with the current interface permissions."
_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization|cookie|password|passwd|token|secret|api[_-]?key|session)\s*[:=]\s*\S+"),
)


def run_tshark_live_capture(
    *,
    user_id: int,
    proposal_id: str,
    request: dict,
    work_dir: str | Path | None = None,
) -> dict[str, object]:
    try:
        proposal = require_approved_tshark_capture(proposal_id, user_id=user_id, request=request)
    except TSharkApprovalError as exc:
        return _live_result(request=request, success=False, error=str(exc), error_type="approval_required", elapsed_seconds=0, command=None)

    readiness = check_tshark_live_readiness()
    executable = str(readiness.get("resolved_binary") or "")
    if readiness.get("ready") is not True:
        mark_tshark_capture_status(proposal.id, "failed")
        return _live_result(request=request, success=False, error=str(readiness.get("error") or TSHARK_NOT_AVAILABLE_ERROR), error_type=str(readiness.get("error_type") or "not_ready"), elapsed_seconds=0, command=None)

    capture_path: Path | None = None
    start_time = time.monotonic()
    try:
        capture_path = _temporary_capture_path(work_dir)
        command = build_tshark_live_capture_command(executable, request, capture_path)
        mark_tshark_capture_status(proposal.id, "executing")
        timeout_seconds = int(request["duration_seconds"]) + 10
        completed = subprocess.run(  # nosec B603
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            shell=False,
            check=False,
        )
        elapsed = time.monotonic() - start_time
        raw_stderr = completed.stderr or ""
        stderr = _sanitize_live_error(raw_stderr)
        if completed.returncode != 0:
            error_type = "permission_denied" if _is_permission_error(raw_stderr) else "execution_failed"
            mark_tshark_capture_status(proposal.id, "failed")
            return _live_result(
                request=request,
                success=False,
                output="",
                error=TSHARK_PERMISSION_ERROR if error_type == "permission_denied" else (stderr or "TShark live capture failed."),
                error_type=error_type,
                returncode=completed.returncode,
                elapsed_seconds=elapsed,
                command=command,
                capture_file=str(capture_path),
            )

        offline_result = run_tshark_offline_analysis(capture_path)
        normalized = normalize_tshark_result(offline_result)
        mark_tshark_capture_status(proposal.id, "executed" if offline_result.get("success") is True else "failed")
        return _live_result(
            request=request,
            success=offline_result.get("success") is True,
            output="",
            error=str(offline_result.get("error") or ""),
            error_type=offline_result.get("error_type"),
            returncode=completed.returncode,
            elapsed_seconds=elapsed,
            command=command,
            capture_file=str(capture_path),
            offline_result=offline_result,
            normalized_evidence=normalized,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - start_time
        mark_tshark_capture_status(proposal.id, "failed")
        return _live_result(
            request=request,
            success=False,
            output="",
            error=_sanitize_live_error(exc.stderr or TSHARK_LIVE_TIMEOUT_ERROR),
            error_type="timeout",
            returncode=None,
            elapsed_seconds=elapsed,
            command=exc.cmd if isinstance(exc.cmd, list) else None,
            capture_file=str(capture_path) if capture_path else "",
        )
    except FileNotFoundError:
        elapsed = time.monotonic() - start_time
        mark_tshark_capture_status(proposal.id, "failed")
        return _live_result(request=request, success=False, error=TSHARK_NOT_AVAILABLE_ERROR, error_type="missing_binary", elapsed_seconds=elapsed, command=None, capture_file=str(capture_path) if capture_path else "")
    except OSError:
        elapsed = time.monotonic() - start_time
        mark_tshark_capture_status(proposal.id, "failed")
        return _live_result(request=request, success=False, error="TShark live capture failed.", error_type="execution_failed", elapsed_seconds=elapsed, command=None, capture_file=str(capture_path) if capture_path else "")
    finally:
        if capture_path is not None:
            try:
                capture_path.unlink(missing_ok=True)
            except OSError:
                logger.warning("Unable to remove temporary TShark live capture file: %s", capture_path)


def build_tshark_live_capture_command(executable: str, request: dict, capture_path: str | Path) -> list[str]:
    return [
        str(executable),
        "-i",
        str(request["interface"]),
        "-a",
        f"duration:{int(request['duration_seconds'])}",
        "-a",
        f"filesize:{int(request['file_size_kb'])}",
        "-c",
        str(int(request["packet_count"])),
        "-w",
        str(capture_path),
    ]


def check_tshark_live_readiness() -> dict[str, object]:
    readiness = check_tshark_readiness(run_version_check=False)
    if readiness.get("ready") is not True:
        return readiness

    allowlist = [item.strip() for item in str(get_settings().tshark_live_interface_allowlist or "").split(",") if item.strip()]
    if not allowlist:
        return {
            **readiness,
            "ready": False,
            "error": "TShark live capture interface allowlist is not configured.",
            "error_type": "missing_interface_allowlist",
            "allowed_interfaces": [],
        }
    return {**readiness, "allowed_interfaces": allowlist}


def _temporary_capture_path(work_dir: str | Path | None) -> Path:
    directory = Path(work_dir or tempfile.gettempdir()).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(prefix="mongrel-tshark-live-", suffix=".pcapng", dir=directory, delete=False)
    try:
        return Path(handle.name)
    finally:
        handle.close()


def _sanitize_live_error(text: object) -> str:
    value = str(text or "").replace("\r", "").strip()
    if _is_permission_error(value):
        return TSHARK_PERMISSION_ERROR
    for pattern in _SECRET_PATTERNS:
        value = pattern.sub(lambda match: f"{match.group(1)}=<REDACTED>", value)
    return value[:1000]


def _is_permission_error(text: str) -> bool:
    lowered = str(text or "").lower()
    return any(indicator in lowered for indicator in ("permission denied", "you don't have permission", "operation not permitted", "capabilities", "dumpcap"))


def _live_result(
    *,
    request: dict,
    success: bool,
    output: str = "",
    error: str = "",
    error_type: object,
    returncode: int | None = None,
    elapsed_seconds: float,
    command: list[str] | None,
    capture_file: str = "",
    offline_result: dict | None = None,
    normalized_evidence: dict | None = None,
) -> dict[str, object]:
    return {
        "source": "tshark_live",
        "success": success,
        "interface": request.get("interface"),
        "duration_seconds": int(request.get("duration_seconds") or 0),
        "packet_count_limit": int(request.get("packet_count") or 0),
        "file_size_kb_limit": int(request.get("file_size_kb") or 0),
        "capture_file": capture_file,
        "output": output,
        "error": error,
        "error_type": error_type,
        "returncode": returncode,
        "exit_code": returncode,
        "elapsed_seconds": elapsed_seconds,
        "command": command,
        "offline_result": offline_result or {},
        "normalized_evidence": normalized_evidence or {},
        "limitations": [
            "Live capture is bounded by approved interface, duration, packet count, and file size.",
            "Captured packets are normalized through offline TShark metadata extraction.",
            "Packet activity is not automatically malicious.",
            "A connection is not compromise.",
            "A DNS query is not exfiltration.",
            "Encrypted traffic limits visibility.",
        ],
    }
