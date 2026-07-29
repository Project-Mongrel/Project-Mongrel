import logging
import subprocess  # nosec B404
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from app.parsers.tshark_parser import normalize_tshark_result
from app.services.metasploit_approval import get_metasploit_proposal
from app.services.tshark_approval import TSharkApprovalError, mark_tshark_capture_status, require_approved_tshark_capture
from app.tools.metasploit_runner import run_metasploit_validation
from app.tools.tshark_live_runner import build_tshark_live_capture_command, check_tshark_live_readiness
from app.tools.tshark_runner import run_tshark_offline_analysis

logger = logging.getLogger(__name__)

DEFAULT_POST_VALIDATION_TAIL_SECONDS = 3
MAX_POST_VALIDATION_TAIL_SECONDS = 10
TSHARK_CAPTURE_VALIDATION_ERROR = "TShark capture-during-validation failed."


def run_tshark_capture_during_validation(
    *,
    user_id: int,
    capture_proposal_id: str,
    capture_request: dict,
    metasploit_proposal_id: str,
    metasploit_request: dict,
    post_validation_tail_seconds: int = DEFAULT_POST_VALIDATION_TAIL_SECONDS,
    work_dir: str | Path | None = None,
) -> dict[str, object]:
    provenance = _base_provenance(
        user_id=user_id,
        capture_proposal_id=capture_proposal_id,
        capture_request=capture_request,
        metasploit_proposal_id=metasploit_proposal_id,
        metasploit_request=metasploit_request,
    )
    try:
        capture_proposal = require_approved_tshark_capture(capture_proposal_id, user_id=user_id, request=capture_request)
    except TSharkApprovalError as exc:
        return _result(False, str(exc), "approval_required", provenance=provenance)

    metasploit_proposal = get_metasploit_proposal(metasploit_proposal_id)
    if metasploit_proposal is None or metasploit_proposal.user_id != int(user_id):
        mark_tshark_capture_status(capture_proposal.id, "failed")
        return _result(False, "Metasploit validation proposal is not available for this user.", "validation_unavailable", provenance=provenance)
    if metasploit_proposal.fingerprint != str(metasploit_request.get("fingerprint") or ""):
        mark_tshark_capture_status(capture_proposal.id, "failed")
        return _result(False, "Metasploit validation details changed.", "validation_mutated", provenance=provenance)

    readiness = check_tshark_live_readiness()
    if readiness.get("ready") is not True:
        mark_tshark_capture_status(capture_proposal.id, "failed")
        return _result(False, str(readiness.get("error") or TSHARK_CAPTURE_VALIDATION_ERROR), str(readiness.get("error_type") or "not_ready"), provenance=provenance)

    tail_seconds = _bounded_tail(post_validation_tail_seconds)
    capture_path: Path | None = None
    capture_process: subprocess.Popen | None = None
    command: list[str] | None = None
    start_monotonic = time.monotonic()
    try:
        capture_path = _temporary_capture_path(work_dir)
        command = build_tshark_live_capture_command(str(readiness.get("resolved_binary") or "tshark"), capture_request, capture_path)
        provenance["pcap_artifact_path"] = str(capture_path)
        provenance["capture_started_at"] = _now()
        mark_tshark_capture_status(capture_proposal.id, "executing")
        capture_process = subprocess.Popen(  # nosec B603
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )

        provenance["validation_started_at"] = _now()
        validation_result = run_metasploit_validation(
            user_id=user_id,
            proposal_id=metasploit_proposal_id,
            request=metasploit_request,
            work_dir=work_dir,
        )
        provenance["validation_ended_at"] = _now()

        time.sleep(tail_seconds)
        _stop_capture_process(capture_process)
        provenance["capture_ended_at"] = _now()
        stdout, stderr = capture_process.communicate(timeout=5)

        offline_result = run_tshark_offline_analysis(capture_path)
        normalized = normalize_tshark_result(offline_result)
        success = bool(validation_result.get("success") is True and offline_result.get("success") is True)
        mark_tshark_capture_status(capture_proposal.id, "executed" if success else "failed")
        return {
            "source": "tshark_capture_during_validation",
            "success": success,
            "error": str(offline_result.get("error") or validation_result.get("error") or ""),
            "error_type": None if success else str(offline_result.get("error_type") or validation_result.get("error_type") or "execution_failed"),
            "elapsed_seconds": time.monotonic() - start_monotonic,
            "command": command,
            "output": "",
            "capture_stdout": str(stdout or "")[:1000],
            "validation_result": validation_result,
            "offline_result": offline_result,
            "normalized_evidence": normalized,
            "provenance": provenance,
            "post_validation_tail_seconds": tail_seconds,
        }
    except Exception as exc:
        if capture_process is not None:
            _stop_capture_process(capture_process)
            provenance["capture_ended_at"] = _now()
        mark_tshark_capture_status(capture_proposal.id, "failed")
        return _result(False, TSHARK_CAPTURE_VALIDATION_ERROR, "execution_failed", provenance=provenance, command=command, exception=str(exc)[:200])
    finally:
        if capture_path is not None:
            try:
                capture_path.unlink(missing_ok=True)
            except OSError:
                logger.warning("Unable to remove temporary TShark validation capture file: %s", capture_path)


def _stop_capture_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _temporary_capture_path(work_dir: str | Path | None) -> Path:
    directory = Path(work_dir or tempfile.gettempdir()).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(prefix="mongrel-tshark-validation-", suffix=".pcapng", dir=directory, delete=False)
    try:
        return Path(handle.name)
    finally:
        handle.close()


def _bounded_tail(value: object) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = DEFAULT_POST_VALIDATION_TAIL_SECONDS
    return max(0, min(parsed, MAX_POST_VALIDATION_TAIL_SECONDS))


def _base_provenance(*, user_id: int, capture_proposal_id: str, capture_request: dict, metasploit_proposal_id: str, metasploit_request: dict) -> dict[str, object]:
    return {
        "user_id": int(user_id),
        "capture_proposal_id": str(capture_proposal_id),
        "validation_proposal_id": str(metasploit_proposal_id),
        "target": metasploit_request.get("target"),
        "module": metasploit_request.get("module"),
        "action": metasploit_request.get("action_type"),
        "port": metasploit_request.get("port"),
        "interface": capture_request.get("interface"),
        "capture_duration_seconds": capture_request.get("duration_seconds"),
    }


def _result(success: bool, error: str, error_type: str, *, provenance: dict, command: list[str] | None = None, **extra: object) -> dict[str, object]:
    return {
        "source": "tshark_capture_during_validation",
        "success": success,
        "error": error,
        "error_type": error_type,
        "elapsed_seconds": 0,
        "command": command,
        "output": "",
        "normalized_evidence": {},
        "provenance": provenance,
        **extra,
    }


def _now() -> str:
    return datetime.now(UTC).isoformat()
