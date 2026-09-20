import logging
import os
import re
import shutil
import tempfile
import threading
import time
from pathlib import Path

from app.core.config import get_settings
from app.services.metasploit_approval import (
    MetasploitApprovalError,
    mark_metasploit_proposal_status,
    require_approved_metasploit_action,
)
from app.services.scan_status import scan_status_from_result
from app.tools.process_lifecycle import run_scanner_process

logger = logging.getLogger(__name__)

METASPLOIT_NOT_AVAILABLE_ERROR = "Metasploit/msfconsole is not installed or configured. Set METASPLOIT_BINARY to the msfconsole path on the VPS."
METASPLOIT_TIMEOUT_ERROR = "Metasploit validation timed out."
METASPLOIT_VERSION_TIMEOUT_SECONDS = 10
_SECRET_PATTERNS = (
    re.compile(r"(?i)(password|pass|token|secret|apikey|api_key)\s*=>\s*\S+"),
    re.compile(r"(?i)(password|pass|token|secret|apikey|api_key)\s*[:=]\s*\S+"),
)
_METASPLOIT_BOOTSNAP_ENV = "DISABLE_BOOTSNAP_LOAD_PATH_CACHE"


def _metasploit_subprocess_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment[_METASPLOIT_BOOTSNAP_ENV] = "1"
    return environment


def run_metasploit_validation(
    *,
    user_id: int,
    proposal_id: str,
    request: dict,
    work_dir: str | Path | None = None,
    cancellation_event: threading.Event | None = None,
) -> dict[str, object]:
    try:
        proposal = require_approved_metasploit_action(proposal_id, user_id=user_id, request=request)
    except MetasploitApprovalError as exc:
        return _result(request=request, success=False, error=str(exc), error_type="approval_required", elapsed_seconds=0, command=None)

    if cancellation_event is not None and cancellation_event.is_set():
        mark_metasploit_proposal_status(proposal.id, "cancelled")
        return _result(
            request=request,
            success=False,
            error="Metasploit validation cancelled.",
            error_type="cancelled",
            elapsed_seconds=0,
            command=None,
        )

    settings = get_settings()
    readiness = check_metasploit_readiness(run_version_check=False)
    executable = str(readiness.get("resolved_binary") or "")
    if readiness.get("ready") is not True:
        mark_metasploit_proposal_status(proposal.id, "failed")
        return _result(request=request, success=False, error=METASPLOIT_NOT_AVAILABLE_ERROR, error_type="missing_binary", elapsed_seconds=0, command=None)

    timeout_seconds = min(int(request.get("timeout_seconds") or settings.metasploit_timeout_seconds), settings.metasploit_timeout_seconds)
    working_directory = Path(work_dir or tempfile.gettempdir()).resolve()
    working_directory.mkdir(parents=True, exist_ok=True)
    resource_path = _write_resource_file(request, working_directory)
    command = [executable, "-q", "-r", str(resource_path)]
    start_time = time.monotonic()
    mark_metasploit_proposal_status(proposal.id, "executing")
    try:
        completed = run_scanner_process(
            command,
            timeout_seconds=timeout_seconds,
            cwd=str(working_directory),
            env=_metasploit_subprocess_environment(),
            cancellation_event=cancellation_event,
        )
        elapsed = time.monotonic() - start_time
        success = completed.returncode == 0 and not completed.timed_out and not completed.cancelled
        error_type = "cancelled" if completed.cancelled else "timeout" if completed.timed_out else None if success else "execution_failed"
        result_status = scan_status_from_result(
            {
                "success": success,
                "error_type": error_type,
            }
        )
        proposal_status = "executed" if result_status == "completed" else result_status
        mark_metasploit_proposal_status(proposal.id, proposal_status)
        error = completed.stderr
        if completed.timed_out and not error:
            error = METASPLOIT_TIMEOUT_ERROR
        elif completed.cancelled and not error:
            error = "Metasploit validation cancelled."
        return _result(
            request=request,
            success=success,
            output=redact_metasploit_text(completed.stdout),
            error=redact_metasploit_text(error),
            error_type=error_type,
            returncode=completed.returncode,
            elapsed_seconds=elapsed,
            command=command,
            working_directory=working_directory,
        )
    except FileNotFoundError:
        elapsed = time.monotonic() - start_time
        mark_metasploit_proposal_status(proposal.id, "failed")
        return _result(request=request, success=False, error=METASPLOIT_NOT_AVAILABLE_ERROR, error_type="missing_binary", elapsed_seconds=elapsed, command=command, working_directory=working_directory)
    except OSError:
        elapsed = time.monotonic() - start_time
        mark_metasploit_proposal_status(proposal.id, "failed")
        return _result(request=request, success=False, error="Metasploit execution failed.", error_type="execution_failed", elapsed_seconds=elapsed, command=command, working_directory=working_directory)
    finally:
        try:
            resource_path.unlink(missing_ok=True)
        except OSError:
            logger.warning("Unable to remove generated Metasploit resource file: %s", resource_path)


def build_metasploit_resource_commands(request: dict) -> list[str]:
    module = str(request.get("module") or "")
    target = str(request.get("target") or "")
    port = int(request.get("port") or 0)
    action = str(request.get("action_type") or "")
    options = dict(request.get("options") or {})
    commands = [
        f"use {module}",
        f"set RHOSTS {target}",
        f"set RPORT {port}",
    ]
    commands.extend(f"set {key} {value}" for key, value in sorted(options.items()))
    if action == "check":
        commands.append("check")
    elif action == "auxiliary_validation":
        commands.append("run")
    elif action == "exploit_validation":
        commands.append("run -z")
    else:
        raise ValueError("Unsupported Metasploit action.")
    commands.append("exit -y")
    if len(commands) > 20:
        raise ValueError("Metasploit resource command list is too large.")
    return commands


def redact_metasploit_text(text: str) -> str:
    redacted = str(text or "")
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(lambda match: f"{match.group(1)}=<REDACTED>", redacted)
    return redacted[:20000]


def check_metasploit_readiness(*, run_version_check: bool = False) -> dict[str, object]:
    settings = get_settings()
    configured_binary = str(settings.metasploit_binary or "msfconsole").strip() or "msfconsole"
    executable = _resolve_msfconsole_executable(configured_binary)
    if executable is None:
        return {
            "ready": False,
            "error": METASPLOIT_NOT_AVAILABLE_ERROR,
            "error_type": "missing_binary",
            "configured_binary": configured_binary,
            "resolved_binary": None,
        }
    if run_version_check:
        try:
            completed = run_scanner_process(
                [executable, "--version"],
                timeout_seconds=METASPLOIT_VERSION_TIMEOUT_SECONDS,
                env=_metasploit_subprocess_environment(),
            )
        except OSError:
            return {
                "ready": False,
                "error": "Metasploit/msfconsole readiness check failed.",
                "error_type": "version_check_failed",
                "configured_binary": configured_binary,
                "resolved_binary": executable,
            }
        if completed.timed_out or completed.cancelled:
            return {
                "ready": False,
                "error": "Metasploit/msfconsole readiness check failed.",
                "error_type": "version_check_failed",
                "configured_binary": configured_binary,
                "resolved_binary": executable,
            }
        version_output = redact_metasploit_text((completed.stdout or completed.stderr or "").strip())[:300]
        if completed.returncode != 0:
            return {
                "ready": False,
                "error": "Metasploit/msfconsole readiness check failed.",
                "error_type": "version_check_failed",
                "configured_binary": configured_binary,
                "resolved_binary": executable,
                "version": version_output,
            }
        return {
            "ready": True,
            "error": "",
            "error_type": None,
            "configured_binary": configured_binary,
            "resolved_binary": executable,
            "version": version_output,
        }
    return {
        "ready": True,
        "error": "",
        "error_type": None,
        "configured_binary": configured_binary,
        "resolved_binary": executable,
    }


def _write_resource_file(request: dict, working_directory: Path) -> Path:
    commands = build_metasploit_resource_commands(request)
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".rc", prefix="mongrel-msf-", dir=working_directory, delete=False)
    with handle:
        handle.write("\n".join(commands))
        handle.write("\n")
    return Path(handle.name)


def _resolve_msfconsole_executable(configured_binary: str = "msfconsole") -> str | None:
    configured = str(configured_binary or "msfconsole").strip() or "msfconsole"
    if configured != "msfconsole":
        path = Path(configured).expanduser()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
        return None
    return shutil.which("msfconsole")


def _result(
    *,
    request: dict,
    success: bool,
    output: str = "",
    error: str = "",
    error_type: str | None,
    returncode: int | None = None,
    elapsed_seconds: float,
    command: list[str] | None,
    working_directory: Path | None = None,
) -> dict[str, object]:
    return {
        "source": "metasploit",
        "success": success,
        "module": request.get("module"),
        "action_type": request.get("action_type"),
        "target": request.get("target"),
        "port": request.get("port"),
        "risk_tier": request.get("risk_tier"),
        "expected_effect": request.get("expected_effect"),
        "output": output,
        "error": error,
        "error_type": error_type,
        "returncode": returncode,
        "exit_code": returncode,
        "elapsed_seconds": elapsed_seconds,
        "command": command,
        "working_directory": str(working_directory or Path.cwd().resolve()),
        "stdout_len": len(output or ""),
        "stderr_len": len(error or ""),
    }
