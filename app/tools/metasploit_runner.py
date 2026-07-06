import logging
import re
import shutil
import subprocess  # nosec B404
import tempfile
import time
from pathlib import Path

from app.core.config import get_settings
from app.services.metasploit_approval import (
    MetasploitApprovalError,
    mark_metasploit_proposal_status,
    require_approved_metasploit_action,
)

logger = logging.getLogger(__name__)

METASPLOIT_NOT_AVAILABLE_ERROR = "msfconsole executable was not found."
METASPLOIT_TIMEOUT_ERROR = "Metasploit validation timed out."
_SECRET_PATTERNS = (
    re.compile(r"(?i)(password|pass|token|secret|apikey|api_key)\s*=>\s*\S+"),
    re.compile(r"(?i)(password|pass|token|secret|apikey|api_key)\s*[:=]\s*\S+"),
)


def run_metasploit_validation(
    *,
    user_id: int,
    proposal_id: str,
    request: dict,
    work_dir: str | Path | None = None,
) -> dict[str, object]:
    try:
        proposal = require_approved_metasploit_action(proposal_id, user_id=user_id, request=request)
    except MetasploitApprovalError as exc:
        return _result(request=request, success=False, error=str(exc), error_type="approval_required", elapsed_seconds=0, command=None)

    settings = get_settings()
    executable = _resolve_msfconsole_executable(settings.metasploit_binary)
    if executable is None:
        return _result(request=request, success=False, error=METASPLOIT_NOT_AVAILABLE_ERROR, error_type="missing_binary", elapsed_seconds=0, command=None)

    timeout_seconds = min(int(request.get("timeout_seconds") or settings.metasploit_timeout_seconds), settings.metasploit_timeout_seconds)
    working_directory = Path(work_dir or tempfile.gettempdir()).resolve()
    working_directory.mkdir(parents=True, exist_ok=True)
    resource_path = _write_resource_file(request, working_directory)
    command = [executable, "-q", "-r", str(resource_path)]
    start_time = time.monotonic()
    mark_metasploit_proposal_status(proposal.id, "executing")
    try:
        process = subprocess.Popen(  # nosec B603
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(working_directory),
            shell=False,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout_seconds)
            elapsed = time.monotonic() - start_time
            success = process.returncode == 0
            mark_metasploit_proposal_status(proposal.id, "executed" if success else "failed")
            return _result(
                request=request,
                success=success,
                output=redact_metasploit_text(stdout or ""),
                error=redact_metasploit_text(stderr or ""),
                error_type=None if success else "execution_failed",
                returncode=process.returncode,
                elapsed_seconds=elapsed,
                command=command,
                working_directory=working_directory,
            )
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            elapsed = time.monotonic() - start_time
            mark_metasploit_proposal_status(proposal.id, "failed")
            return _result(
                request=request,
                success=False,
                output=redact_metasploit_text(stdout or ""),
                error=redact_metasploit_text(stderr or METASPLOIT_TIMEOUT_ERROR),
                error_type="timeout",
                returncode=process.returncode,
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


def _write_resource_file(request: dict, working_directory: Path) -> Path:
    commands = build_metasploit_resource_commands(request)
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".rc", prefix="mongrel-msf-", dir=working_directory, delete=False)
    with handle:
        handle.write("\n".join(commands))
        handle.write("\n")
    return Path(handle.name)


def _resolve_msfconsole_executable(configured_binary: str = "msfconsole") -> str | None:
    if configured_binary and configured_binary != "msfconsole":
        return configured_binary
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
