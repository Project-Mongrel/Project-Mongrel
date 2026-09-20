import os
import subprocess
import threading
from unittest.mock import ANY, patch

import pytest

from app.core.config import Settings
from app.services.metasploit_approval import approve_metasploit_proposal, clear_metasploit_proposals, get_metasploit_proposal, propose_metasploit_action
from app.services.findings_store import close_findings_database, configure_findings_database
from app.services.metasploit_policy import build_metasploit_action_request
from app.tools.metasploit_runner import METASPLOIT_NOT_AVAILABLE_ERROR, build_metasploit_resource_commands, check_metasploit_readiness, run_metasploit_validation
from app.tools.process_lifecycle import ScannerExecution


class FakeProcess:
    def __init__(self, *, stdout: str = "", stderr: str = "", returncode: int = 0, timeout: bool = False) -> None:
        self.output = stdout
        self.error = stderr
        self.stdout = None
        self.stderr = None
        self.stdin = None
        self.final_returncode = returncode
        self.returncode = None
        self.timeout = timeout
        self.terminated = False
        self.killed = False

    def communicate(self, timeout: int | None = None):
        if self.timeout and not self.terminated and not self.killed:
            raise subprocess.TimeoutExpired(cmd="msfconsole", timeout=timeout or 1)
        if self.returncode is None:
            self.returncode = self.final_returncode
        return self.output, self.error

    def poll(self):
        return self.returncode

    def wait(self, timeout: float | None = None):
        if self.returncode is None:
            self.returncode = self.final_returncode
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


@pytest.fixture(autouse=True)
def isolated_store(tmp_path) -> None:
    configure_findings_database(tmp_path / "mongrel.db")
    clear_metasploit_proposals()
    yield
    clear_metasploit_proposals()
    close_findings_database()
    configure_findings_database(None)


def _request(action_type: str = "auxiliary_validation") -> dict:
    return build_metasploit_action_request(
        module="auxiliary/scanner/http/http_version",
        action_type=action_type,
        target="example.com",
        port=80,
        options={"TARGETURI": "/"},
        timeout_seconds=60,
    )


def _approved(request: dict) -> str:
    proposal = propose_metasploit_action(100, request)
    approve_metasploit_proposal(proposal.id, user_id=100)
    return proposal.id


def test_metasploit_runner_requires_approval() -> None:
    request = _request()

    result = run_metasploit_validation(user_id=100, proposal_id="missing", request=request)

    assert result["success"] is False
    assert result["error_type"] == "approval_required"


def test_metasploit_pre_spawn_cancellation_does_not_start_process() -> None:
    request = _request()
    proposal_id = _approved(request)
    cancellation_event = threading.Event()
    cancellation_event.set()
    with patch("app.tools.metasploit_runner.run_scanner_process") as run_mock:
        result = run_metasploit_validation(
            user_id=100,
            proposal_id=proposal_id,
            request=request,
            cancellation_event=cancellation_event,
        )

    assert result["error_type"] == "cancelled"
    assert get_metasploit_proposal(proposal_id).execution_state == "cancelled"
    run_mock.assert_not_called()


def test_metasploit_runner_uses_shell_false_and_generated_resource(tmp_path) -> None:
    request = _request()
    proposal_id = _approved(request)
    fake_process = FakeProcess(stdout="appears vulnerable", returncode=0)

    with (
        patch.dict(os.environ, {"MONGREL_INHERITED_ENV_TEST": "retained"}),
        patch("app.tools.metasploit_runner.get_settings", return_value=Settings(_env_file=None, metasploit_binary="msfconsole", metasploit_timeout_seconds=120)),
        patch("app.tools.metasploit_runner.shutil.which", return_value="msfconsole"),
        patch("app.tools.process_lifecycle.subprocess.Popen", return_value=fake_process) as popen_mock,
    ):
        result = run_metasploit_validation(user_id=100, proposal_id=proposal_id, request=request, work_dir=tmp_path)

    assert result["success"] is True
    assert result["output"] == "appears vulnerable"
    assert popen_mock.call_args.args[0][0] == "msfconsole"
    assert "-r" in popen_mock.call_args.args[0]
    assert popen_mock.call_args.kwargs["shell"] is False
    assert popen_mock.call_args.kwargs["start_new_session"] is True
    assert popen_mock.call_args.kwargs["env"]["DISABLE_BOOTSNAP_LOAD_PATH_CACHE"] == "1"
    assert popen_mock.call_args.kwargs["env"]["MONGREL_INHERITED_ENV_TEST"] == "retained"
    resource_path = popen_mock.call_args.args[0][-1]
    assert not (tmp_path / resource_path).exists()


def test_metasploit_runner_timeout_kills_process(tmp_path) -> None:
    request = _request()
    proposal_id = _approved(request)
    fake_process = FakeProcess(stdout="partial", stderr="slow", timeout=True)

    with (
        patch("app.tools.metasploit_runner.get_settings", return_value=Settings(_env_file=None, metasploit_binary="msfconsole", metasploit_timeout_seconds=0)),
        patch("app.tools.metasploit_runner.shutil.which", return_value="msfconsole"),
        patch("app.tools.process_lifecycle.subprocess.Popen", return_value=fake_process),
    ):
        result = run_metasploit_validation(user_id=100, proposal_id=proposal_id, request=request, work_dir=tmp_path)

    assert result["success"] is False
    assert result["error_type"] == "timeout"
    assert get_metasploit_proposal(proposal_id).execution_state == "timed_out"
    assert fake_process.terminated is True


def test_metasploit_bounded_command_generation() -> None:
    request = _request()
    commands = build_metasploit_resource_commands(request)

    assert commands == [
        "use auxiliary/scanner/http/http_version",
        "set RHOSTS example.com",
        "set RPORT 80",
        "set TARGETURI /",
        "run",
        "exit -y",
    ]
    assert len(commands) <= 20
    assert not any("sessions" in command for command in commands)


def test_metasploit_runner_denies_mutated_request_after_approval() -> None:
    request = _request()
    proposal_id = _approved(request)
    mutated = {**request, "target": "other.example"}

    result = run_metasploit_validation(user_id=100, proposal_id=proposal_id, request=mutated)

    assert result["success"] is False
    assert result["error_type"] == "approval_required"


def test_metasploit_missing_binary_returns_clean_error_and_blocks_execution(tmp_path) -> None:
    request = _request()
    proposal_id = _approved(request)
    missing_binary = tmp_path / "missing-msfconsole"

    with (
        patch("app.tools.metasploit_runner.get_settings", return_value=Settings(_env_file=None, metasploit_binary=str(missing_binary), metasploit_timeout_seconds=120)),
        patch("app.tools.process_lifecycle.subprocess.Popen") as popen_mock,
    ):
        result = run_metasploit_validation(user_id=100, proposal_id=proposal_id, request=request, work_dir=tmp_path)

    popen_mock.assert_not_called()
    assert result["success"] is False
    assert result["error_type"] == "missing_binary"
    assert result["error"] == METASPLOIT_NOT_AVAILABLE_ERROR
    assert "Traceback" not in result["error"]


def test_metasploit_readiness_honors_configured_binary_path_and_does_not_execute_modules(tmp_path) -> None:
    binary = tmp_path / "msfconsole"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")

    with (
        patch("app.tools.metasploit_runner.get_settings", return_value=Settings(_env_file=None, metasploit_binary=str(binary), metasploit_timeout_seconds=120)),
        patch("app.tools.metasploit_runner.os.access", return_value=True),
        patch("app.tools.metasploit_runner.run_scanner_process") as run_mock,
        patch("app.tools.process_lifecycle.subprocess.Popen") as popen_mock,
    ):
        readiness = check_metasploit_readiness(run_version_check=False)

    assert readiness["ready"] is True
    assert readiness["resolved_binary"] == str(binary)
    run_mock.assert_not_called()
    popen_mock.assert_not_called()


def test_metasploit_readiness_version_check_is_safe_and_bounded(tmp_path) -> None:
    binary = tmp_path / "msfconsole"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    completed = ScannerExecution(returncode=0, stdout="Framework Version 6.4.0", stderr="")

    with (
        patch("app.tools.metasploit_runner.get_settings", return_value=Settings(_env_file=None, metasploit_binary=str(binary), metasploit_timeout_seconds=120)),
        patch("app.tools.metasploit_runner.os.access", return_value=True),
        patch("app.tools.metasploit_runner.run_scanner_process", return_value=completed) as run_mock,
        patch("app.tools.process_lifecycle.subprocess.Popen") as popen_mock,
    ):
        readiness = check_metasploit_readiness(run_version_check=True)

    assert readiness["ready"] is True
    assert readiness["version"] == "Framework Version 6.4.0"
    run_mock.assert_called_once_with(
        [str(binary), "--version"],
        timeout_seconds=10,
        env=ANY,
    )
    assert run_mock.call_args.kwargs["env"]["DISABLE_BOOTSNAP_LOAD_PATH_CACHE"] == "1"
    popen_mock.assert_not_called()
