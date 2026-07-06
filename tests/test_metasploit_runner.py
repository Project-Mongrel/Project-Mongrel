import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.core.config import Settings
from app.services.metasploit_approval import approve_metasploit_proposal, clear_metasploit_proposals, propose_metasploit_action
from app.services.findings_store import close_findings_database, configure_findings_database
from app.services.metasploit_policy import build_metasploit_action_request
from app.tools.metasploit_runner import build_metasploit_resource_commands, run_metasploit_validation


class FakeProcess:
    def __init__(self, *, stdout: str = "", stderr: str = "", returncode: int = 0, timeout: bool = False) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.timeout = timeout
        self.killed = False

    def communicate(self, timeout: int | None = None):
        if self.timeout and not self.killed:
            raise subprocess.TimeoutExpired(cmd="msfconsole", timeout=timeout or 1)
        return self.stdout, self.stderr

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


def test_metasploit_runner_uses_shell_false_and_generated_resource(tmp_path) -> None:
    request = _request()
    proposal_id = _approved(request)
    fake_process = FakeProcess(stdout="appears vulnerable", returncode=0)

    with (
        patch("app.tools.metasploit_runner.get_settings", return_value=Settings(_env_file=None, metasploit_binary="msfconsole", metasploit_timeout_seconds=120)),
        patch("app.tools.metasploit_runner.shutil.which", return_value="msfconsole"),
        patch("app.tools.metasploit_runner.subprocess.Popen", return_value=fake_process) as popen_mock,
    ):
        result = run_metasploit_validation(user_id=100, proposal_id=proposal_id, request=request, work_dir=tmp_path)

    assert result["success"] is True
    assert result["output"] == "appears vulnerable"
    assert popen_mock.call_args.args[0][0] == "msfconsole"
    assert "-r" in popen_mock.call_args.args[0]
    assert popen_mock.call_args.kwargs["shell"] is False
    resource_path = popen_mock.call_args.args[0][-1]
    assert not (tmp_path / resource_path).exists()


def test_metasploit_runner_timeout_kills_process(tmp_path) -> None:
    request = _request()
    proposal_id = _approved(request)
    fake_process = FakeProcess(stdout="partial", stderr="slow", timeout=True)

    with (
        patch("app.tools.metasploit_runner.get_settings", return_value=Settings(_env_file=None, metasploit_binary="msfconsole", metasploit_timeout_seconds=30)),
        patch("app.tools.metasploit_runner.shutil.which", return_value="msfconsole"),
        patch("app.tools.metasploit_runner.subprocess.Popen", return_value=fake_process),
    ):
        result = run_metasploit_validation(user_id=100, proposal_id=proposal_id, request=request, work_dir=tmp_path)

    assert result["success"] is False
    assert result["error_type"] == "timeout"
    assert fake_process.killed is True


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
