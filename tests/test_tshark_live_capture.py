import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.core.config import Settings
from app.services.tshark_approval import (
    TSharkApprovalError,
    approve_tshark_capture,
    clear_tshark_capture_proposals,
    get_tshark_capture_proposal,
    propose_tshark_capture,
    require_approved_tshark_capture,
)
from app.services.tshark_policy import build_tshark_capture_request
from app.tools.tshark_live_runner import build_tshark_live_capture_command, check_tshark_live_readiness, run_tshark_live_capture


@pytest.fixture(autouse=True)
def clear_tshark_capture_store() -> None:
    clear_tshark_capture_proposals()
    yield
    clear_tshark_capture_proposals()


def _settings() -> Settings:
    return Settings(
        _env_file=None,
        tshark_live_interface_allowlist="eth0,lo",
        tshark_live_max_duration_seconds=30,
        tshark_live_max_packet_count=500,
        tshark_live_max_file_size_kb=4096,
    )


def _request(interface: str = "eth0") -> dict:
    with patch("app.services.tshark_policy.get_settings", return_value=_settings()):
        return build_tshark_capture_request(interface=interface, duration_seconds=5, packet_count=25, file_size_kb=512)


def _approved(request: dict, user_id: int = 100) -> str:
    proposal = propose_tshark_capture(user_id, request)
    approve_tshark_capture(proposal.id, user_id=user_id)
    return proposal.id


def test_tshark_live_policy_accepts_allowlisted_interface_and_rejects_others() -> None:
    request = _request("eth0")

    assert request["interface"] == "eth0"
    assert request["duration_seconds"] == 5
    assert request["packet_count"] == 25
    assert request["file_size_kb"] == 512

    with patch("app.services.tshark_policy.get_settings", return_value=_settings()):
        with pytest.raises(ValueError, match="allowlisted"):
            build_tshark_capture_request(interface="wlan0", duration_seconds=5, packet_count=25)
        with pytest.raises(ValueError, match="Malformed"):
            build_tshark_capture_request(interface="eth0;id", duration_seconds=5, packet_count=25)
        with pytest.raises(ValueError, match="duration"):
            build_tshark_capture_request(interface="eth0", duration_seconds=999, packet_count=25)


def test_tshark_live_approval_exact_binding_wrong_user_expired_and_mutated_denied() -> None:
    request = _request()
    proposal = propose_tshark_capture(100, request)

    with pytest.raises(TSharkApprovalError):
        require_approved_tshark_capture(proposal.id, user_id=100, request=request)
    with pytest.raises(TSharkApprovalError):
        approve_tshark_capture(proposal.id, user_id=101)
    with pytest.raises(TSharkApprovalError):
        approve_tshark_capture(proposal.id, user_id=100, actor="ai")

    approved = approve_tshark_capture(proposal.id, user_id=100)
    with pytest.raises(TSharkApprovalError):
        require_approved_tshark_capture(approved.id, user_id=101, request=request)
    with pytest.raises(TSharkApprovalError):
        require_approved_tshark_capture(approved.id, user_id=100, request={**request, "packet_count": 26})

    from app.services import tshark_approval

    tshark_approval._proposals[approved.id] = replace(approved, expires_at=datetime.now(UTC) - timedelta(seconds=1))
    with pytest.raises(TSharkApprovalError):
        require_approved_tshark_capture(approved.id, user_id=100, request=request)
    assert get_tshark_capture_proposal(approved.id).status == "expired"


def test_tshark_live_command_is_bounded_argument_list(tmp_path) -> None:
    request = _request()
    capture_path = tmp_path / "capture.pcapng"
    command = build_tshark_live_capture_command("tshark", request, capture_path)

    assert command == [
        "tshark",
        "-i",
        "eth0",
        "-a",
        "duration:5",
        "-a",
        "filesize:512",
        "-c",
        "25",
        "-w",
        str(capture_path),
    ]
    assert "duration:0" not in command
    assert "-f" not in command
    assert "-Y" not in command


def test_tshark_live_runner_reuses_offline_parser_and_cleans_temp_file(tmp_path) -> None:
    request = _request()
    proposal_id = _approved(request)
    seen_capture_paths = []
    normalized = {"source": "tshark", "packet_count": 1, "evidence_limitations": ["A connection is not compromise."]}

    def fake_subprocess(command, **kwargs):
        assert kwargs["shell"] is False
        assert kwargs["timeout"] == 15
        assert "-i" in command
        assert "-w" in command
        capture_path = command[command.index("-w") + 1]
        seen_capture_paths.append(capture_path)
        assert capture_path.startswith(str(tmp_path))
        assert capture_path.endswith(".pcapng")
        return subprocess.CompletedProcess(command, 0, stdout="packet bytes not rendered", stderr="")

    with (
        patch("app.tools.tshark_live_runner.check_tshark_live_readiness", return_value={"ready": True, "resolved_binary": "tshark"}),
        patch("app.tools.tshark_live_runner.subprocess.run", side_effect=fake_subprocess) as run_mock,
        patch("app.tools.tshark_live_runner.run_tshark_offline_analysis", return_value={"success": True, "output": "structured"}) as offline_mock,
        patch("app.tools.tshark_live_runner.normalize_tshark_result", return_value=normalized) as parser_mock,
    ):
        result = run_tshark_live_capture(user_id=100, proposal_id=proposal_id, request=request, work_dir=tmp_path)

    assert result["success"] is True
    assert result["interface"] == "eth0"
    assert result["duration_seconds"] == 5
    assert result["packet_count_limit"] == 25
    assert result["file_size_kb_limit"] == 512
    assert result["normalized_evidence"] == normalized
    assert result["output"] == ""
    assert "packet bytes not rendered" not in str(result)
    assert seen_capture_paths and not any(__import__("pathlib").Path(path).exists() for path in seen_capture_paths)
    offline_mock.assert_called_once()
    parser_mock.assert_called_once_with({"success": True, "output": "structured"})
    assert run_mock.call_args.args[0] == result["command"]
    assert get_tshark_capture_proposal(proposal_id).status == "executed"


def test_tshark_live_runner_blocks_unapproved_wrong_user_and_mutated_request() -> None:
    request = _request()
    proposal_id = propose_tshark_capture(100, request).id

    result = run_tshark_live_capture(user_id=100, proposal_id=proposal_id, request=request)
    assert result["success"] is False
    assert result["error_type"] == "approval_required"

    approved_id = _approved(request)
    wrong_user = run_tshark_live_capture(user_id=101, proposal_id=approved_id, request=request)
    mutated = run_tshark_live_capture(user_id=100, proposal_id=approved_id, request={**request, "duration_seconds": 6})
    assert wrong_user["success"] is False
    assert wrong_user["error_type"] == "approval_required"
    assert mutated["success"] is False
    assert mutated["error_type"] == "approval_required"


def test_tshark_live_timeout_and_permission_failure_are_sanitized_and_cleaned(tmp_path) -> None:
    request = _request()
    timeout_id = _approved(request)
    timeout = subprocess.TimeoutExpired(cmd=["tshark", "-i", "eth0"], timeout=15)
    timeout.stderr = "cookie=secret"

    with (
        patch("app.tools.tshark_live_runner.check_tshark_live_readiness", return_value={"ready": True, "resolved_binary": "tshark"}),
        patch("app.tools.tshark_live_runner.subprocess.run", side_effect=timeout),
    ):
        timeout_result = run_tshark_live_capture(user_id=100, proposal_id=timeout_id, request=request, work_dir=tmp_path)

    assert timeout_result["success"] is False
    assert timeout_result["error_type"] == "timeout"
    assert "cookie=<REDACTED>" in timeout_result["error"]
    assert "cookie=secret" not in str(timeout_result)
    assert not list(tmp_path.glob("mongrel-tshark-live-*.pcapng"))

    permission_id = _approved(request)
    with (
        patch("app.tools.tshark_live_runner.check_tshark_live_readiness", return_value={"ready": True, "resolved_binary": "tshark"}),
        patch("app.tools.tshark_live_runner.subprocess.run", return_value=subprocess.CompletedProcess(["tshark"], 1, stdout="", stderr="dumpcap: Permission denied")),
    ):
        permission_result = run_tshark_live_capture(user_id=100, proposal_id=permission_id, request=request, work_dir=tmp_path)

    assert permission_result["success"] is False
    assert permission_result["error_type"] == "permission_denied"
    assert permission_result["error"] == "TShark live capture could not start with the current interface permissions."
    assert "dumpcap" not in permission_result["error"]
    assert not list(tmp_path.glob("mongrel-tshark-live-*.pcapng"))


def test_tshark_live_readiness_requires_binary_and_interface_allowlist() -> None:
    with patch("app.tools.tshark_live_runner.check_tshark_readiness", return_value={"ready": False, "error_type": "missing_binary", "error": "missing"}):
        missing = check_tshark_live_readiness()

    with (
        patch("app.tools.tshark_live_runner.check_tshark_readiness", return_value={"ready": True, "resolved_binary": "tshark"}),
        patch("app.tools.tshark_live_runner.get_settings", return_value=Settings(_env_file=None, tshark_live_interface_allowlist="")),
    ):
        no_allowlist = check_tshark_live_readiness()

    with (
        patch("app.tools.tshark_live_runner.check_tshark_readiness", return_value={"ready": True, "resolved_binary": "tshark"}),
        patch("app.tools.tshark_live_runner.get_settings", return_value=_settings()),
    ):
        ready = check_tshark_live_readiness()

    assert missing["ready"] is False
    assert missing["error_type"] == "missing_binary"
    assert no_allowlist["ready"] is False
    assert no_allowlist["error_type"] == "missing_interface_allowlist"
    assert ready["ready"] is True
    assert ready["allowed_interfaces"] == ["eth0", "lo"]
