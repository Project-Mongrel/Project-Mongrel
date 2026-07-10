import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.core.config import Settings
from app.tools.tshark_runner import (
    TSHARK_FIELDS,
    build_tshark_offline_command,
    check_tshark_readiness,
    run_tshark_offline_analysis,
    validate_tshark_capture_path,
)


def _capture(tmp_path, name: str):
    path = tmp_path / name
    path.write_bytes(b"\xd4\xc3\xb2\xa1")
    return path


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["tshark"], returncode=returncode, stdout=stdout, stderr=stderr)


def test_tshark_accepts_valid_pcap_and_pcapng(tmp_path) -> None:
    pcap = _capture(tmp_path, "sample.pcap")
    pcapng = _capture(tmp_path, "sample.pcapng")

    assert validate_tshark_capture_path(pcap) == pcap.resolve()
    assert validate_tshark_capture_path(pcapng) == pcapng.resolve()


def test_tshark_rejects_unsupported_missing_directory_and_unsafe_paths(tmp_path) -> None:
    unsupported = _capture(tmp_path, "sample.txt")
    directory = tmp_path / "capture.pcap"
    directory.mkdir()

    with pytest.raises(ValueError, match="pcap"):
        validate_tshark_capture_path(unsupported)
    with pytest.raises(ValueError, match="does not exist"):
        validate_tshark_capture_path(tmp_path / "missing.pcap")
    with pytest.raises(ValueError, match="file, not a directory"):
        validate_tshark_capture_path(directory)
    with pytest.raises(ValueError, match="unsupported shell characters"):
        validate_tshark_capture_path(str(tmp_path / "safe.pcap") + ";id")


def test_tshark_runner_uses_shell_false_argument_list_and_offline_r_only(tmp_path) -> None:
    capture = _capture(tmp_path, "sample.pcap")
    settings = Settings(_env_file=None, tshark_timeout_seconds=9)

    with (
        patch("app.tools.tshark_runner.get_settings", return_value=settings),
        patch("app.tools.tshark_runner.shutil.which", return_value="tshark"),
        patch("app.tools.tshark_runner.subprocess.run", return_value=_completed(stdout="")) as run_mock,
    ):
        result = run_tshark_offline_analysis(capture)

    command = run_mock.call_args.args[0]
    assert isinstance(command, list)
    assert command[0] == "tshark"
    assert "-r" in command
    assert str(capture.resolve()) in command
    assert "-i" not in command
    assert run_mock.call_args.kwargs["shell"] is False
    assert run_mock.call_args.kwargs["timeout"] == 9
    assert result["success"] is True


def test_tshark_command_requests_only_metadata_fields(tmp_path) -> None:
    capture = _capture(tmp_path, "sample.pcapng")
    command = build_tshark_offline_command("tshark", capture)
    joined = " ".join(command).lower()

    assert "-r" in command
    assert "-i" not in command
    assert "-T" in command
    assert all(field in command for field in TSHARK_FIELDS)
    forbidden = ("http.authorization", "http.cookie", "http.file_data", "data.data", "tcp.payload", "udp.payload")
    assert not any(field in joined for field in forbidden)


def test_tshark_timeout_and_oversized_output_are_bounded(tmp_path) -> None:
    capture = _capture(tmp_path, "sample.pcap")
    settings = Settings(_env_file=None, tshark_timeout_seconds=1, tshark_max_output_bytes=10)
    timeout = subprocess.TimeoutExpired(cmd="tshark", timeout=1)
    timeout.stdout = "x" * 40
    timeout.stderr = "slow"

    with (
        patch("app.tools.tshark_runner.get_settings", return_value=settings),
        patch("app.tools.tshark_runner.shutil.which", return_value="tshark"),
        patch("app.tools.tshark_runner.subprocess.run", side_effect=timeout),
    ):
        result = run_tshark_offline_analysis(capture)

    assert result["success"] is False
    assert result["error_type"] == "timeout"
    assert result["output_truncated"] is True
    assert len(result["output"]) <= 10


def test_tshark_readiness_success_failure_and_version_check(tmp_path) -> None:
    missing = tmp_path / "missing-tshark"
    binary = tmp_path / "tshark"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")

    with patch("app.tools.tshark_runner.get_settings", return_value=Settings(_env_file=None, tshark_binary=str(missing))):
        missing_result = check_tshark_readiness()

    with (
        patch("app.tools.tshark_runner.get_settings", return_value=Settings(_env_file=None, tshark_binary=str(binary))),
        patch("app.tools.tshark_runner.os.access", return_value=True),
        patch("app.tools.tshark_runner.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="TShark 4.2.2", stderr="")) as run_mock,
    ):
        ready = check_tshark_readiness(run_version_check=True)

    assert missing_result["ready"] is False
    assert missing_result["error_type"] == "missing_binary"
    assert ready["ready"] is True
    assert ready["version"] == "TShark 4.2.2"
    run_mock.assert_called_once_with(
        [str(binary), "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        shell=False,
        check=False,
    )
