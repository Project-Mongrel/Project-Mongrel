import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from app.tools import bbot_runner
from app.tools.bbot_runner import BBOT_TIMEOUT_SECONDS, is_bbot_available, run_bbot_scan


def test_is_bbot_available_true() -> None:
    with patch("app.tools.bbot_runner.shutil.which", return_value="C:\\Tools\\bbot.exe"):
        assert is_bbot_available() is True


def test_is_bbot_available_false() -> None:
    with patch("app.tools.bbot_runner.shutil.which", return_value=None):
        assert is_bbot_available() is False


def test_empty_target_rejected() -> None:
    with pytest.raises(ValueError, match="cannot be empty"):
        run_bbot_scan("   ")


@pytest.mark.parametrize("target", ["example.com;whoami", "example.com && whoami", "example.com|whoami"])
def test_dangerous_shell_characters_rejected(target: str) -> None:
    with pytest.raises(ValueError, match="shell characters"):
        run_bbot_scan(target)


def test_bbot_subprocess_called_with_list_args_and_shell_false(tmp_path: Path) -> None:
    completed_process = Mock(returncode=0, stdout="bbot output", stderr="")

    with (
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.subprocess.run", return_value=completed_process) as run_mock,
    ):
        result = run_bbot_scan("https://example.com/path")

    run_mock.assert_called_once_with(
        ["bbot", "-t", "example.com", "-p", "subdomain-enum", "-o", str(tmp_path / "example.com"), "-y"],
        capture_output=True,
        text=True,
        timeout=BBOT_TIMEOUT_SECONDS,
        check=False,
        shell=False,
    )
    assert result["success"] is True
    assert result["target"] == "example.com"
    assert result["output"] == "bbot output"
    assert result["error"] == ""
    assert result["returncode"] == 0
    assert "elapsed_seconds" in result
    assert result["output_dir"] == str(tmp_path / "example.com")


def test_bbot_timeout_handled(tmp_path: Path) -> None:
    timeout = subprocess.TimeoutExpired(
        cmd=["bbot", "-t", "example.com"],
        timeout=BBOT_TIMEOUT_SECONDS,
        output="partial output",
        stderr="partial error",
    )

    with (
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.subprocess.run", side_effect=timeout),
    ):
        result = run_bbot_scan("example.com")

    assert result["success"] is False
    assert result["output"] == "partial output"
    assert result["error"] == "partial error"
    assert result["returncode"] is None


def test_bbot_missing_binary_handled(tmp_path: Path) -> None:
    with (
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.subprocess.run", side_effect=FileNotFoundError),
    ):
        result = run_bbot_scan("example.com")

    assert result["success"] is False
    assert result["output"] == ""
    assert result["error"] == "BBOT is not installed or not available on PATH."
    assert result["returncode"] is None


def test_bbot_failure_result_shape(tmp_path: Path) -> None:
    completed_process = Mock(returncode=2, stdout="", stderr="bad target")

    with (
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.subprocess.run", return_value=completed_process),
    ):
        result = run_bbot_scan("example.com")

    assert result["success"] is False
    assert result["target"] == "example.com"
    assert result["output"] == ""
    assert result["error"] == "bad target"
    assert result["returncode"] == 2
    assert "elapsed_seconds" in result
