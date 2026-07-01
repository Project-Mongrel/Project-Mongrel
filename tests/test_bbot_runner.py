from io import StringIO
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from app.tools import bbot_runner
from app.tools.bbot_runner import BBOT_RUNTIME_INCOMPATIBLE_ERROR, BBOT_TIMEOUT_SECONDS, is_bbot_available, run_bbot_scan


def test_is_bbot_available_true() -> None:
    with patch("app.tools.bbot_runner.shutil.which", return_value="bbot"):
        assert is_bbot_available() is True


def test_is_bbot_available_from_windows_venv_fallback() -> None:
    windows_venv_bbot = str(Path(".venv") / "Scripts" / "bbot.exe")

    with (
        patch("app.tools.bbot_runner.shutil.which", return_value=None),
        patch("app.tools.bbot_runner.Path.is_file", autospec=True, side_effect=lambda path: str(path) == windows_venv_bbot),
    ):
        assert is_bbot_available() is True


def test_is_bbot_available_false() -> None:
    with (
        patch("app.tools.bbot_runner.shutil.which", return_value=None),
        patch("app.tools.bbot_runner.Path.is_file", return_value=False),
    ):
        assert is_bbot_available() is False


def test_empty_target_rejected() -> None:
    with pytest.raises(ValueError, match="cannot be empty"):
        run_bbot_scan("   ")


@pytest.mark.parametrize("target", ["example.com;whoami", "example.com && whoami", "example.com|whoami"])
def test_dangerous_shell_characters_rejected(target: str) -> None:
    with pytest.raises(ValueError, match="shell characters"):
        run_bbot_scan(target)


def test_bbot_subprocess_called_with_list_args_and_shell_false(tmp_path: Path) -> None:
    process = FakeBbotProcess(returncode=0, stdout="bbot output\n", stderr="")

    with (
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.shutil.which", return_value="bbot"),
        patch("app.tools.bbot_runner.subprocess.Popen", return_value=process) as popen_mock,
    ):
        result = run_bbot_scan("https://example.com/path")

    popen_mock.assert_called_once_with(
        ["bbot", "-t", "example.com", "-p", "subdomain-enum", "-o", str(tmp_path / "example.com"), "-y"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        cwd=str(Path.cwd().resolve()),
        shell=False,
    )
    assert result["success"] is True
    assert result["target"] == "example.com"
    assert result["output"] == "bbot output"
    assert result["error"] == ""
    assert result["returncode"] == 0
    assert "elapsed_seconds" in result
    assert result["output_dir"] == str(tmp_path / "example.com")
    assert result["command"] == ["bbot", "-t", "example.com", "-p", "subdomain-enum", "-o", str(tmp_path / "example.com"), "-y"]
    assert result["working_directory"] == str(Path.cwd().resolve())


def test_bbot_timeout_handled(tmp_path: Path) -> None:
    process = FakeBbotProcess(returncode=-9, stdout="partial output\n", stderr="partial error\n", timeout=True)

    with (
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.shutil.which", return_value="bbot"),
        patch("app.tools.bbot_runner.subprocess.Popen", return_value=process),
    ):
        result = run_bbot_scan("example.com")

    assert result["success"] is False
    assert result["output"] == "partial output"
    assert result["error"] == "partial error"
    assert result["returncode"] == -9
    assert process.killed is True


def test_bbot_timeout_harvests_json_output(tmp_path: Path) -> None:
    json_output_dir = tmp_path / "example.com" / "scan" / "output"
    json_output_dir.mkdir(parents=True)
    json_file = json_output_dir / "output.jsonl"
    json_file.write_text('{"type":"DNS_NAME","data":"partial.example.com"}\n', encoding="utf-8")
    process = FakeBbotProcess(returncode=-9, stdout="partial stdout\n", stderr="partial error\n", timeout=True)

    with (
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.shutil.which", return_value="bbot"),
        patch("app.tools.bbot_runner.subprocess.Popen", return_value=process),
    ):
        result = run_bbot_scan("example.com")

    assert result["success"] is False
    assert "partial stdout" in result["output"]
    assert '{"type":"DNS_NAME","data":"partial.example.com"}' in result["output"]
    assert result["json_output_found"] is True
    assert result["json_output_paths"] == [str(json_file)]
    assert process.killed is True


def test_bbot_missing_binary_handled(tmp_path: Path) -> None:
    with (
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.shutil.which", return_value=None),
        patch("app.tools.bbot_runner.Path.is_file", return_value=False),
        patch("app.tools.bbot_runner.subprocess.Popen") as popen_mock,
    ):
        result = run_bbot_scan("example.com")

    popen_mock.assert_not_called()
    assert result["success"] is False
    assert result["output"] == ""
    assert result["error"] == "BBOT is not installed or not available on PATH."
    assert result["returncode"] is None


def test_bbot_subprocess_uses_windows_venv_fallback(tmp_path: Path) -> None:
    process = FakeBbotProcess(returncode=0, stdout="bbot output\n", stderr="")
    windows_venv_bbot = str(Path(".venv") / "Scripts" / "bbot.exe")

    with (
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.shutil.which", return_value=None),
        patch("app.tools.bbot_runner.Path.is_file", autospec=True, side_effect=lambda path: str(path) == windows_venv_bbot),
        patch("app.tools.bbot_runner.subprocess.Popen", return_value=process) as popen_mock,
    ):
        result = run_bbot_scan("example.com")

    popen_mock.assert_called_once_with(
        [windows_venv_bbot, "-t", "example.com", "-p", "subdomain-enum", "-o", str(tmp_path / "example.com"), "-y"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        cwd=str(Path.cwd().resolve()),
        shell=False,
    )
    assert result["success"] is True
    assert result["command"][0] == windows_venv_bbot


def test_fcntl_error_classified_as_runtime_incompatible(tmp_path: Path) -> None:
    traceback = "Traceback (most recent call last):\n  File \"bbot\", line 1\nModuleNotFoundError: No module named 'fcntl'"
    process = FakeBbotProcess(returncode=1, stdout="", stderr=traceback)

    with (
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.shutil.which", return_value="bbot"),
        patch("app.tools.bbot_runner.subprocess.Popen", return_value=process),
    ):
        result = run_bbot_scan("example.com")

    assert result["success"] is False
    assert result["error_type"] == "runtime_incompatible"
    assert result["error"] == BBOT_RUNTIME_INCOMPATIBLE_ERROR
    assert "Traceback" not in result["error"]
    assert "fcntl" not in result["error"]
    assert result["output"] == ""


def test_resource_error_classified_as_runtime_incompatible_if_fatal(tmp_path: Path) -> None:
    traceback = 'Traceback (most recent call last):\nModuleNotFoundError: No module named "resource"'
    process = FakeBbotProcess(returncode=1, stdout=traceback, stderr="")

    with (
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.shutil.which", return_value="bbot"),
        patch("app.tools.bbot_runner.subprocess.Popen", return_value=process),
    ):
        result = run_bbot_scan("example.com")

    assert result["success"] is False
    assert result["error_type"] == "runtime_incompatible"
    assert result["error"] == BBOT_RUNTIME_INCOMPATIBLE_ERROR
    assert "Traceback" not in result["error"]
    assert "resource" not in result["error"]


def test_bbot_failure_result_shape(tmp_path: Path) -> None:
    process = FakeBbotProcess(returncode=2, stdout="", stderr="bad target\n")

    with (
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.shutil.which", return_value="bbot"),
        patch("app.tools.bbot_runner.subprocess.Popen", return_value=process),
    ):
        result = run_bbot_scan("example.com")

    assert result["success"] is False
    assert result["target"] == "example.com"
    assert result["output"] == ""
    assert result["error"] == "bad target"
    assert result["error_type"] == "bbot_failed"
    assert result["returncode"] == 2
    assert "elapsed_seconds" in result


def test_bbot_json_output_is_harvested_after_process_exit(tmp_path: Path) -> None:
    json_output_dir = tmp_path / "example.com" / "scan" / "output"
    json_output_dir.mkdir(parents=True)
    json_file = json_output_dir / "output.jsonl"
    json_file.write_text('{"type":"DNS_NAME","data":"app.example.com"}\n', encoding="utf-8")
    process = FakeBbotProcess(returncode=0, stdout="bbot complete\n", stderr="")

    with (
        patch.object(bbot_runner, "BBOT_OUTPUT_DIR", tmp_path),
        patch("app.tools.bbot_runner.shutil.which", return_value="bbot"),
        patch("app.tools.bbot_runner.subprocess.Popen", return_value=process),
    ):
        result = run_bbot_scan("example.com")

    assert result["success"] is True
    assert "bbot complete" in result["output"]
    assert '{"type":"DNS_NAME","data":"app.example.com"}' in result["output"]
    assert result["json_output_found"] is True
    assert result["json_output_paths"] == [str(json_file)]


class FakeBbotProcess:
    def __init__(self, returncode: int, stdout: str, stderr: str, timeout: bool = False) -> None:
        self.returncode = returncode
        self.stdout = StringIO(stdout)
        self.stderr = StringIO(stderr)
        self.timeout = timeout
        self.killed = False
        self.wait_calls = 0

    def wait(self, timeout: int | None = None) -> int:
        self.wait_calls += 1
        if self.timeout and self.wait_calls == 1:
            raise subprocess.TimeoutExpired(cmd=["bbot"], timeout=timeout)
        return self.returncode

    def kill(self) -> None:
        self.killed = True
