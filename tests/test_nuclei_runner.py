import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from app.core.config import Settings
from app.tools.nuclei_runner import _build_nuclei_command, _resolve_nuclei_executable, run_nuclei_scan


def _expected_nuclei_command(executable: str = "nuclei") -> list[str]:
    return [
        executable,
        "-u",
        "example.com",
        "-jsonl",
        "-silent",
        "-severity",
        "low,medium,high,critical",
        "-tags",
        "exposure,misconfig,tech,panel,headers",
        "-rate-limit",
        "25",
        "-timeout",
        "5",
        "-retries",
        "1",
    ]


def test_empty_nuclei_target_rejected() -> None:
    with pytest.raises(ValueError, match="cannot be empty"):
        run_nuclei_scan("   ")


@pytest.mark.parametrize("target", ["example.com;whoami", "example.com && whoami", "example.com|whoami"])
def test_dangerous_nuclei_target_rejected(target: str) -> None:
    with pytest.raises(ValueError, match="shell characters"):
        run_nuclei_scan(target)


def test_nuclei_subprocess_called_with_list_args_and_shell_false() -> None:
    completed_process = Mock(returncode=0, stdout='{"template-id":"one"}\n', stderr="")
    settings = Settings(_env_file=None)

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=settings),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.run", return_value=completed_process) as run_mock,
    ):
        result = run_nuclei_scan("https://example.com")

    run_mock.assert_called_once_with(
        _expected_nuclei_command(),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
        cwd=str(Path.cwd().resolve()),
        shell=False,
    )
    assert result["target"] == "example.com"
    assert result["success"] is True
    assert result["output"] == '{"template-id":"one"}\n'
    assert result["error"] == ""
    assert result["error_type"] is None
    assert result["returncode"] == 0
    assert result["command"] == _expected_nuclei_command()
    assert result["working_directory"] == str(Path.cwd().resolve())


def test_nuclei_command_uses_custom_configured_path() -> None:
    completed_process = Mock(returncode=0, stdout="", stderr="")
    settings = Settings(_env_file=None, nuclei_path="C:\\Tools\\Nuclei\\nuclei.exe")

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=settings),
        patch("app.tools.nuclei_runner.subprocess.run", return_value=completed_process) as run_mock,
    ):
        run_nuclei_scan("https://example.com")

    assert run_mock.call_args.args[0] == _expected_nuclei_command("C:\\Tools\\Nuclei\\nuclei.exe")


def test_nuclei_subprocess_timeout_uses_config_value() -> None:
    completed_process = Mock(returncode=0, stdout="", stderr="")
    settings = Settings(_env_file=None, nuclei_scan_timeout_seconds=444)

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=settings),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.run", return_value=completed_process) as run_mock,
    ):
        run_nuclei_scan("https://example.com")

    assert run_mock.call_args.kwargs["timeout"] == 444


def test_nuclei_command_uses_configured_rate_limit_timeout_and_retries() -> None:
    completed_process = Mock(returncode=0, stdout="", stderr="")
    settings = Settings(
        _env_file=None,
        nuclei_tags="exposure,tech",
        nuclei_rate_limit=10,
        nuclei_request_timeout=3,
        nuclei_retries=2,
    )

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=settings),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.run", return_value=completed_process) as run_mock,
    ):
        run_nuclei_scan("https://example.com")

    assert run_mock.call_args.args[0] == [
        "nuclei",
        "-u",
        "example.com",
        "-jsonl",
        "-silent",
        "-severity",
        "low,medium,high,critical",
        "-tags",
        "exposure,tech",
        "-rate-limit",
        "10",
        "-timeout",
        "3",
        "-retries",
        "2",
    ]


def test_nuclei_timeout_handled() -> None:
    timeout = subprocess.TimeoutExpired(
        cmd=_expected_nuclei_command(),
        timeout=180,
        output="partial output",
    )

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.run", side_effect=timeout),
    ):
        result = run_nuclei_scan("https://example.com")

    assert result["target"] == "example.com"
    assert result["success"] is False
    assert result["output"] == "partial output"
    assert result["error"] == "Nuclei fast scan timed out. Try a smaller target or use a deeper scan profile later."
    assert result["error_type"] == "timeout"
    assert result["returncode"] is None


def test_nuclei_configured_executable_missing_at_subprocess_handled() -> None:
    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None, nuclei_path="missing-nuclei")),
        patch("app.tools.nuclei_runner.subprocess.run", side_effect=FileNotFoundError),
    ):
        result = run_nuclei_scan("https://example.com")

    assert result["target"] == "example.com"
    assert result["success"] is False
    assert result["output"] == ""
    assert result["error"] == "Nuclei executable was not found."
    assert result["error_type"] == "missing_binary"
    assert result["returncode"] is None


def test_nuclei_path_discovery() -> None:
    with patch("app.tools.nuclei_runner.shutil.which", return_value="/opt/bin/nuclei"):
        assert _resolve_nuclei_executable() == "/opt/bin/nuclei"


def test_nuclei_linux_executable_discovery() -> None:
    linux_nuclei = Path("/usr/local/bin/nuclei")

    with (
        patch("app.tools.nuclei_runner.shutil.which", return_value=None),
        patch("app.tools.nuclei_runner.Path.is_file", autospec=True, side_effect=lambda path: path == linux_nuclei),
    ):
        assert _resolve_nuclei_executable() == str(linux_nuclei)


def test_nuclei_windows_executable_discovery() -> None:
    windows_nuclei = Path(".venv") / "Scripts" / "nuclei.exe"

    with (
        patch("app.tools.nuclei_runner.shutil.which", return_value=None),
        patch("app.tools.nuclei_runner.Path.is_file", autospec=True, side_effect=lambda path: path == windows_nuclei),
    ):
        assert _resolve_nuclei_executable() == str(windows_nuclei)


def test_nuclei_linux_venv_executable_discovery() -> None:
    linux_venv_nuclei = Path(".venv") / "bin" / "nuclei"

    with (
        patch("app.tools.nuclei_runner.shutil.which", return_value=None),
        patch("app.tools.nuclei_runner.Path.is_file", autospec=True, side_effect=lambda path: path == linux_venv_nuclei),
    ):
        assert _resolve_nuclei_executable() == str(linux_venv_nuclei)


def test_nuclei_missing_binary_handled_before_subprocess() -> None:
    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.nuclei_runner.shutil.which", return_value=None),
        patch("app.tools.nuclei_runner.Path.is_file", return_value=False),
        patch("app.tools.nuclei_runner.subprocess.run") as run_mock,
    ):
        result = run_nuclei_scan("https://example.com")

    run_mock.assert_not_called()
    assert result["success"] is False
    assert result["error"] == "Nuclei executable was not found."
    assert result["error_type"] == "missing_binary"
    assert result["command"] is None


def test_nuclei_execution_failure_classified() -> None:
    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.run", side_effect=PermissionError("denied")),
    ):
        result = run_nuclei_scan("https://example.com")

    assert result["success"] is False
    assert result["error"] == "Nuclei execution failed."
    assert result["error_type"] == "execution_failed"
    assert result["returncode"] is None


def test_nuclei_nonzero_exit_classified_as_execution_failed() -> None:
    completed_process = Mock(returncode=2, stdout="", stderr="bad flags")

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.run", return_value=completed_process),
    ):
        result = run_nuclei_scan("https://example.com")

    assert result["success"] is False
    assert result["error"] == "bad flags"
    assert result["error_type"] == "execution_failed"
    assert result["returncode"] == 2


def test_nuclei_runner_error_classified() -> None:
    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.nuclei_runner.shutil.which", return_value="nuclei"),
        patch("app.tools.nuclei_runner.subprocess.run", side_effect=RuntimeError("boom")),
    ):
        result = run_nuclei_scan("https://example.com")

    assert result["success"] is False
    assert result["error"] == "Nuclei runner error."
    assert result["error_type"] == "runner_error"


def test_nuclei_argv_generation() -> None:
    settings = Settings(_env_file=None, nuclei_tags="exposure", nuclei_rate_limit=7, nuclei_request_timeout=3, nuclei_retries=0)

    assert _build_nuclei_command("/usr/local/bin/nuclei", "scanme.nmap.org", settings) == [
        "/usr/local/bin/nuclei",
        "-u",
        "scanme.nmap.org",
        "-jsonl",
        "-silent",
        "-severity",
        "low,medium,high,critical",
        "-tags",
        "exposure",
        "-rate-limit",
        "7",
        "-timeout",
        "3",
        "-retries",
        "0",
    ]


def test_nuclei_linux_regression_uses_common_path_when_path_lookup_fails() -> None:
    completed_process = Mock(returncode=0, stdout="", stderr="")

    with (
        patch("app.tools.nuclei_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.nuclei_runner.shutil.which", return_value=None),
        patch("app.tools.nuclei_runner.Path.is_file", autospec=True, side_effect=lambda path: path == Path("/usr/local/bin/nuclei")),
        patch("app.tools.nuclei_runner.subprocess.run", return_value=completed_process) as run_mock,
    ):
        result = run_nuclei_scan("https://scanme.nmap.org")

    assert result["success"] is True
    assert run_mock.call_args.args[0][0] == str(Path("/usr/local/bin/nuclei"))
