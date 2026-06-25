import subprocess
from unittest.mock import Mock, patch

import pytest

from app.tools.nmap_runner import NMAP_TIMEOUT_SECONDS, run_nmap_scan


def test_empty_target_rejected() -> None:
    with pytest.raises(ValueError, match="cannot be empty"):
        run_nmap_scan("   ")


@pytest.mark.parametrize("target", ["example.com;whoami", "example.com && whoami", "example.com|whoami"])
def test_dangerous_shell_characters_rejected(target: str) -> None:
    with pytest.raises(ValueError, match="shell characters"):
        run_nmap_scan(target)


def test_subprocess_called_with_list_args() -> None:
    completed_process = Mock(returncode=0, stdout="scan output", stderr="")

    with patch("app.tools.nmap_runner.subprocess.run", return_value=completed_process) as run_mock:
        result = run_nmap_scan("example.com")

    run_mock.assert_called_once_with(
        ["nmap", "-Pn", "-T3", "example.com"],
        capture_output=True,
        text=True,
        timeout=NMAP_TIMEOUT_SECONDS,
        check=False,
        shell=False,
    )
    assert result == {
        "target": "example.com",
        "success": True,
        "output": "scan output",
        "error": "",
        "returncode": 0,
    }


def test_nmap_url_target_is_normalized_before_execution() -> None:
    completed_process = Mock(returncode=0, stdout="scan output", stderr="")

    with patch("app.tools.nmap_runner.subprocess.run", return_value=completed_process) as run_mock:
        result = run_nmap_scan("https://www.example.com/shop")

    run_mock.assert_called_once_with(
        ["nmap", "-Pn", "-T3", "www.example.com"],
        capture_output=True,
        text=True,
        timeout=NMAP_TIMEOUT_SECONDS,
        check=False,
        shell=False,
    )
    assert result["target"] == "www.example.com"


def test_timeout_handled() -> None:
    timeout = subprocess.TimeoutExpired(
        cmd=["nmap", "-Pn", "-T3", "example.com"],
        timeout=NMAP_TIMEOUT_SECONDS,
        output="partial output",
        stderr="partial error",
    )

    with patch("app.tools.nmap_runner.subprocess.run", side_effect=timeout):
        result = run_nmap_scan("example.com")

    assert result == {
        "target": "example.com",
        "success": False,
        "output": "partial output",
        "error": "partial error",
        "returncode": None,
    }
