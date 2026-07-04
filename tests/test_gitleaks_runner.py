import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from app.core.config import Settings
from app.parsers.gitleaks_parser import REDACTION_MARKER, contains_unredacted_secret, normalize_gitleaks_output
from app.tools.gitleaks_runner import _build_gitleaks_command, _resolve_gitleaks_executable, _validate_scan_scope, run_gitleaks_scan

RAW_SECRET = "ghp_1234567890abcdefghijklmnopqrstuv"
GITLEAKS_JSON = f"""
[
  {{
    "RuleID": "github-pat",
    "Description": "GitHub Personal Access Token",
    "File": "src/config.py",
    "StartLine": 12,
    "Secret": "{RAW_SECRET}",
    "Match": "token={RAW_SECRET}",
    "Entropy": 4.9,
    "Fingerprint": "abc123",
    "Commit": "deadbeef",
    "Author": "Ada"
  }}
]
"""


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["gitleaks"], returncode=returncode, stdout=stdout, stderr=stderr)


def test_gitleaks_runner_success_uses_safe_subprocess_args(tmp_path) -> None:
    scope = tmp_path / "artifact"
    scope.mkdir()
    settings = Settings(_env_file=None, gitleaks_scan_timeout_seconds=13)

    def run_side_effect(command, **kwargs):
        Path(command[7]).write_text(GITLEAKS_JSON, encoding="utf-8")
        return _completed(returncode=1)

    with (
        patch("app.tools.gitleaks_runner.get_settings", return_value=settings),
        patch("app.tools.gitleaks_runner.shutil.which", return_value="gitleaks"),
        patch("app.tools.gitleaks_runner.subprocess.run", side_effect=run_side_effect) as run_mock,
    ):
        result = run_gitleaks_scan(str(scope))

    command = run_mock.call_args.args[0]
    assert command[0] == "gitleaks"
    assert command[1] == "detect"
    assert command[2] == "--source"
    assert command[3] == str(scope.resolve())
    assert "--redact" in command
    assert run_mock.call_args.kwargs["shell"] is False
    assert run_mock.call_args.kwargs["timeout"] == 13
    assert result["success"] is True
    assert result["returncode"] == 1
    assert result["json_output"].strip().startswith("[")


def test_gitleaks_missing_binary_is_clean_failure(tmp_path) -> None:
    scope = tmp_path / "artifact"
    scope.mkdir()
    with (
        patch("app.tools.gitleaks_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.gitleaks_runner.shutil.which", return_value=None),
        patch("app.tools.gitleaks_runner.Path.is_file", return_value=False),
        patch("app.tools.gitleaks_runner.subprocess.run") as run_mock,
    ):
        result = run_gitleaks_scan(str(scope))

    assert result["success"] is False
    assert result["error_type"] == "missing_binary"
    assert result["command"] is None
    run_mock.assert_not_called()


def test_gitleaks_timeout_is_clean_failure(tmp_path) -> None:
    scope = tmp_path / "artifact"
    scope.mkdir()
    with (
        patch("app.tools.gitleaks_runner.get_settings", return_value=Settings(_env_file=None, gitleaks_scan_timeout_seconds=1)),
        patch("app.tools.gitleaks_runner.shutil.which", return_value="gitleaks"),
        patch("app.tools.gitleaks_runner.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="gitleaks", timeout=1, output="", stderr="slow")),
    ):
        result = run_gitleaks_scan(str(scope))

    assert result["success"] is False
    assert result["error_type"] == "timeout"
    assert result["error"] == "slow"


def test_gitleaks_path_safety_rejects_roots_and_traversal() -> None:
    with pytest.raises(ValueError):
        _validate_scan_scope("/")
    with pytest.raises(ValueError, match="shell characters"):
        _validate_scan_scope("artifact;whoami")


def test_gitleaks_path_safety_accepts_workspace_child(tmp_path) -> None:
    scope = tmp_path / "artifact"
    scope.mkdir()

    assert _validate_scan_scope(str(scope)) == scope.resolve()


def test_build_gitleaks_command_uses_explicit_argv(tmp_path) -> None:
    command = _build_gitleaks_command("gitleaks", tmp_path, Path("out.json"))

    assert command == [
        "gitleaks",
        "detect",
        "--source",
        str(tmp_path),
        "--report-format",
        "json",
        "--report-path",
        "out.json",
        "--redact",
        "--no-banner",
    ]


def test_gitleaks_path_discovery() -> None:
    with patch("app.tools.gitleaks_runner.shutil.which", return_value="/opt/bin/gitleaks"):
        assert _resolve_gitleaks_executable() == "/opt/bin/gitleaks"


def test_gitleaks_normalization_redacts_secret_values() -> None:
    evidence = normalize_gitleaks_output(GITLEAKS_JSON, scan_root="/tmp/artifact")
    finding = evidence["findings"][0]

    assert evidence["finding_count"] == 1
    assert evidence["affected_files_count"] == 1
    assert finding["rule_id"] == "github-pat"
    assert finding["file_path"] == "src/config.py"
    assert finding["line_number"] == 12
    assert finding["provider"] == "github"
    assert finding["redacted_secret_preview"].startswith(REDACTION_MARKER)
    assert not contains_unredacted_secret(evidence, RAW_SECRET)
