import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from app.core.config import Settings
from app.tools.prowler_runner import (
    build_prowler_command,
    normalize_prowler_provider,
    redact_prowler_text,
    run_prowler_scan,
    summarize_prowler_failure,
)


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["prowler"], returncode=returncode, stdout=stdout, stderr=stderr)


def test_prowler_provider_allowlist_accepts_initial_clouds() -> None:
    assert normalize_prowler_provider("aws") == "aws"
    assert normalize_prowler_provider("AZURE") == "azure"
    assert normalize_prowler_provider(" gcp ") == "gcp"


def test_prowler_provider_allowlist_rejects_unsupported_values() -> None:
    with pytest.raises(ValueError):
        normalize_prowler_provider("kubernetes")


def test_build_prowler_command_uses_narrow_json_ocsf_contract(tmp_path) -> None:
    command = build_prowler_command("prowler", "aws", tmp_path, "mongrel-prowler")

    assert command == [
        "prowler",
        "aws",
        "--output-formats",
        "json-ocsf",
        "--output-directory",
        str(tmp_path),
        "--output-filename",
        "mongrel-prowler",
    ]


def test_build_prowler_command_rejects_arbitrary_flag_injection(tmp_path) -> None:
    with pytest.raises(ValueError):
        build_prowler_command("prowler", "aws", tmp_path, "report --fix")
    with pytest.raises(ValueError):
        build_prowler_command("prowler", "aws --fix", tmp_path, "report")


def test_prowler_runner_success_uses_safe_subprocess_args(tmp_path) -> None:
    settings = Settings(_env_file=None, prowler_timeout_seconds=17)

    with (
        patch("app.tools.prowler_runner.get_settings", return_value=settings),
        patch("app.tools.prowler_runner.shutil.which", return_value="prowler"),
        patch("app.tools.prowler_runner.subprocess.run", return_value=_completed(stdout="ok")) as run_mock,
    ):
        result = run_prowler_scan("aws", tmp_path, "mongrel-prowler")

    command = run_mock.call_args.args[0]
    assert command[0] == "prowler"
    assert command[1] == "aws"
    assert "--output-formats" in command
    assert "json-ocsf" in command
    assert run_mock.call_args.kwargs["shell"] is False
    assert run_mock.call_args.kwargs["timeout"] == 17
    assert result["success"] is True
    assert result["output"] == "ok"


def test_prowler_missing_binary_is_clean_failure(tmp_path) -> None:
    with (
        patch("app.tools.prowler_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.prowler_runner.shutil.which", return_value=None),
        patch("app.tools.prowler_runner.subprocess.run") as run_mock,
    ):
        result = run_prowler_scan("aws", tmp_path, "mongrel-prowler")

    assert result["success"] is False
    assert result["error_type"] == "missing_binary"
    assert result["command"] is None
    run_mock.assert_not_called()


def test_prowler_timeout_is_clean_failure_and_redacts_credentials(tmp_path) -> None:
    raw_error = "aws_secret_access_key=not-a-real-test-value"
    with (
        patch("app.tools.prowler_runner.get_settings", return_value=Settings(_env_file=None, prowler_timeout_seconds=1)),
        patch("app.tools.prowler_runner.shutil.which", return_value="prowler"),
        patch("app.tools.prowler_runner.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="prowler", timeout=1, stderr=raw_error)),
    ):
        result = run_prowler_scan("aws", tmp_path, "mongrel-prowler")

    assert result["success"] is False
    assert result["error_type"] == "timeout"
    assert "not-a-real-test-value" not in str(result)
    assert "<REDACTED>" in result["error"]


def test_prowler_failure_redacts_credential_like_output(tmp_path) -> None:
    stderr = "authorization: Bearer fake-token-for-test"
    with (
        patch("app.tools.prowler_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.prowler_runner.shutil.which", return_value="prowler"),
        patch("app.tools.prowler_runner.subprocess.run", return_value=_completed(stderr=stderr, returncode=2)),
    ):
        result = run_prowler_scan("aws", tmp_path, "mongrel-prowler")

    assert result["success"] is False
    assert "fake-token-for-test" not in str(result)
    assert "<REDACTED>" in result["error"]


def test_prowler_no_credentials_failure_uses_concise_safe_reason(tmp_path) -> None:
    stdout = "[1;92m                         _\n\x1b[1;92m  ____  Prowler banner"
    stderr = "\n".join(
        [
            "[File: aws_provider.py:1347]",
            "[Module: aws_provider]",
            "CRITICAL: NoCredentialsError: Unable to locate credentials",
            "aws_secret_access_key=not-a-real-test-value",
        ]
    )
    with (
        patch("app.tools.prowler_runner.get_settings", return_value=Settings(_env_file=None)),
        patch("app.tools.prowler_runner.shutil.which", return_value="prowler"),
        patch("app.tools.prowler_runner.subprocess.run", return_value=_completed(stdout=stdout, stderr=stderr, returncode=2)),
    ):
        result = run_prowler_scan("aws", tmp_path, "mongrel-prowler")

    assert result["success"] is False
    assert result["error_type"] == "missing_credentials"
    assert result["error"] == "Cloud credentials were not available for AWS on the Mongrel VPS."
    assert "[1;92m" not in str(result)
    assert "____" not in str(result)
    assert "[File:" not in result["error"]
    assert "[Module:" not in result["error"]
    assert "not-a-real-test-value" not in str(result)


def test_prowler_other_failure_ignores_banner_and_is_safely_summarized() -> None:
    summary = summarize_prowler_failure(
        "aws",
        stdout="[1;92m                         _\n\x1b[1;92m  ____  Prowler banner",
        stderr="[File: x.py:1]\n[Module: x]\nCRITICAL: Prowler execution failed for an expected test reason",
    )

    assert summary == "CRITICAL: Prowler execution failed for an expected test reason"
    assert "[1;92m" not in summary
    assert "____" not in summary
    assert "[File:" not in summary
    assert "[Module:" not in summary


def test_redact_prowler_text_removes_likely_access_key() -> None:
    access_key = "".join(("AK", "IA", "IOSFODNN7", "EXAMPLE"))
    assert access_key not in redact_prowler_text(access_key)
