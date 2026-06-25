import subprocess

from scripts import security_audit


def _check(name: str = "Example") -> security_audit.AuditCheck:
    return security_audit.AuditCheck(
        name=name,
        command=["python", "-m", "example"],
        module_name="example",
        install_hint="Install example",
        timeout_seconds=10,
    )


def test_missing_tool_becomes_skipped() -> None:
    result = security_audit.run_check(_check(), installed=lambda check: False)

    assert result.status == security_audit.STATUS_SKIPPED
    assert result.error == "Install example"
    assert result.returncode is None


def test_passing_command_becomes_pass() -> None:
    def runner(*args, **kwargs):
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="ok", stderr="")

    result = security_audit.run_check(_check(), installed=lambda check: True, runner=runner)

    assert result.status == security_audit.STATUS_PASS
    assert result.output == "ok"
    assert result.returncode == 0


def test_failing_command_becomes_fail() -> None:
    def runner(*args, **kwargs):
        return subprocess.CompletedProcess(args=args[0], returncode=1, stdout="", stderr="bad")

    result = security_audit.run_check(_check(), installed=lambda check: True, runner=runner)

    assert result.status == security_audit.STATUS_FAIL
    assert result.error == "bad"
    assert result.returncode == 1


def test_timeout_becomes_fail() -> None:
    def runner(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=10, output=b"partial \x81")

    result = security_audit.run_check(_check(), installed=lambda check: True, runner=runner)

    assert result.status == security_audit.STATUS_FAIL
    assert result.output == "partial \ufffd"
    assert result.error == "Example timed out after 10s."


def test_subprocess_unicode_decode_error_becomes_fail() -> None:
    def runner(*args, **kwargs):
        raise UnicodeDecodeError("cp1252", b"\x81", 0, 1, "undefined")

    result = security_audit.run_check(_check(), installed=lambda check: True, runner=runner)

    assert result.status == security_audit.STATUS_FAIL
    assert "Unable to decode subprocess output" in result.error


def test_final_summary_fails_if_any_required_check_fails() -> None:
    results = [
        security_audit.AuditResult(check=_check("Passing"), status=security_audit.STATUS_PASS),
        security_audit.AuditResult(check=_check("Failing"), status=security_audit.STATUS_FAIL),
    ]

    assert security_audit.audit_passed(results) is False


def test_subprocess_uses_list_args_and_shell_false() -> None:
    calls = []

    def runner(*args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    check = _check()
    security_audit.run_check(check, installed=lambda installed_check: True, runner=runner)

    args, kwargs = calls[0]
    assert args[0] == check.command
    assert isinstance(args[0], list)
    assert kwargs["shell"] is False
    assert kwargs["encoding"] == "utf-8"
    assert kwargs["errors"] == "replace"
    assert kwargs["timeout"] == 10


def test_pytest_command_uses_project_local_basetemp() -> None:
    tests_check = next(check for check in security_audit.DEFAULT_CHECKS if check.name == "Tests")

    assert "--basetemp" in tests_check.command
    assert security_audit.PYTEST_BASETEMP in tests_check.command
    assert tests_check.timeout_seconds == 180


def test_bandit_command_does_not_scan_tests() -> None:
    bandit_check = next(check for check in security_audit.DEFAULT_CHECKS if check.name == "Bandit")

    assert bandit_check.command == [
        security_audit.sys.executable,
        "-m",
        "bandit",
        "-r",
        "app",
        "scripts",
    ]
    assert "tests" not in bandit_check.command
    assert bandit_check.timeout_seconds == 120


def test_default_audit_excludes_semgrep_and_includes_detect_secrets() -> None:
    calls = []

    def runner(*args, **kwargs):
        calls.append(args[0])
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    results = security_audit.run_audit(installed=lambda check: True, runner=runner)

    assert [result.check.name for result in results] == ["Tests", "Bandit", "pip-audit", "detect-secrets"]
    assert "Semgrep" not in [result.check.name for result in results]
    assert calls[-1] == ["detect-secrets", "scan"]


def test_full_audit_includes_semgrep() -> None:
    def runner(*args, **kwargs):
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    results = security_audit.run_audit(include_semgrep=True, installed=lambda check: True, runner=runner)

    assert [result.check.name for result in results] == [
        "Tests",
        "Bandit",
        "pip-audit",
        "detect-secrets",
        "Semgrep",
    ]
    assert results[-1].check.timeout_seconds == 180
