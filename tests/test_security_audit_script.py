import os
import subprocess
import time
from pathlib import Path

import pytest

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


def test_requirements_declares_starlette_full_extra_without_changing_httpx_pin() -> None:
    requirements = (security_audit.PROJECT_ROOT / "requirements.txt").read_text(encoding="utf-8")

    assert "starlette[full]==1.3.1" in requirements.splitlines()
    assert "httpx==0.28.1" in requirements.splitlines()
    assert "httpx2" not in requirements


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
    assert kwargs["cwd"] == str(security_audit.PROJECT_ROOT)
    assert isinstance(kwargs["env"], dict)


def test_pytest_command_uses_project_local_basetemp() -> None:
    tests_check = next(check for check in security_audit.DEFAULT_CHECKS if check.name == "Tests")

    assert tests_check.command == [security_audit.sys.executable, "-m", "pytest"]
    assert "--basetemp" not in tests_check.command
    basetemp = security_audit.build_pytest_audit_basetemp()
    assert basetemp.parent == security_audit.PYTEST_AUDIT_TEMP_ROOT
    assert basetemp.name.startswith("run-")
    assert tests_check.timeout_seconds == 180


def test_import_time_default_checks_do_not_create_audit_run_directory() -> None:
    tests_check = next(check for check in security_audit.DEFAULT_CHECKS if check.name == "Tests")

    assert not any(part.startswith("run-") for part in tests_check.command)
    assert "--basetemp" not in tests_check.command


def test_pytest_check_uses_audit_temp_root_environment() -> None:
    calls = []

    def runner(*args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    tests_check = next(check for check in security_audit.DEFAULT_CHECKS if check.name == "Tests")
    security_audit.run_check(tests_check, installed=lambda check: True, runner=runner)

    command = calls[0][0][0]
    assert command[:3] == [security_audit.sys.executable, "-m", "pytest"]
    assert "--basetemp" in command
    basetemp = Path(command[command.index("--basetemp") + 1])
    assert basetemp.parent == security_audit.PYTEST_AUDIT_TEMP_ROOT
    assert basetemp.name.startswith("run-")
    assert calls[0][1]["env"][security_audit.PYTEST_TEMP_ROOT_ENV] == str(basetemp / "nested-pytest")


def test_pytest_audit_temp_is_cleaned_after_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    audit_root = tmp_path / ".pytest_tmp_audit"
    basetemp = audit_root / "run-success"
    monkeypatch.setattr(security_audit, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(security_audit, "PYTEST_AUDIT_TEMP_ROOT", audit_root)
    monkeypatch.setattr(security_audit, "build_pytest_audit_basetemp", lambda: basetemp)

    def runner(*args, **kwargs):
        basetemp.mkdir(parents=True)
        (basetemp / "mongrel.db").write_text("generated", encoding="utf-8")
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    result = security_audit.run_check(_check("Tests"), installed=lambda check: True, runner=runner)

    assert result.status == security_audit.STATUS_PASS
    assert not basetemp.exists()


def test_pytest_audit_temp_is_cleaned_after_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    audit_root = tmp_path / ".pytest_tmp_audit"
    basetemp = audit_root / "run-failure"
    monkeypatch.setattr(security_audit, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(security_audit, "PYTEST_AUDIT_TEMP_ROOT", audit_root)
    monkeypatch.setattr(security_audit, "build_pytest_audit_basetemp", lambda: basetemp)

    def runner(*args, **kwargs):
        basetemp.mkdir(parents=True)
        (basetemp / "mongrel.db").write_text("generated", encoding="utf-8")
        return subprocess.CompletedProcess(args=args[0], returncode=1, stdout="", stderr="failed")

    result = security_audit.run_check(_check("Tests"), installed=lambda check: True, runner=runner)

    assert result.status == security_audit.STATUS_FAIL
    assert not basetemp.exists()


def test_pytest_audit_temp_is_cleaned_after_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    audit_root = tmp_path / ".pytest_tmp_audit"
    basetemp = audit_root / "run-timeout"
    monkeypatch.setattr(security_audit, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(security_audit, "PYTEST_AUDIT_TEMP_ROOT", audit_root)
    monkeypatch.setattr(security_audit, "build_pytest_audit_basetemp", lambda: basetemp)

    def runner(*args, **kwargs):
        basetemp.mkdir(parents=True)
        (basetemp / "mongrel.db").write_text("generated", encoding="utf-8")
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=10)

    result = security_audit.run_check(_check("Tests"), installed=lambda check: True, runner=runner)

    assert result.status == security_audit.STATUS_FAIL
    assert not basetemp.exists()


def test_repeated_pytest_audit_runs_do_not_accumulate_run_directories(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    audit_root = tmp_path / ".pytest_tmp_audit"
    basetemps = [audit_root / "run-first", audit_root / "run-second"]
    monkeypatch.setattr(security_audit, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(security_audit, "PYTEST_AUDIT_TEMP_ROOT", audit_root)
    monkeypatch.setattr(security_audit, "build_pytest_audit_basetemp", lambda: basetemps.pop(0))

    def runner(*args, **kwargs):
        basetemp = Path(args[0][args[0].index("--basetemp") + 1])
        basetemp.mkdir(parents=True)
        (basetemp / "mongrel.db").write_text("generated", encoding="utf-8")
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    check = _check("Tests")
    first = security_audit.run_check(check, installed=lambda check: True, runner=runner)
    second = security_audit.run_check(check, installed=lambda check: True, runner=runner)

    assert first.status == second.status == security_audit.STATUS_PASS
    assert list(audit_root.glob("run-*")) == []


def test_nested_pytest_temp_root_is_scoped_under_current_audit_basetemp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    audit_root = tmp_path / ".pytest_tmp_audit"
    basetemp = audit_root / "run-current"
    monkeypatch.setattr(security_audit, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(security_audit, "PYTEST_AUDIT_TEMP_ROOT", audit_root)
    monkeypatch.setattr(security_audit, "build_pytest_audit_basetemp", lambda: basetemp)

    def runner(*args, **kwargs):
        basetemp.mkdir(parents=True)
        nested_root = Path(kwargs["env"][security_audit.PYTEST_TEMP_ROOT_ENV])
        nested_run = nested_root / "run-nested"
        nested_run.mkdir(parents=True)
        (nested_run / "mongrel.db").write_text("nested generated", encoding="utf-8")
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    result = security_audit.run_check(_check("Tests"), installed=lambda check: True, runner=runner)

    assert result.status == security_audit.STATUS_PASS
    assert not basetemp.exists()
    assert list(audit_root.glob("run-*")) == []


def test_pytest_audit_cleanup_does_not_remove_other_active_run_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    audit_root = tmp_path / ".pytest_tmp_audit"
    basetemp = audit_root / "run-current"
    other_run = audit_root / "run-other-active"
    other_run.mkdir(parents=True)
    (other_run / "keep.txt").write_text("other invocation", encoding="utf-8")
    monkeypatch.setattr(security_audit, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(security_audit, "PYTEST_AUDIT_TEMP_ROOT", audit_root)
    monkeypatch.setattr(security_audit, "build_pytest_audit_basetemp", lambda: basetemp)

    def runner(*args, **kwargs):
        basetemp.mkdir(parents=True)
        (basetemp / "mongrel.db").write_text("generated", encoding="utf-8")
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    result = security_audit.run_check(_check("Tests"), installed=lambda check: True, runner=runner)

    assert result.status == security_audit.STATUS_PASS
    assert not basetemp.exists()
    assert other_run.exists()
    assert (other_run / "keep.txt").exists()


def test_generated_pytest_cleanup_removes_normal_run_directories(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest_root = tmp_path / ".pytest_tmp"
    stale_run = pytest_root / "run-stale"
    stale_run.mkdir(parents=True)
    (stale_run / "mongrel.db").write_text("generated", encoding="utf-8")
    unrelated_dir = pytest_root / "not-run"
    unrelated_dir.mkdir()
    unrelated_file = pytest_root / "run-file"
    unrelated_file.write_text("not a directory", encoding="utf-8")
    monkeypatch.setattr(security_audit, "PYTEST_TEMP_ROOT", pytest_root)
    monkeypatch.setattr(security_audit, "PYTEST_AUDIT_TEMP_ROOT", tmp_path / ".pytest_tmp_audit")
    monkeypatch.setattr(security_audit, "PYTEST_FALLBACK_TEMP_ROOT", tmp_path / ".pytest_tmp_runs")

    removed = security_audit.cleanup_generated_pytest_run_roots()

    assert removed == [stale_run]
    assert not stale_run.exists()
    assert unrelated_dir.exists()
    assert unrelated_file.exists()


def test_generated_pytest_cleanup_removes_fallback_run_directories(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fallback_root = tmp_path / ".pytest_tmp_runs"
    stale_run = fallback_root / "run-fallback"
    stale_run.mkdir(parents=True)
    (stale_run / "mongrel.db").write_text("generated", encoding="utf-8")
    monkeypatch.setattr(security_audit, "PYTEST_TEMP_ROOT", tmp_path / ".pytest_tmp")
    monkeypatch.setattr(security_audit, "PYTEST_AUDIT_TEMP_ROOT", tmp_path / ".pytest_tmp_audit")
    monkeypatch.setattr(security_audit, "PYTEST_FALLBACK_TEMP_ROOT", fallback_root)

    removed = security_audit.cleanup_generated_pytest_run_roots()

    assert removed == [stale_run]
    assert not stale_run.exists()


def test_generated_pytest_cleanup_removes_stale_audit_run_directories(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    audit_root = tmp_path / ".pytest_tmp_audit"
    stale_run = audit_root / "run-stale-audit"
    stale_run.mkdir(parents=True)
    (stale_run / "mongrel.db").write_text("generated", encoding="utf-8")
    monkeypatch.setattr(security_audit, "PYTEST_TEMP_ROOT", tmp_path / ".pytest_tmp")
    monkeypatch.setattr(security_audit, "PYTEST_AUDIT_TEMP_ROOT", audit_root)
    monkeypatch.setattr(security_audit, "PYTEST_FALLBACK_TEMP_ROOT", tmp_path / ".pytest_tmp_runs")

    removed = security_audit.cleanup_generated_pytest_run_roots()

    assert removed == [stale_run]
    assert not stale_run.exists()


def test_generated_pytest_cleanup_preserves_active_audit_basetemp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    audit_root = tmp_path / ".pytest_tmp_audit"
    active_run = audit_root / "run-active"
    stale_run = audit_root / "run-stale"
    active_run.mkdir(parents=True)
    stale_run.mkdir()
    (active_run / "keep.txt").write_text("active", encoding="utf-8")
    (stale_run / "mongrel.db").write_text("generated", encoding="utf-8")
    monkeypatch.setattr(security_audit, "PYTEST_TEMP_ROOT", tmp_path / ".pytest_tmp")
    monkeypatch.setattr(security_audit, "PYTEST_AUDIT_TEMP_ROOT", audit_root)
    monkeypatch.setattr(security_audit, "PYTEST_FALLBACK_TEMP_ROOT", tmp_path / ".pytest_tmp_runs")

    removed = security_audit.cleanup_generated_pytest_run_roots(active_basetemp=active_run)

    assert removed == [stale_run]
    assert active_run.exists()
    assert (active_run / "keep.txt").exists()
    assert not stale_run.exists()


def test_generated_pytest_cleanup_preserves_live_pid_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest_root = tmp_path / ".pytest_tmp"
    live_run = pytest_root / f"run-{security_audit.os.getpid()}-live"
    stale_run = pytest_root / "run-999999999-stale"
    live_run.mkdir(parents=True)
    stale_run.mkdir()
    (live_run / "keep.txt").write_text("active process", encoding="utf-8")
    (stale_run / "mongrel.db").write_text("generated", encoding="utf-8")
    monkeypatch.setattr(security_audit, "PYTEST_TEMP_ROOT", pytest_root)
    monkeypatch.setattr(security_audit, "PYTEST_AUDIT_TEMP_ROOT", tmp_path / ".pytest_tmp_audit")
    monkeypatch.setattr(security_audit, "PYTEST_FALLBACK_TEMP_ROOT", tmp_path / ".pytest_tmp_runs")

    removed = security_audit.cleanup_generated_pytest_run_roots()

    assert removed == [stale_run]
    assert live_run.exists()
    assert (live_run / "keep.txt").exists()
    assert not stale_run.exists()


def test_generated_pytest_cleanup_removes_stale_live_pid_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest_root = tmp_path / ".pytest_tmp"
    stale_live_run = pytest_root / f"run-{os.getpid()}-stale"
    stale_live_run.mkdir(parents=True)
    (stale_live_run / "mongrel.db").write_text("generated", encoding="utf-8")
    stale_time = time.time() - security_audit.PYTEST_TEMP_STALE_SECONDS - 1
    os.utime(stale_live_run, (stale_time, stale_time))
    monkeypatch.setattr(security_audit, "PYTEST_TEMP_ROOT", pytest_root)
    monkeypatch.setattr(security_audit, "PYTEST_AUDIT_TEMP_ROOT", tmp_path / ".pytest_tmp_audit")
    monkeypatch.setattr(security_audit, "PYTEST_FALLBACK_TEMP_ROOT", tmp_path / ".pytest_tmp_runs")

    removed = security_audit.cleanup_generated_pytest_run_roots()

    assert removed == [stale_live_run]
    assert not stale_live_run.exists()


def test_generated_pytest_cleanup_removes_stale_dead_pid_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest_root = tmp_path / ".pytest_tmp"
    stale_dead_run = pytest_root / "run-999999999-stale"
    stale_dead_run.mkdir(parents=True)
    stale_time = time.time() - security_audit.PYTEST_TEMP_STALE_SECONDS - 1
    os.utime(stale_dead_run, (stale_time, stale_time))
    monkeypatch.setattr(security_audit, "PYTEST_TEMP_ROOT", pytest_root)
    monkeypatch.setattr(security_audit, "PYTEST_AUDIT_TEMP_ROOT", tmp_path / ".pytest_tmp_audit")
    monkeypatch.setattr(security_audit, "PYTEST_FALLBACK_TEMP_ROOT", tmp_path / ".pytest_tmp_runs")

    removed = security_audit.cleanup_generated_pytest_run_roots()

    assert removed == [stale_dead_run]
    assert not stale_dead_run.exists()


def test_generated_pytest_cleanup_rejects_symlink_escape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest_root = tmp_path / ".pytest_tmp"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("do not remove", encoding="utf-8")
    pytest_root.mkdir()
    escape = pytest_root / "run-escape"
    escape.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(security_audit, "PYTEST_TEMP_ROOT", pytest_root)
    monkeypatch.setattr(security_audit, "PYTEST_AUDIT_TEMP_ROOT", tmp_path / ".pytest_tmp_audit")
    monkeypatch.setattr(security_audit, "PYTEST_FALLBACK_TEMP_ROOT", tmp_path / ".pytest_tmp_runs")

    removed = security_audit.cleanup_generated_pytest_run_roots()

    assert removed == []
    assert escape.exists()
    assert outside.exists()
    assert (outside / "keep.txt").exists()


def test_detect_secrets_prepare_cleans_pytest_run_roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest_root = tmp_path / ".pytest_tmp"
    stale_run = pytest_root / "run-before-detect-secrets"
    stale_run.mkdir(parents=True)
    (stale_run / "mongrel.db").write_text("generated", encoding="utf-8")
    monkeypatch.setattr(security_audit, "PYTEST_TEMP_ROOT", pytest_root)
    monkeypatch.setattr(security_audit, "PYTEST_AUDIT_TEMP_ROOT", tmp_path / ".pytest_tmp_audit")
    monkeypatch.setattr(security_audit, "PYTEST_FALLBACK_TEMP_ROOT", tmp_path / ".pytest_tmp_runs")

    security_audit.prepare_check(_check("detect-secrets"))

    assert not stale_run.exists()


def test_audit_temp_cleanup_rejects_paths_outside_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project_root = tmp_path / "project"
    audit_root = project_root / ".pytest_tmp_audit"
    outside = tmp_path / "outside" / "run-danger"
    outside.mkdir(parents=True)
    (outside / "keep.txt").write_text("do not remove", encoding="utf-8")
    monkeypatch.setattr(security_audit, "PROJECT_ROOT", project_root)
    monkeypatch.setattr(security_audit, "PYTEST_AUDIT_TEMP_ROOT", audit_root)

    assert security_audit.cleanup_audit_temp_path(outside) is False
    assert outside.exists()


def test_stale_security_audit_temp_cleanup_removes_only_safe_direct_children(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    stale = tmp_path / ".pytest_tmp_security_audit_123"
    stale.mkdir()
    (stale / "mongrel.db").write_text("generated", encoding="utf-8")
    unrelated = tmp_path / ".pytest_tmp_security_audit_notes.txt"
    unrelated.write_text("not a directory", encoding="utf-8")
    nested_parent = tmp_path / "nested"
    nested_parent.mkdir()
    nested = nested_parent / ".pytest_tmp_security_audit_456"
    nested.mkdir()
    monkeypatch.setattr(security_audit, "PROJECT_ROOT", tmp_path)

    removed = security_audit.cleanup_stale_security_audit_pytest_roots()

    assert removed == [stale]
    assert not stale.exists()
    assert unrelated.exists()
    assert nested.exists()


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


def test_default_stage_timeouts_keep_detect_secrets_budgeted_at_300_seconds() -> None:
    timeouts = {check.name: check.timeout_seconds for check in security_audit.DEFAULT_CHECKS}

    assert timeouts == {
        "Tests": 180,
        "Bandit": 120,
        "pip-audit": 180,
        "detect-secrets": 300,
    }


def test_default_audit_excludes_semgrep_and_includes_detect_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    tracked_paths = ["app/main.py", "tests/test_security_audit_script.py", "scripts/security_audit.py"]
    monkeypatch.setattr(security_audit, "list_git_tracked_files", lambda: tracked_paths)

    def runner(*args, **kwargs):
        calls.append(args[0])
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    results = security_audit.run_audit(installed=lambda check: True, runner=runner)

    assert [result.check.name for result in results] == ["Tests", "Bandit", "pip-audit", "detect-secrets"]
    assert "Semgrep" not in [result.check.name for result in results]
    assert calls[-1] == [
        "detect-secrets",
        "scan",
        "--exclude-files",
        security_audit.DETECT_SECRETS_EXCLUDE_FILES,
        *tracked_paths,
    ]
    assert "." not in calls[-1]


def test_detect_secrets_excludes_generated_pytest_artifacts_only() -> None:
    detect_secrets_check = next(check for check in security_audit.DEFAULT_CHECKS if check.name == "detect-secrets")

    assert detect_secrets_check.command == [
        "detect-secrets",
        "scan",
        "--exclude-files",
        security_audit.DETECT_SECRETS_EXCLUDE_FILES,
    ]
    excludes = security_audit.DETECT_SECRETS_EXCLUDE_FILES
    assert ".pytest_tmp_security_audit_" in excludes
    assert ".pytest_tmp" in excludes
    assert ".pytest_tmp_audit" in excludes
    assert ".pytest_tmp_runs" in excludes
    assert ".pytest_cache" in excludes
    assert "app" not in excludes
    assert "tests" not in excludes


def test_git_tracked_file_enumeration_uses_safe_explicit_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tracked_paths = [
        "app/main.py",
        "tests/test_example.py",
        "scripts/security_audit.py",
        "docs/usage.md",
        "requirements.txt",
        "data/tracked-fixture.json",
        "artifacts/tracked-sample.txt",
    ]
    untracked_paths = [
        ".venv/lib/site.py",
        "data/runtime.db",
        "uploads/user.bin",
        ".git/objects/aa/bb",
        ".pytest_tmp/run-stale/mongrel.db",
        ".pytest_tmp_audit/run-stale/mongrel.db",
        ".pytest_tmp_runs/run-stale/mongrel.db",
    ]
    for relative_path in [*tracked_paths, *untracked_paths]:
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("content", encoding="utf-8")
    monkeypatch.setattr(security_audit, "PROJECT_ROOT", tmp_path)

    def runner(*args, **kwargs):
        assert args[0] == ["git", "ls-files", "-z"]
        assert kwargs["cwd"] == str(tmp_path)
        assert kwargs["shell"] is False
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout="\0".join(tracked_paths) + "\0",
            stderr="",
        )

    result = security_audit.list_git_tracked_files(runner=runner)

    assert result == tracked_paths
    assert ".venv/lib/site.py" not in result
    assert "data/runtime.db" not in result
    assert "uploads/user.bin" not in result
    assert ".git/objects/aa/bb" not in result
    assert ".pytest_tmp/run-stale/mongrel.db" not in result
    assert ".pytest_tmp_audit/run-stale/mongrel.db" not in result
    assert ".pytest_tmp_runs/run-stale/mongrel.db" not in result


def test_detect_secrets_command_uses_tracked_paths_and_not_dot(monkeypatch: pytest.MonkeyPatch) -> None:
    tracked_paths = [
        "app/service.py",
        "tests/test_service.py",
        "scripts/security_audit.py",
        "docs/security.md",
        "requirements.txt",
    ]
    monkeypatch.setattr(security_audit, "list_git_tracked_files", lambda: tracked_paths)
    calls = []

    def runner(*args, **kwargs):
        calls.append(args[0])
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    detect_secrets_check = next(check for check in security_audit.DEFAULT_CHECKS if check.name == "detect-secrets")
    result = security_audit.run_check(detect_secrets_check, installed=lambda check: True, runner=runner)

    assert result.status == security_audit.STATUS_PASS
    assert calls == [
        [
            "detect-secrets",
            "scan",
            "--exclude-files",
            security_audit.DETECT_SECRETS_EXCLUDE_FILES,
            *tracked_paths,
        ]
    ]
    assert "." not in calls[0]
    assert "app/service.py" in calls[0]
    assert "tests/test_service.py" in calls[0]
    assert "scripts/security_audit.py" in calls[0]
    assert "docs/security.md" in calls[0]
    assert "requirements.txt" in calls[0]
    assert ".venv/lib/site.py" not in calls[0]
    assert "data/runtime.db" not in calls[0]
    assert "uploads/user.bin" not in calls[0]
    assert ".git/objects/aa/bb" not in calls[0]
    assert ".pytest_tmp/run-stale/mongrel.db" not in calls[0]


def test_detect_secrets_git_ls_files_failure_fails_safely(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        security_audit,
        "list_git_tracked_files",
        lambda: (_ for _ in ()).throw(security_audit.GitTrackedFilesError("git ls-files failed")),
    )
    calls = []

    def runner(*args, **kwargs):
        calls.append(args[0])
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    detect_secrets_check = next(check for check in security_audit.DEFAULT_CHECKS if check.name == "detect-secrets")
    result = security_audit.run_check(detect_secrets_check, installed=lambda check: True, runner=runner)

    assert result.status == security_audit.STATUS_FAIL
    assert result.error == "git ls-files failed"
    assert result.returncode is None
    assert calls == []


def test_full_audit_includes_semgrep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(security_audit, "list_git_tracked_files", lambda: ["app/main.py"])

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
