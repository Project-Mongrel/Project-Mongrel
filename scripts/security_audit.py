from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import shutil
# Required to run local audit tools with explicit arg lists.
import subprocess  # nosec B404
import sys
import time
from dataclasses import dataclass
from typing import Callable, Sequence
from uuid import uuid4


# Audit status label, not a password.
STATUS_PASS = "PASS"  # nosec B105
STATUS_FAIL = "FAIL"
STATUS_SKIPPED = "SKIPPED"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
PYTEST_TEMP_ROOT = PROJECT_ROOT / ".pytest_tmp"
PYTEST_AUDIT_TEMP_ROOT = PROJECT_ROOT / ".pytest_tmp_audit"
PYTEST_FALLBACK_TEMP_ROOT = PROJECT_ROOT / ".pytest_tmp_runs"
PYTEST_AUDIT_STALE_PREFIX = ".pytest_tmp_security_audit_"
PYTEST_TEMP_ROOT_ENV = "MONGREL_PYTEST_TEMP_ROOT"
PYTEST_TEMP_STALE_SECONDS = 24 * 60 * 60
DETECT_SECRETS_EXCLUDE_FILES = r"(^|/)(?:\.pytest_tmp(?:/|$)|\.pytest_tmp_audit(?:/|$)|\.pytest_tmp_runs(?:/|$)|\.pytest_cache(?:/|$)|\.pytest_tmp_security_audit_[^/]*(?:/|$))"


@dataclass(frozen=True)
class AuditCheck:
    name: str
    command: list[str]
    install_hint: str
    timeout_seconds: int
    required: bool = True
    module_name: str | None = None
    executable_name: str | None = None


@dataclass(frozen=True)
class AuditResult:
    check: AuditCheck
    status: str
    output: str = ""
    error: str = ""
    returncode: int | None = None


class GitTrackedFilesError(RuntimeError):
    """Raised when tracked source enumeration cannot be completed safely."""


DEFAULT_CHECKS = [
    AuditCheck(
        name="Tests",
        command=[sys.executable, "-m", "pytest"],
        module_name="pytest",
        install_hint="Install with: python -m pip install pytest",
        timeout_seconds=180,
    ),
    AuditCheck(
        name="Bandit",
        command=[sys.executable, "-m", "bandit", "-r", "app", "scripts"],
        module_name="bandit",
        install_hint="Install with: python -m pip install bandit",
        timeout_seconds=120,
    ),
    AuditCheck(
        name="pip-audit",
        command=[sys.executable, "-m", "pip_audit"],
        module_name="pip_audit",
        install_hint="Install with: python -m pip install pip-audit",
        timeout_seconds=180,
    ),
    AuditCheck(
        name="detect-secrets",
        command=["detect-secrets", "scan", "--exclude-files", DETECT_SECRETS_EXCLUDE_FILES],
        executable_name="detect-secrets",
        install_hint="Install with: python -m pip install detect-secrets",
        timeout_seconds=120,
    ),
]

SEMGREP_CHECK = AuditCheck(
    name="Semgrep",
    command=["semgrep", "scan", "--config", "auto"],
    executable_name="semgrep",
    install_hint="Install in a separate Semgrep audit environment with: python -m pip install -r requirements-semgrep.txt",
    timeout_seconds=180,
)

REQUIRED_CHECKS = DEFAULT_CHECKS


def is_tool_installed(check: AuditCheck) -> bool:
    if check.module_name:
        return importlib.util.find_spec(check.module_name) is not None
    if check.executable_name:
        return shutil.which(check.executable_name) is not None
    return False


def prepare_check(check: AuditCheck) -> None:
    if check.name == "Tests":
        PYTEST_AUDIT_TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        cleanup_stale_security_audit_pytest_roots()
    elif check.name == "detect-secrets":
        cleanup_generated_pytest_run_roots()


def build_pytest_audit_basetemp() -> Path:
    return PYTEST_AUDIT_TEMP_ROOT / f"run-{os.getpid()}-{time.time_ns()}-{uuid4().hex[:8]}"


def command_for_check(
    check: AuditCheck,
    basetemp: Path | None = None,
    tracked_paths: Sequence[str] | None = None,
) -> list[str]:
    if check.name == "detect-secrets" and tracked_paths is not None:
        return [*check.command, *tracked_paths]
    if check.name != "Tests":
        return list(check.command)
    selected_basetemp = basetemp or build_pytest_audit_basetemp()
    return [*check.command, "--basetemp", str(selected_basetemp)]


def list_git_tracked_files(
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[str]:
    """Return safe repo-relative Git-tracked file paths for source auditing."""
    command = ["git", "ls-files", "-z"]
    try:
        completed = runner(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            cwd=str(PROJECT_ROOT),
            check=False,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise GitTrackedFilesError("Unable to enumerate Git-tracked files: git is not installed.") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitTrackedFilesError("Unable to enumerate Git-tracked files: git ls-files timed out.") from exc
    except UnicodeDecodeError as exc:
        raise GitTrackedFilesError(f"Unable to enumerate Git-tracked files: {exc}") from exc

    if completed.returncode != 0:
        error = (completed.stderr or completed.stdout or "").strip()
        detail = f": {error}" if error else "."
        raise GitTrackedFilesError(f"Unable to enumerate Git-tracked files{detail}")

    tracked_paths: list[str] = []
    root = PROJECT_ROOT.resolve()
    for raw_path in completed.stdout.split("\0"):
        path_text = raw_path
        if not path_text:
            continue
        relative_path = Path(path_text)
        if relative_path.is_absolute():
            raise GitTrackedFilesError("Unable to enumerate Git-tracked files: absolute path returned by git.")
        candidate = (PROJECT_ROOT / relative_path).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise GitTrackedFilesError("Unable to enumerate Git-tracked files: path escapes project root.") from exc
        if not candidate.is_file():
            continue
        tracked_paths.append(path_text)

    if not tracked_paths:
        raise GitTrackedFilesError("Unable to enumerate Git-tracked files: no tracked files found.")
    return tracked_paths


def cleanup_audit_temp_path(path: Path) -> bool:
    if not _is_safe_audit_temp_path(path):
        return False
    shutil.rmtree(path, ignore_errors=True)
    return True


def cleanup_stale_security_audit_pytest_roots() -> list[Path]:
    removed: list[Path] = []
    try:
        children = list(PROJECT_ROOT.iterdir())
    except OSError:
        return removed
    for child in children:
        if not _is_safe_stale_security_audit_root(child):
            continue
        shutil.rmtree(child, ignore_errors=True)
        removed.append(child)
    return removed


def cleanup_generated_pytest_run_roots(active_basetemp: Path | None = None) -> list[Path]:
    """Remove generated pytest run roots before recursive source audits.

    The cleanup is intentionally limited to direct ``run-*`` children of the
    known repo-local pytest temp roots.  It skips the current audit basetemp
    and recent run directories whose embedded PID is still alive.  Age bounds
    liveness so reused or unrelated PIDs cannot preserve stale roots forever.
    """
    removed: list[Path] = []
    for root in (PYTEST_TEMP_ROOT, PYTEST_AUDIT_TEMP_ROOT, PYTEST_FALLBACK_TEMP_ROOT):
        removed.extend(_cleanup_generated_pytest_run_root(root, active_basetemp=active_basetemp))
    return removed


def _cleanup_generated_pytest_run_root(root: Path, active_basetemp: Path | None = None) -> list[Path]:
    removed: list[Path] = []
    try:
        children = list(root.iterdir())
    except OSError:
        return removed
    for child in children:
        if not _is_safe_generated_pytest_run_path(child, root, active_basetemp=active_basetemp):
            continue
        if _run_path_pid_is_alive(child) and not _run_path_is_stale(child):
            continue
        shutil.rmtree(child, ignore_errors=True)
        removed.append(child)
    return removed


def _is_safe_audit_temp_path(path: Path) -> bool:
    try:
        resolved = path.resolve()
        root = PROJECT_ROOT.resolve()
        audit_root = PYTEST_AUDIT_TEMP_ROOT.resolve()
    except OSError:
        return False
    if not resolved.is_dir():
        return False
    if resolved.parent != audit_root:
        return False
    if not resolved.name.startswith("run-"):
        return False
    try:
        resolved.relative_to(root)
    except ValueError:
        return False
    return True


def _is_safe_generated_pytest_run_path(
    path: Path,
    expected_root: Path,
    active_basetemp: Path | None = None,
) -> bool:
    try:
        resolved = path.resolve()
        resolved_root = expected_root.resolve()
    except OSError:
        return False
    if active_basetemp is not None:
        try:
            if resolved == active_basetemp.resolve():
                return False
        except OSError:
            return False
    if path.is_symlink():
        return False
    if not path.is_dir():
        return False
    if path.parent.resolve() != resolved_root:
        return False
    if resolved.parent != resolved_root:
        return False
    if not path.name.startswith("run-"):
        return False
    return True


def _run_path_pid_is_alive(path: Path) -> bool:
    pid = _parse_run_path_pid(path.name)
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _run_path_is_stale(path: Path) -> bool:
    try:
        return path.stat().st_mtime <= time.time() - PYTEST_TEMP_STALE_SECONDS
    except OSError:
        return False


def _parse_run_path_pid(name: str) -> int | None:
    parts = name.split("-", 2)
    if len(parts) < 3:
        return None
    if parts[0] != "run" or not parts[1].isdigit():
        return None
    pid = int(parts[1])
    if pid <= 0:
        return None
    return pid


def _is_safe_stale_security_audit_root(path: Path) -> bool:
    try:
        resolved = path.resolve()
        root = PROJECT_ROOT.resolve()
    except OSError:
        return False
    if resolved.parent != root:
        return False
    if path.name != resolved.name:
        return False
    if not path.name.startswith(PYTEST_AUDIT_STALE_PREFIX):
        return False
    return resolved.is_dir()


def run_check(
    check: AuditCheck,
    installed: Callable[[AuditCheck], bool] = is_tool_installed,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> AuditResult:
    if not installed(check):
        return AuditResult(check=check, status=STATUS_SKIPPED, error=check.install_hint)

    prepare_check(check)
    pytest_basetemp = build_pytest_audit_basetemp() if check.name == "Tests" else None
    try:
        tracked_paths = list_git_tracked_files() if check.name == "detect-secrets" else None
        command = command_for_check(check, pytest_basetemp, tracked_paths=tracked_paths)
    except GitTrackedFilesError as exc:
        return AuditResult(check=check, status=STATUS_FAIL, error=str(exc), returncode=None)

    try:
        env = os.environ.copy()
        if check.name == "Tests" and pytest_basetemp is not None:
            env[PYTEST_TEMP_ROOT_ENV] = str(pytest_basetemp / "nested-pytest")
        completed = runner(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=check.timeout_seconds,
            cwd=str(PROJECT_ROOT),
            env=env,
            check=False,
            shell=False,
        )
    except FileNotFoundError:
        return AuditResult(check=check, status=STATUS_SKIPPED, error=check.install_hint)
    except subprocess.TimeoutExpired as exc:
        output = _decode_timeout_output(exc.stdout)
        error = _decode_timeout_output(exc.stderr) or f"{check.name} timed out after {check.timeout_seconds}s."
        return AuditResult(
            check=check,
            status=STATUS_FAIL,
            output=output,
            error=error,
            returncode=None,
        )
    except UnicodeDecodeError as exc:
        return AuditResult(
            check=check,
            status=STATUS_FAIL,
            error=f"Unable to decode subprocess output: {exc}",
            returncode=None,
        )
    finally:
        if pytest_basetemp is not None:
            cleanup_audit_temp_path(pytest_basetemp)

    status = STATUS_PASS if completed.returncode == 0 else STATUS_FAIL
    return AuditResult(
        check=check,
        status=status,
        output=completed.stdout or "",
        error=completed.stderr or "",
        returncode=completed.returncode,
    )


def _decode_timeout_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def run_audit(
    checks: Sequence[AuditCheck] = DEFAULT_CHECKS,
    include_semgrep: bool = False,
    installed: Callable[[AuditCheck], bool] = is_tool_installed,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[AuditResult]:
    audit_checks = list(checks)
    if include_semgrep:
        audit_checks.append(SEMGREP_CHECK)
    results = [run_check(check, installed=installed, runner=runner) for check in audit_checks]
    return results


def audit_passed(results: Sequence[AuditResult]) -> bool:
    return all(result.status != STATUS_FAIL for result in results)


def _print_failure_output(result: AuditResult) -> None:
    if result.returncode is not None:
        print(f"Exit code: {result.returncode}")
    if result.output.strip():
        print("Output:")
        print(result.output.rstrip())
    if result.error.strip():
        print("Error:")
        print(result.error.rstrip())


def print_report(results: Sequence[AuditResult], required_count: int | None = None) -> None:
    print("Project Mongrel Security Audit")
    print()

    required_results = [result for result in results if result.check.required]
    required_count = required_count or len(required_results)

    for index, result in enumerate(required_results, start=1):
        print(f"[{index}/{required_count}] {result.check.name}")
        print(f"Status: {result.status}")
        if result.status == STATUS_SKIPPED:
            print(result.error)
        elif result.status == STATUS_FAIL:
            _print_failure_output(result)
        print()

    print("Summary:")
    print(STATUS_PASS if audit_passed(results) else STATUS_FAIL)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Project Mongrel security audit.")
    parser.add_argument(
        "--full",
        action="store_true",
        help="Include slower deep checks such as Semgrep.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    results = run_audit(include_semgrep=args.full)
    print_report(results)
    return 0 if audit_passed(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
