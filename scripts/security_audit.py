from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import shutil
# Required to run local audit tools with explicit arg lists.
import subprocess  # nosec B404
import sys
from dataclasses import dataclass
from typing import Callable, Sequence


# Audit status label, not a password.
STATUS_PASS = "PASS"  # nosec B105
STATUS_FAIL = "FAIL"
STATUS_SKIPPED = "SKIPPED"
PYTEST_BASETEMP = f".pytest_tmp_security_audit_{os.getpid()}"


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


DEFAULT_CHECKS = [
    AuditCheck(
        name="Tests",
        command=[sys.executable, "-m", "pytest", "--basetemp", PYTEST_BASETEMP],
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
        command=["detect-secrets", "scan"],
        executable_name="detect-secrets",
        install_hint="Install with: python -m pip install detect-secrets",
        timeout_seconds=120,
    ),
]

SEMGREP_CHECK = AuditCheck(
    name="Semgrep",
    command=["semgrep", "scan", "--config", "auto"],
    executable_name="semgrep",
    install_hint="Install with: python -m pip install semgrep",
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
        Path(PYTEST_BASETEMP).mkdir(exist_ok=True)


def run_check(
    check: AuditCheck,
    installed: Callable[[AuditCheck], bool] = is_tool_installed,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> AuditResult:
    if not installed(check):
        return AuditResult(check=check, status=STATUS_SKIPPED, error=check.install_hint)

    prepare_check(check)

    try:
        completed = runner(
            check.command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=check.timeout_seconds,
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
