# Security Audit

The security audit command provides a repeatable local release check for Project Mongrel. It combines tests, static analysis, dependency vulnerability review, and secret detection into a single command.

## Run

From the project root:

```powershell
python scripts/security_audit.py
```

The default audit is the normal release check.

For a slower deeper scan that includes Semgrep:

```powershell
python scripts/security_audit.py --full
```

## Default Checks

- `pytest`: runs the automated test suite.
- `Bandit`: scans application and script code for common Python security issues.
- `pip-audit`: checks installed Python dependencies for known vulnerabilities.
- `detect-secrets`: scans the repository for likely secrets.

## Optional Deeper Scan

Semgrep is available through `--full`. It runs broader static analysis rules and can take longer than the default release audit.

## Results

- `PASS`: the check ran successfully.
- `FAIL`: the check ran and returned a non-zero exit code. Review the displayed output before release.
- `SKIPPED`: the tool is not installed. Install the tool or explicitly accept the skip according to release policy.

The final summary is `FAIL` if any installed check fails.

## Authorization

External scans and security tools must only target systems owned by the operator or systems where explicit authorization has been granted. Project Mongrel must not be used to assess third-party systems without permission.
