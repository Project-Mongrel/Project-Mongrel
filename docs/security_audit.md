# Security Audit

Project Mongrel includes a local security audit command for release checks. The
default audit is the normal release check and avoids slower Semgrep scans.

## Install Tools

The audit runs installed tools and skips missing tools cleanly.

```powershell
.venv\Scripts\python -m pip install pytest bandit pip-audit detect-secrets
.venv\Scripts\python -m pip install semgrep
```

`gitleaks` is optional and is installed separately from the project. See the
official gitleaks releases for platform-specific installation instructions.

## Run Audit

From the project root:

```powershell
.venv\Scripts\python scripts\security_audit.py
```

Run the slower full audit when you explicitly want Semgrep included:

```powershell
.venv\Scripts\python scripts\security_audit.py --full
```

## Checks

- `pytest`: runs the automated test suite with `python -m pytest --basetemp .pytest_tmp`.
- `bandit`: scans `app` and `scripts` for common insecure coding patterns.
- `pip-audit`: checks installed Python dependencies for known vulnerabilities.
- `detect-secrets`: scans for likely secrets when installed.
- `semgrep`: runs Semgrep's automatic rules with `semgrep scan --config auto`
  only when `--full` is passed.

Each check has a timeout so the audit does not hang indefinitely:

- `pytest`: 180 seconds.
- `bandit`: 120 seconds.
- `pip-audit`: 180 seconds.
- `detect-secrets`: 120 seconds.
- `semgrep`: 180 seconds in `--full` mode.

## Results

- `PASS`: the tool ran and returned a successful exit code.
- `FAIL`: the tool ran and returned a non-zero exit code. Review the displayed
  output or error text before release.
- `SKIPPED`: the tool was not installed. Install the tool from the shown hint if
  the check is required for the release.

The final summary is `FAIL` if any installed check fails. Missing tools are
reported as `SKIPPED` and do not crash the audit command.

## Authorization

External scanning must only be run against systems you own or have explicit
authorization to assess. Do not use Project Mongrel security tooling against
third-party systems without written permission.
