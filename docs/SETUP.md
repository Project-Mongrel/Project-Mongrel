# Setup

Project Mongrel supports Windows development and Linux deployment from the same runtime/test `requirements.txt`.

## Python Environment

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\activate
```

Activate it on Linux or macOS:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
python -m pip check
```

`requirements.txt` is the supported Mongrel app/test/default-audit environment. It intentionally does not install Semgrep or the BBOT Python package because current BBOT and Semgrep releases require dependency ranges that cannot share one valid, audit-clean Python environment.

## Optional Semgrep Audit Environment

For the slower full audit, install Semgrep into a separate virtual environment:

```bash
python -m venv .venv-semgrep
.venv-semgrep\Scripts\activate
python -m pip install -r requirements-semgrep.txt
semgrep scan --config auto
```

On Linux/macOS:

```bash
python -m venv .venv-semgrep
source .venv-semgrep/bin/activate
python -m pip install -r requirements-semgrep.txt
semgrep scan --config auto
```

## Platform-Specific Dependencies

Windows-only packages use environment markers in `requirements.txt`. For example:

```text
pywin32==311; platform_system=="Windows"
```

Pip installs those packages on Windows and skips them on Linux/macOS. Do not remove the marker when updating dependency pins, or Linux installation will fail.

## Linux Deployment Notes

Linux deployments should use the same install command:

```bash
python -m pip install -r requirements.txt
python -m pip check
```

BBOT scan execution should run as an external tool in a Linux-compatible runtime such as Linux, Kali, or WSL. Install the BBOT CLI outside the Mongrel app virtual environment, for example with `pipx install bbot` or in a tool-specific environment, and set `BBOT_BINARY` if it is not on `PATH`.

Recommended VPS model:

```bash
python -m pip install -r requirements.txt
python -m pip check
pipx install bbot
export BBOT_BINARY="$HOME/.local/bin/bbot"
```

Mongrel passes only validated BBOT presets/modules/config values. Do not put BBOT, Semgrep, or their conflicting Python dependency trees into the Mongrel app venv.

Windows development remains supported, but BBOT scan modes that import Linux-only modules may not run directly in native Windows Python.

## ffuf Wordlist

Mongrel ships `app/resources/wordlists/ffuf_default.txt` as the Quick profile wordlist. It is a small smoke-test/minimal fallback list. For competition or production deployments, configure vetted external wordlists that fit the authorized scope and timeout budget:

- `FFUF_WORDLIST_STANDARD_PATH`: medium normal-assessment list, approximately 2,000-5,000 entries.
- `FFUF_WORDLIST_DEEP_PATH`: broader list, approximately 20,000 entries.
- `FFUF_WORDLIST_PATH`: custom profile path, preserving the existing override behavior.

Example SecLists candidates include `Discovery/Web-Content/directory-list-2.3-small.txt` for Standard and a bounded raft/directory list for Deep.

Do not rely on the bundled fallback for meaningful hidden-content discovery.

## Verification

Run:

```bash
python -m pytest
python scripts/security_audit.py
```
