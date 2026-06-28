# Setup

Project Mongrel supports Windows development and Linux deployment from the same `requirements.txt`.

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
```

BBOT scan execution should run in a Linux-compatible runtime such as Linux, Kali, or WSL. Windows development remains supported, but BBOT scan modes that import Linux-only modules may not run directly in native Windows Python.

## Verification

Run:

```bash
python -m pytest
python scripts/security_audit.py
```
