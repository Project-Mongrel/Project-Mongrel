# Release Checklist

Use this checklist before tagging or publishing a Project Mongrel release.

## Build Verification

- [ ] Application starts locally.
- [ ] Required environment variables are documented.
- [ ] New files required for runtime are included.
- [ ] Generated files are excluded from version control.

## Automated Testing

- [ ] Run `python -m pytest`.
- [ ] Confirm all tests pass.
- [ ] Review warnings for new regressions.

## Security Audit

- [ ] Run `python scripts/security_audit.py`.
- [ ] Confirm audit summary is `PASS`.
- [ ] Run `python scripts/security_audit.py --full` when a deeper Semgrep scan is required.
- [ ] Review any `SKIPPED` tools and decide whether release policy allows them.

## Dependency Review

- [ ] Confirm dependency pins are intentional.
- [ ] Confirm `pip-audit` passes.
- [ ] Review newly added dependencies for maintenance and security posture.

## Secret Verification

- [ ] Confirm `.env` is not committed.
- [ ] Confirm `.env.example` contains placeholders only.
- [ ] Confirm `detect-secrets` passes.
- [ ] Review logs and generated reports for accidental secrets.

## Telegram Smoke Test

- [ ] Start the Telegram bot.
- [ ] Confirm main menu renders correctly.
- [ ] Confirm navigation works without broken callbacks.
- [ ] Confirm user-facing text is professional and concise.

## Investigation Workflow

- [ ] Create an investigation.
- [ ] Add evidence through at least one tool or upload.
- [ ] Confirm timeline events are recorded.
- [ ] Confirm investigation history can be retrieved.

## Nmap

- [ ] Confirm Nmap target normalization works.
- [ ] Confirm dangerous shell characters are rejected.
- [ ] Confirm subprocess execution uses explicit argument lists.
- [ ] Confirm scan results are stored as investigation evidence.

## Nuclei

- [ ] Confirm Nuclei target normalization works.
- [ ] Confirm dangerous shell characters are rejected.
- [ ] Confirm subprocess execution uses explicit argument lists and `shell=False`.
- [ ] Confirm clean scans and findings are stored correctly.

## Uploads

- [ ] Upload supported Nmap XML.
- [ ] Upload supported Nuclei JSONL.
- [ ] Confirm parser errors are handled cleanly.
- [ ] Confirm uploaded findings contribute to investigation evidence.

## Reports

- [ ] Generate a report from an investigation with findings.
- [ ] Generate a report from a clean scan.
- [ ] Confirm timeline and history sections are accurate.
- [ ] Confirm recommendations match observed evidence.

## AI

- [ ] Confirm AI assessment is grounded in supplied evidence.
- [ ] Confirm reports still generate when AI is disabled.
- [ ] Confirm AI failures degrade gracefully.

## Database

- [ ] Confirm SQLite database creation works.
- [ ] Confirm findings persist after connection reload.
- [ ] Confirm investigation history persists after connection reload.
- [ ] Confirm local database files are ignored by git.

## Logging

- [ ] Confirm useful operational events are logged.
- [ ] Confirm logs do not contain secrets.
- [ ] Confirm log files are ignored by git.

## Git

- [ ] Review `git status`.
- [ ] Review changed files for unrelated edits.
- [ ] Confirm generated artifacts are not staged.
- [ ] Commit with a focused message.

## Release Notes

- [ ] Document highlights.
- [ ] Document major changes.
- [ ] Document known limitations.
- [ ] Document future work.

## Release Approval

- [ ] Confirm tests pass.
- [ ] Confirm security audit passes.
- [ ] Confirm documentation is updated.
- [ ] Confirm release owner approval.
