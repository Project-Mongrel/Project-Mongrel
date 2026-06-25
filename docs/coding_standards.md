# Coding Standards

Project Mongrel code should be clear, testable, and safe by default.

## General Standards

- Type hints are preferred for public functions, service boundaries, and structured data.
- Logging is required for meaningful operational events, especially tool execution, timeouts, parser failures, and report generation.
- Every feature should include focused tests.
- SQLite persistence should be used before adding in-memory-only state for user-facing investigation data.
- Commits should be small and focused.

## Security Standards

- Do not use `shell=True`.
- Subprocess commands must use explicit argument lists.
- Validate user-controlled targets before passing them to tools.
- Handle missing tools, timeouts, and subprocess failures without crashing user workflows.
- Security actions require human approval before execution.
- External scanning must only target owned or authorized systems.
- Maintain a security-first mindset when adding integrations, parsers, persistence, and AI features.

## AI Standards

- AI assessment must remain grounded in supplied evidence.
- AI output must not invent findings, targets, or exploitability.
- Reports must remain deterministic when AI is disabled or unavailable.

## Telegram UX Standards

- Telegram workflows should be professional, concise, and predictable.
- Callback flows should avoid dead ends.
- User-facing errors should be actionable.
- Icons should come from the centralized icon helper rather than being scattered through handlers.

## Review Standards

- Prefer explicit behavior over hidden side effects.
- Keep modules focused around their responsibility.
- Avoid unrelated refactors inside feature or security commits.
- Update documentation when architecture, release workflow, or operator behavior changes.
