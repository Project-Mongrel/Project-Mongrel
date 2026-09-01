# Telegram assessment conversation routing

Telegram uses `assessment_chat_state` as the single authoritative in-memory marker for assessment-conversation mode. The state contains the user-scoped assessment ID and persistent conversation ID; conversation turns themselves live in SQLite and therefore survive bot restarts. Re-entering Ask Mongrel from an assessment resumes that user's latest active conversation for the assessment.

Text routing precedence is:

1. Active scan, scan-recovery, and approval input (`pending_nmap_scan_request_id`), including guided Metasploit input.
2. Finding Analysis mode.
3. Assessment creation input.
4. Assessment-scoped Ask Mongrel conversation mode.
5. Generic Ask Mongrel mode.
6. Main-menu/no-op handling.

Callback and document handlers remain separate from text routing. TShark approval/capture and upload operations continue through their existing callbacks and document handler, and assessment Ask Mongrel does not initiate any scanner, validation, capture, or approval action.

Opening, resuming, reading, or appending an assessment conversation requires both the Telegram user ID and assessment ownership. Each user turn is saved before AI is called. Each assistant turn is then saved with evidence references, the evidence-context digest, and provenance metadata before it is sent to Telegram. System prompts are never persisted.
