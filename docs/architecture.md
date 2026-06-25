# Architecture

Project Mongrel is organized around investigations. Each user action, tool result, upload, comparison, AI assessment, and report contributes evidence to an investigation record that can be reviewed over time.

## Current Flow

Telegram

Bot Handlers

Investigation Layer

SQLite Persistence

Security Tools

- Nmap
- Nuclei
- Upload Parsers

Risk Engine

Comparison Engine

Mongrel AI

Reports

Timeline

History

## Component Responsibilities

Telegram is the primary user interface. It provides a guided operational workflow for starting investigations, running authorized scans, uploading findings, reviewing results, and generating reports.

Bot handlers translate Telegram interactions into application actions. They are responsible for user flow, callback handling, input collection, and response formatting.

The investigation layer groups evidence and actions into coherent assessment records. It provides the context needed for timelines, report generation, and future correlation.

SQLite persistence stores findings, investigation metadata, events, report metadata, and scan history. The MVP uses SQLite to keep the system local, auditable, and easy to operate.

Security tools provide evidence. Nmap contributes network and service observations. Nuclei contributes template-based exposure and misconfiguration findings. Upload parsers allow external scan outputs to enter the investigation workflow.

The risk engine normalizes findings into practical risk signals. It supports consistent severity handling and recommendation generation.

The comparison engine detects repeated, changed, or newly observed findings across scan history. It supports investigation continuity and avoids treating every scan as isolated.

Mongrel AI provides optional grounded assessment. AI output must be based on supplied findings, scan history, and investigation context rather than unsupported assumptions.

Reports summarize investigation evidence, risk, recommendations, AI assessment when available, timeline context, and history.

Timeline and history preserve the sequence of events and allow reviewers to understand how an investigation evolved.

## Extension Points

- BBOT integration for broader reconnaissance evidence.
- Observation Agent for universal evidence ingestion across tools and uploads.
- Attack Path Analysis for connecting observations into likely exploit paths.
- Dashboard for non-Telegram review and operational visibility.
- PDF Export for formal deliverables.
