# Architectural Decision Log

This document records significant engineering decisions and the reasoning behind them. It explains why choices were made, not how they were implemented.

## Decision Format

Each decision should include:

- Date
- Decision
- Reason
- Alternatives Considered
- Future Review, if applicable

## 2026-06-25 - Telegram-First User Interface

Decision: Project Mongrel uses Telegram as the primary user interface.

Reason: Telegram provides a lightweight operational interface for guided security workflows without requiring a dedicated dashboard in the MVP.

Alternatives Considered: Web dashboard first, command-line only interface, API-only service.

Future Review: Revisit when dashboard requirements become central to review workflows.

## 2026-06-25 - Investigation-Centric Architecture

Decision: Evidence, timelines, reports, and history are organized around investigations.

Reason: Security assessment work needs context. Investigation records prevent scan outputs from becoming isolated artifacts and support future correlation.

Alternatives Considered: Tool-centric storage, target-centric storage, report-only workflow.

Future Review: Revisit when multi-project or team workflows require additional hierarchy.

## 2026-06-25 - SQLite Persistence for MVP

Decision: Project Mongrel uses SQLite persistence for MVP data storage.

Reason: SQLite keeps the system local, simple to operate, easy to test, and sufficient for the current single-instance investigation workflow.

Alternatives Considered: In-memory storage, PostgreSQL, document database.

Future Review: Revisit if concurrent team usage or hosted deployment becomes a primary requirement.

## 2026-06-25 - Human Approval Before Security Actions

Decision: Security actions require human approval before execution.

Reason: Scanning and assessment actions can have operational and legal impact. The product must keep the operator responsible for authorization.

Alternatives Considered: Fully automated scanning, scheduled execution without approval.

Future Review: Revisit only with explicit policy controls and authorization boundaries.

## 2026-06-25 - Local LLM Using Ollama and Qwen

Decision: AI assessment is designed around a local LLM path using Ollama and Qwen.

Reason: Local inference reduces dependency on external services and keeps assessment evidence closer to the operator environment.

Alternatives Considered: Cloud-only LLM provider, no AI assessment, rule-only assessment.

Future Review: Revisit if deployment models require managed AI providers.

## 2026-06-25 - Deterministic Reports with Optional Grounded AI Assessment

Decision: Reports must remain deterministic, with AI assessment as an optional grounded section.

Reason: Reports are release and review artifacts. They must remain available even when AI is disabled, unavailable, or fails.

Alternatives Considered: AI-generated reports as the primary output, no AI in reports.

Future Review: Revisit if AI reliability and evaluation coverage improve enough to expand its role.

## 2026-06-25 - Security Audit Pipeline Before Major Features

Decision: Project Mongrel includes a local security audit pipeline before adding major new features.

Reason: The platform executes security tooling and handles sensitive evidence. Release discipline must include tests, static analysis, dependency review, and secret checks.

Alternatives Considered: Manual review only, CI-only security checks, deferred hardening.

Future Review: Revisit when CI integration is added.

## 2026-06-25 - Centralized Icon Helper

Decision: Telegram icon usage should be centralized.

Reason: Centralized icons keep the user interface consistent and reduce scattered presentation decisions across handlers.

Alternatives Considered: Inline icons in each handler, no icons.

Future Review: Revisit if a broader design system replaces the helper.

## 2026-06-25 - Observation Agent as Universal Evidence Ingestion Layer

Decision: The Observation Agent is the planned universal evidence ingestion layer.

Reason: Future tools and uploads need a consistent way to become investigation evidence. A universal ingestion layer supports correlation and attack path analysis.

Alternatives Considered: Separate ingestion logic per tool, report-time normalization only.

Future Review: Revisit during Observation Agent implementation.

## 2026-06-25 - Modular Tool Architecture

Decision: Tool integrations are modular, including Nmap, Nuclei, BBOT, and future integrations.

Reason: Security tools have different execution models and output formats. Modular integrations limit blast radius and keep tool-specific behavior isolated.

Alternatives Considered: Single scanner abstraction for all tools, external orchestration only.

Future Review: Revisit as shared observation schemas mature.

## 2026-06-25 - AI Must Remain Grounded in Supplied Evidence

Decision: AI output must be grounded in supplied findings, scan history, and investigation context.

Reason: Unsupported AI conclusions would reduce trust and create review risk. Grounding keeps AI useful while preserving evidence integrity.

Alternatives Considered: Open-ended AI analysis, no AI output.

Future Review: Revisit as evaluation and guardrail coverage improves.

## 2026-06-25 - Professional Documentation Maintained Alongside Code

Decision: Documentation is maintained in the repository alongside code.

Reason: Architecture, release process, decisions, and operational standards need to evolve with implementation changes.

Alternatives Considered: External wiki, release notes only, code comments only.

Future Review: Revisit if project governance moves to a dedicated documentation site.
