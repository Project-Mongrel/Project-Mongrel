# Agents

Project Mongrel uses agent concepts to separate responsibilities in the investigation workflow. Current agent behavior is limited and grounded in available evidence. Planned agents describe future responsibilities, not current implementation guarantees.

## Current

### Mongrel AI

Provides optional grounded assessment for reports and investigation summaries. Mongrel AI must base its output on supplied findings, scan history, and investigation context.

## Planned

### Scout

Collects reconnaissance evidence from approved tools and authorized targets.

### Findings Analyst

Reviews normalized findings, identifies repeated or changed observations, and supports risk interpretation.

### CVE Intelligence

Adds vulnerability intelligence context to observed services and findings.

### Memory

Maintains historical context across investigations, targets, findings, and reports.

### Report Generator

Assembles deterministic investigation reports from evidence, timeline events, risk analysis, and optional grounded AI assessment.

### Observation Agent

Ingests evidence from tools, uploads, and future integrations into a consistent observation model.

### Attack Path Analysis

Connects observations into plausible attack paths when supported by evidence.

### Orchestrator

Coordinates agent responsibilities, tool execution, user approval, and investigation state.
