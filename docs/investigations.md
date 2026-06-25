# Investigations

Investigations are the central organizing model in Project Mongrel. They group evidence, actions, timeline events, reports, and history into a single reviewable workflow.

## Model

Investigation

Events

Timeline

Reports

History

Future Correlation

## Purpose

An investigation represents an authorized assessment workflow. Every tool and upload contributes evidence to the investigation so reviewers can understand what was observed, when it was observed, and how it changed over time.

Events capture actions and notable changes. Timeline views present those events in sequence. Reports summarize the current evidence and recommendations. History preserves previous observations so repeated, new, changed, and resolved findings can be identified.

## Evidence Sources

Current evidence sources include Nmap results, Nuclei results, and uploaded scan outputs. Future sources should follow the same model: contribute evidence to an investigation rather than operating as isolated tool output.

## Future Correlation

The Observation Agent is planned as a universal evidence ingestion layer. It should normalize observations from tools, uploads, and future integrations so correlation, attack path analysis, and trend reporting can operate over a consistent evidence model.
