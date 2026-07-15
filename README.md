# Project Mongrel

A Telegram-first AI Security Assistant built for the Wittgenstein AI Tournament.

Project Mongrel combines multiple specialist security agents under a single orchestrator to help defenders analyze findings, run authorized scans, prioritize risk, track historical changes, and generate professional reports.

---

# Vision

Most security tools generate data.

Mongrel generates understanding.

The goal is to give defenders a practical AI-powered assistant that can:

- Run authorized security scans
- Analyze findings
- Prioritize risk
- Explain vulnerabilities
- Track changes over time
- Generate professional reports

All from a simple Telegram interface.

---

# Core Architecture

```

Telegram UI
↓
Mongrel Orchestrator
↓
├── Scout Agent
├── Analyst Agent
├── Hunter Agent
├── Intel Agent
├── Memory Agent
├── Scribe Agent
├── Reviewer Agent
└── Report Agent

↓
Tools Layer
├── Nmap
├── Nuclei
├── BBOT
├── Log Analysis
├── File Parsers
└── Report Generation

↓
Local Open Source LLM

```

---

# Agent Ecosystem

## Scout

Reconnaissance and asset discovery.

Responsibilities:

- Nmap execution
- Host discovery
- Port analysis
- Service enumeration

---

## Analyst

Security findings interpretation.

Responsibilities:

- Vulnerability analysis
- Risk prioritization
- Impact explanation
- Remediation suggestions

---

## Hunter

Log and IOC analysis.

Responsibilities:

- Suspicious activity detection
- IOC extraction
- Threat hunting support

---

## Intel

Threat intelligence assistant.

Responsibilities:

- CVE research
- Exploit context
- Threat actor context
- Security recommendations

---

## Memory

Historical project memory.

Responsibilities:

- Scan history
- Previous findings
- Delta comparison
- Project knowledge retention

---

## Scribe

Professional reporting.

Responsibilities:

- Executive summaries
- Technical reports
- Markdown export
- PDF export

---

## Reviewer

Validation and quality control.

Responsibilities:

- Cross-check findings
- Reduce hallucinations
- Improve report accuracy

---

## Mongrel Orchestrator

The central brain.

Responsibilities:

- Route requests
- Coordinate agents
- Aggregate results
- Present final answers

---

# Planned Features

## Phase 1 (Tournament MVP)

- [ ] Telegram control panel
- [ ] Upload scan files
- [ ] Nmap integration
- [ ] Nuclei integration
- [ ] BBOT integration
- [ ] AI findings analysis
- [ ] Historical memory
- [ ] Report generation

---

## Phase 2

- [ ] Multi-project support
- [ ] Scheduled scans
- [ ] Team collaboration
- [ ] Dashboard UI

---

## Phase 3

- [ ] Continuous monitoring
- [ ] Cloud assessment
- [ ] Code review
- [ ] AI-assisted remediation plans

---

# Technology Stack

## Backend

- Python
- FastAPI

## AI

- Open-source LLM
- Ollama

## Messaging

- Telegram Bot API

## Database

- SQLite (MVP)
- PostgreSQL (future)

## Security Tools

- Nmap
- Nuclei
- BBOT

---

# Project Structure

```

app/
├── agents/
├── bot/
├── core/
├── db/
├── memory/
├── models/
├── parsers/
├── reports/
├── services/
└── tools/

tests/
docs/
scripts/
data/
logs/

```

---

# Setup

Create virtual environment:

```bash
python -m venv .venv
```

Activate:

```bash
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
python -m pip check
```

Use `requirements.txt` for the main Mongrel app/test/default-audit environment. Install Semgrep from `requirements-semgrep.txt` only in a separate optional audit virtual environment, and install the BBOT CLI outside the Mongrel app venv, because current BBOT and Semgrep dependency ranges cannot share one valid, audit-clean environment.

Run tests:

```bash
pytest
```

---

# Competition Goal

Build a practical AI-powered security assistant that demonstrates:

- Technical quality
- Real-world usefulness
- Strong engineering practices
- Effective AI integration
- Professional presentation

---

# Status

Current Phase:

Planning & Foundation

Repository:

https://github.com/FuzzyDuckLabs/Project-Mongrel
