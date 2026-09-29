# Project Mongrel

Project Mongrel is an evidence-first AI security assessment assistant with a Telegram interface. It runs bounded security-tool workflows, preserves normalized evidence and provenance, and helps a human interpret what the evidence does—and does not—establish.

Mongrel is deliberately uncertainty-honest. A completed scan is not proof that a target is secure, a scanner match is not automatically an exploitable vulnerability, and tool execution is not proof of compromise.

> **Authorized use only:** scan only systems you own or have explicit permission to assess. You are responsible for scope, authorization, and the impact of every tool you choose to run.

## Try the Competition Bot

The competition bot is **[@Project_Mongrel_Bot](https://t.me/Project_Mongrel_Bot)**.

1. If you do not already have Telegram, install the official [mobile app](https://telegram.org/apps) or [desktop app](https://desktop.telegram.org/), or use [Telegram Web](https://web.telegram.org/) in your browser.
2. Sign in or create a Telegram account.
3. Search for the exact username `@Project_Mongrel_Bot`.
4. Open the bot and press **Start**, or send `/start`.
5. Use only a target you own or are explicitly authorized to test.

Telegram Desktop is particularly convenient for reviewing longer scan results and reports.

Competition-bot access requires no local installation. The [Self-hosting](#self-hosting) instructions are separate and are only for operators deploying their own Mongrel instance.

## More Than a Tool Wrapper

Mongrel began as a Telegram security-tool orchestrator and evolved into an evidence-driven assessment platform. It coordinates 12 security tools through dedicated runners and parsers, normalizes their output, and persists assessment state and lifecycle in SQLite. Telegram provides the operational UX, while specialist AI, Assessment-scoped Ask Mongrel, and Standalone/Generic Ask Mongrel interpret different kinds of context without pretending that a conversation is evidence.

The platform also includes a cross-tool assessment map, provenance linking, encrypted Evidence Vault storage for sensitive Gitleaks evidence, review and approval workflows, deterministic and reporting guardrails, and explicit uncertainty. Conclusions stay tied to persisted evidence rather than to tool names, model confidence, or a completed process.

The locked competition toolset is exactly:

**Nmap, BBOT, Nuclei, httpx, Playwright, Katana, ffuf, testssl.sh, Gitleaks, Prowler, Metasploit, and TShark.**

## How to Use Project Mongrel

1. Find and open **@Project_Mongrel_Bot** in Telegram.
2. Press **Start** or send `/start`.
3. Use the home screen to choose between a new assessment, a standalone question, previous assessments, and other supported workflows.
4. Choose **New Assessment** to enter Assessment Mode, name the assessment, and provide an authorized target.
5. Run tools from the assessment dashboard. Review each result, its stored evidence, and its limitations before choosing the next action.
6. Use **Ask Mongrel about this assessment** for questions grounded in that assessment's authorized persisted evidence.
7. Use the home-screen **Ask Mongrel** for general cybersecurity questions and Mongrel capability guidance. It does not inherit assessment evidence or run tools from chat text.
8. Open **Previous Assessments** to return to active, partial, interrupted, or completed workspaces.
9. Use the assessment **Dashboard**, **AI Report**, and **Markdown Report** to review lifecycle state, evidence, interpretation, recommendations, and limitations.
10. Use Telegram navigation buttons to return to the dashboard, history, reports, or Ask Mongrel. Telegram Desktop can be especially convenient for reviewing longer scan results and reports.

## Which mode should I use?

| Goal | Use | What it does |
|---|---|---|
| Collect evidence for one authorized target over time | **Assessment Mode** | Creates a persistent workspace with target, tool state, normalized evidence, provenance, history, and reports. |
| Ask what a stored assessment established | **Assessment Ask Mongrel** | Answers from that assessment's authorized persisted evidence and explains what remains uncertain. |
| Ask a general cybersecurity or Mongrel capability question | **Standalone Ask Mongrel** | Provides bounded general guidance without assessment findings and without executing tools. |
| Return to earlier work | **Previous Assessments / History** | Reopens stored assessments and their scan history without automatically rerunning tools. |
| Review results and generate deliverables | **Dashboard / Report** | Shows assessment state and evidence-backed AI or deterministic Markdown reporting with limitations. |

## A 60-second first assessment

1. Select **New Assessment** to enter Assessment Mode.
2. Name the assessment and enter an authorized target when prompted.
3. Choose a tool from the 12-tool assessment dashboard—for a quick demo, start with **Nmap Scan**.
4. Inspect the deterministic result and its evidence limitations.
5. Select **Ask Mongrel about this assessment** for evidence-grounded questions and next-step guidance.
6. Generate an **AI Report** or **Markdown Report** from the Assessment Dashboard.
7. Return later through **Previous Assessments** to reopen the stored workspace, history, reports, and assessment-scoped conversation.

Tools do not run merely because a menu is opened. Active workflows retain their confirmation, authorization, and approval boundaries.

## Product modes

### Tool Mode

Select **Scan** from the home keyboard for direct, single-tool use. Results receive specialist interpretation and Tool Mode continuation controls. Tool Mode does not create an assessment-scoped evidence workspace.

### Assessment Mode

Select **New Assessment** for a persistent workspace containing its target, authoritative scan states, normalized evidence, history, reports, and assessment-specific navigation.

### Ask Mongrel

- **Assessment-scoped Ask Mongrel** is persistent and reasons from evidence stored for that assessment. It does not execute tools from chat text.
- The home-screen **Ask Mongrel** is a separate, session-only general cybersecurity conversation. It does not inherit assessment evidence.

### Previous Assessments

**Previous Assessments** reopens active, partial, interrupted, or completed assessment workspaces without automatically rerunning tools.

## The canonical 12 tools

Mongrel exposes exactly these 12 competition tools:

| Tool | Evidence-oriented purpose |
|---|---|
| Nmap | Host, port, and service discovery |
| BBOT | Reconnaissance and asset discovery |
| Nuclei | Template-based exposure and vulnerability checks |
| httpx | HTTP/HTTPS response probing and characterization |
| Playwright | Passive browser and rendered-page observation |
| Katana | Web crawling and endpoint discovery |
| ffuf | Bounded fuzzing and content discovery at configured `FUZZ` positions |
| testssl.sh | TLS protocol, cipher, and certificate assessment |
| Gitleaks | Secret-pattern detection in authorized repositories or files |
| Prowler | Provider-specific cloud configuration checks |
| Metasploit | Controlled validation of evidence-supported hypotheses |
| TShark | Packet capture, PCAP analysis, and bounded correlation |

Tool capability is not evidence that a tool ran. Context-sensitive tools such as Gitleaks and Prowler require suitable repository/filesystem or cloud context and are not automatic recommendations for every web target.

## Specialist workflows and safety boundaries

### ffuf profiles

ffuf presents a profile selector before execution:

- **Quick** uses the bundled small smoke-test list.
- **Standard** uses the configured normal-assessment wordlist.
- **Deep** uses the configured broader wordlist and longer timeout.
- **Custom** uses `FFUF_WORDLIST_PATH` and the existing custom settings.

Standard and Deep require their configured wordlists; Mongrel does not silently substitute the Quick list. Profiles control scope and runtime, not a guarantee of complete discovery.

### Metasploit validation

- **Guided Validation** walks through target, service, an allowlisted compatible validation, review, and explicit approval.
- **Advanced Manual Mode** accepts the bounded structured request format and retains the same authorization and policy controls.

Both modes are evidence-driven and require the applicable review, approval, authorization, and policy checks. Module execution, process completion, or a target response is not by itself successful exploitation.

Launching a module, completing a workflow, or receiving a target response does not prove exploitation. Session establishment and validation outcome remain separate evidence.

### TShark modes

- **Capture During Validation** performs a bounded capture around a fresh eligible approved Metasploit validation.
- **Analyze PCAP** analyzes an existing `.pcap` or `.pcapng` file.
- **Standalone Live Capture** requires explicit approval and a configured allowlisted interface.

Packets, endpoints, DNS, HTTP fields, or TLS metadata are observations—not automatic proof of a completed transaction, TLS handshake, exploit, or compromise. TShark cannot bypass Metasploit approval or make an old failed validation eligible.

Capture and PCAP results retain scope, interface, filter, and time limitations. Correlation can support attribution to a validation window, but it is not proof of exploitation or compromise.

## Evidence model

Mongrel separates evidence from interpretation:

- Scanner output is converted into bounded **normalized evidence** where supported.
- Evidence retains **tool and artifact provenance** so claims remain attributable.
- The latest authoritative run for a tool supplies its current assessment state and evidence.
- `COMPLETED`, `PARTIAL`, `FAILED`, `SKIPPED`, and `NOT_RUN` are execution states, not security outcomes.
- Missing data remains unknown; it is not converted into zero, none, clean, or absent.
- A stored zero is reported as zero but does not prove that unobserved content does not exist.
- Attempted targets are not described as observed responses without response evidence.
- Informational or template matches are not automatically confirmed vulnerabilities or exploitable conditions.
- Failed and incomplete tools become coverage limitations, never evidence that a target is safe.

Ask Mongrel and assessment reports include uncertainty and limitations because no finite tool run establishes complete security. Human review remains necessary.

## Judge-facing demo path

Use a short evidence story instead of trying to demonstrate every tool live:

1. Create or open an authorized assessment.
2. Run **BBOT** to collect bounded reconnaissance and asset observations.
3. Run **Nmap** to establish observed host, port, and service exposure.
4. Ask **Assessment-scoped Ask Mongrel** what BBOT and Nmap established together, what remains unknown, and what should be considered next.
5. Generate the **AI Report** and/or **Markdown Report** to demonstrate evidence-backed reporting and uncertainty.
6. Optionally reopen the workspace through **Previous Assessments** to demonstrate persistence and history.

This path demonstrates collection, interpretation, persistence, uncertainty, and reporting without implying that all 12 tools are appropriate for one target.

## Self-hosting

Self-hosting is independent from access to `@Project_Mongrel_Bot`.

Clone the transferred repository from the new organization:

```bash
git clone https://github.com/Project-Mongrel/Project-Mongrel.git
cd Project-Mongrel
```

### Prerequisites

- Python with `venv` support (the tested dependencies are pinned in `requirements.txt`)
- A Telegram bot token issued through BotFather
- A local [Ollama](https://ollama.com/) service for AI-backed paths
- Only the external scanner binaries needed for the workflows you intend to enable
- Linux and systemd for the supplied production service unit

Scanner binaries are not installed by `requirements.txt`. They have their own platform privileges, data files, credentials, and authorization requirements. Review each tool before enabling it.

### Python environment

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip check
```

On Windows, activate with:

```powershell
.venv\Scripts\activate
```

Use `requirements.txt` for the main Mongrel app, tests, and default audit environment. Install Semgrep from `requirements-semgrep.txt` only in a separate optional audit virtual environment. Install the BBOT CLI outside the Mongrel application venv because current BBOT and Semgrep dependency ranges cannot share one valid, audit-clean environment. Set `BBOT_BINARY` when the external BBOT executable is not on `PATH`.

### Ollama

The competition deployment uses `qwen2.5:3b` through local Ollama. Pull it and set the model explicitly; do not rely on a repository default if reproducing the competition configuration:

```bash
ollama pull qwen2.5:3b
```

Set:

```dotenv
AI_ENABLED=true
AI_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:3b
```

CPU-only inference can take tens of seconds depending on prompt size, model warmth, and VPS resources. Deterministic routes remain available for many evidence/state questions, but self-hosters should treat model latency and availability as operational constraints.

### Environment configuration

Copy `.env.example` to `.env` for local development and provide your own values. At minimum, configure `TELEGRAM_BOT_TOKEN`; never commit it. Also review the database/evidence paths, enabled AI provider, scanner executable paths, scanner timeouts, ffuf wordlists, capture interface allowlist, and any credentials required by external tools.

```bash
cp .env.example .env
.venv/bin/python -m app.bot.bot
```

The application loads `.env` locally. The supplied systemd unit instead reads `/etc/mongrel/mongrel.env`. The portable local example uses `TESTSSL_PATH=testssl.sh`; production deployments can install the reviewed testssl override below to use `/opt/testssl.sh/testssl.sh` with the 600-second scan timeout.

### systemd deployment

The repository includes [`deploy/systemd/mongrel.service`](deploy/systemd/mongrel.service). It is configured for:

- checkout: `/home/mongrel/Project-Mongrel`
- service account: `mongrel`
- environment file: `/etc/mongrel/mongrel.env`
- entry point: `.venv/bin/python -m app.bot.bot`

Review those paths, required groups/capabilities, and every `ReadWritePaths` entry for your host before installation. Then install and start the reviewed unit with administrator privileges:

```bash
sudo install -o root -g root -m 0644 deploy/systemd/mongrel.service /etc/systemd/system/mongrel.service
sudo install -d -o root -g root -m 0755 /etc/systemd/system/mongrel.service.d
sudo install -o root -g root -m 0644 deploy/systemd/mongrel.service.d/testssl-env.conf /etc/systemd/system/mongrel.service.d/testssl-env.conf
sudo install -o root -g root -m 0644 deploy/systemd/mongrel.service.d/ffuf-env.conf /etc/systemd/system/mongrel.service.d/ffuf-env.conf
sudo install -d -o root -g root -m 0755 /etc/mongrel
sudo install -o root -g root -m 0600 deploy/systemd/testssl.env.example /etc/mongrel/testssl.env
sudo install -o root -g root -m 0600 deploy/systemd/ffuf.env.example /etc/mongrel/ffuf.env
sudo systemctl daemon-reload
sudo systemctl enable --now mongrel.service
sudo systemctl status mongrel.service --no-pager
```

The testssl drop-in loads `/etc/mongrel/testssl.env` after the primary environment file, so its two reviewed production values take precedence without duplicating or exposing the main environment file. Review the absolute executable path on each host before installation.

The ffuf drop-in similarly loads `/etc/mongrel/ffuf.env` after the primary environment file. The configured files under `/home/mongrel/wordlists/` are deployment-managed symlinks to the selected SecLists wordlists; both symlinks and their targets must be readable by the `mongrel` service user. The blank ffuf paths in `.env.example` remain portable development defaults.

Do not weaken the unit sandbox broadly to make a scanner work. Grant only the narrowly required runtime paths and privileges after validating the scanner outside and inside the service boundary.

### Tests and security audit

```bash
python -m pytest
python scripts/security_audit.py
```

The default audit runs pytest, Bandit, pip-audit, and detect-secrets when installed. The slower optional Semgrep audit uses a separate environment as documented in [`docs/security_audit.md`](docs/security_audit.md):

```bash
python scripts/security_audit.py --full
```

### Operational limitations

- Mongrel is not an autonomous hacking system and does not guarantee vulnerability discovery.
- It does not turn chat recommendations into automatic tool execution.
- External tools can fail, time out, require privileges, or produce incomplete/ambiguous evidence.
- AI responses depend on local model availability and remain subject to deterministic truthfulness checks.
- SQLite-backed assessment data and evidence files require normal backup, filesystem-permission, and disk-capacity operations.
- Live capture and active validation require explicit authorization and carefully scoped host configuration.

The same boundaries apply across the dashboard, AI Report, Markdown Report, and Ask Mongrel: scan completion does not mean a target is secure; absence of a finding is not proof of absence; passive or reconnaissance observations are not automatically vulnerabilities; observed traffic is not proof of compromise; and missing coverage remains unknown.

## Repository map

```text
app/
├── bot/          # Telegram handlers, routing, and keyboards
├── core/         # Configuration and logging
├── services/     # Assessment, evidence, AI, policy, and reporting services
├── tools/        # Bounded scanner runners
└── reports/      # Generated report output

deploy/systemd/   # Production service unit
docs/             # Setup, audit, release, and design documentation
scripts/          # Security audit and maintenance utilities
tests/            # Automated regression suite
```

Repository: <https://github.com/Project-Mongrel/Project-Mongrel>
