"""Deterministic product knowledge for standalone Ask Mongrel."""

import re
from collections.abc import Sequence

from app.services.mongrel_self_knowledge import build_mongrel_self_knowledge_profile, get_mongrel_tool_names


History = Sequence[tuple[str, str]]
STANDALONE_ASK_PROMPT_MAX_CHARS = 9000


_TOOL_ANSWERS = {
    "nmap": "Nmap discovers hosts, exposed ports, and service/version classifications. Those observations do not by themselves prove a vulnerability.",
    "bbot": "BBOT performs reconnaissance and asset discovery, including hosts, DNS names, URLs, and relationships reported by its enabled modules.",
    "nuclei": "Nuclei runs template-based vulnerability and exposure checks. A template match must still be interpreted in the context of its evidence and does not prove universal exploitability.",
    "httpx": "httpx probes HTTP and HTTPS endpoints and records response details such as status, title, redirects, server, and technology hints.",
    "playwright": "Playwright observes browser-rendered application behavior, including pages, DOM state, screenshots, requests, and interactive flows.",
    "katana": "Katana crawls web applications to discover observed links, URLs, paths, forms, scripts, and reachable resources.",
    "ffuf": "ffuf performs bounded web fuzzing and content discovery at user-defined FUZZ positions, including paths, parameters, and hostnames supported by Mongrel. Its responses do not by themselves prove sensitive exposure or a vulnerability.",
    "testssl.sh": "testssl.sh assesses TLS protocols, ciphers, certificates, negotiation behavior, and reported TLS configuration issues.",
    "gitleaks": "Gitleaks detects secret-like patterns in authorized repositories or files. A match does not establish that a credential is valid or active.",
    "prowler": "Prowler assesses provider-specific cloud configuration and security checks when suitable authorized cloud context is available.",
    "metasploit": "Metasploit provides controlled validation of evidence-supported vulnerability hypotheses. Mongrel requires explicit review and approval; execution alone does not prove exploitation or compromise.",
    "tshark": "TShark captures or analyzes packet and protocol metadata. Packet observations do not by themselves prove a vulnerability, successful exploit, compromise, or completed TLS handshake.",
}


def _normalized(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower().replace("’", "'"))


def _history_text(history: History) -> str:
    return " ".join(text for _role, text in history[-8:]).lower()


def build_standalone_ask_prompt(question: str, history: History = ()) -> str:
    """Build bounded standalone context without assessment evidence."""

    profile = build_mongrel_self_knowledge_profile()
    bounded_question = str(question)[:2000]
    history_lines = []
    for role, text in history[-8:]:
        history_lines.append(f"{str(role).lower()[:20]}: {str(text)[:600]}")
    capability_lines = []
    for name, details in profile["tools"].items():
        capability_lines.append(
            f"- {name}: {details['purpose']} Evidence: {details['evidence']} Boundary: {details['not_proof']}"
        )
    prompt = "\n".join(
        [
            "Standalone Ask Mongrel context:",
            "- Answer general cybersecurity and educational questions generally when appropriate.",
            "- When describing what Mongrel can run, use, or recommend, use only the supported capabilities below.",
            "- Standalone Ask has no assessment findings, target observations, scan evidence, or persisted assessment context.",
            "- Do not fabricate execution, evidence, or security conclusions, and do not execute tools.",
            "- A question about an external tool may be answered as general education, but do not claim Mongrel supports it.",
            "",
            "Supported Mongrel capabilities:",
            *capability_lines,
            "",
            "Bounded standalone conversation history:",
            *(history_lines or ["(none)"]),
            "",
            f"Current user question:\n{bounded_question}",
            "\nReply with the final answer only.",
        ]
    )
    if len(prompt) <= STANDALONE_ASK_PROMPT_MAX_CHARS:
        return prompt
    compact_history = "\n".join(history_lines[-4:]) or "(none)"
    prompt = prompt.replace("\n".join(history_lines) or "(none)", compact_history)
    if len(prompt) <= STANDALONE_ASK_PROMPT_MAX_CHARS:
        return prompt
    suffix = f"\nCurrent user question:\n{bounded_question}\nReply with the final answer only."
    return prompt[:STANDALONE_ASK_PROMPT_MAX_CHARS - len(suffix)] + (
        suffix
    )


def _mentioned_tool(question: str) -> str | None:
    normalized = _normalized(question)
    aliases = {name.lower(): name.lower() for name in get_mongrel_tool_names()}
    aliases["testssl"] = "testssl.sh"
    for alias in sorted(aliases, key=len, reverse=True):
        if re.search(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", normalized):
            return aliases[alias]
    return None


def _tool_list_answer() -> str:
    names = get_mongrel_tool_names()
    return f"Mongrel has exactly 12 competition tools: {', '.join(names)}."


def _tls_answer(plural: bool) -> str:
    if not plural:
        return "Use testssl.sh to assess TLS protocols, ciphers, certificates, negotiation behavior, and configuration issues."
    return (
        "Use testssl.sh as Mongrel's primary TLS configuration-testing tool. TShark can observe TLS traffic and capture metadata "
        "when packet context matters, but it does not replace testssl.sh or prove that a TLS handshake completed."
    )


def _web_assessment_flow() -> str:
    return (
        "A practical Mongrel web assessment starts with reconnaissance and exposure: use BBOT where asset discovery is needed, "
        "then Nmap for ports/services and httpx for HTTP/HTTPS response probing. Next, use Katana for crawling, Playwright for "
        "rendered behavior, ffuf for bounded fuzzing/content discovery, and Nuclei for relevant template-based checks. Use "
        "testssl.sh for TLS configuration where TLS is present. Consider Metasploit only for justified validation with explicit "
        "human approval, "
        "validation, with TShark only when packet observations add value. Not every target needs every tool; select tools from "
        "the target context and evidence gaps."
    )


def _exposed_services_answer() -> str:
    return (
        "For exposed services, use Nmap to establish ports and service classifications. For web services, httpx can probe "
        "responses, Katana can crawl, ffuf can perform bounded content discovery, Nuclei can run relevant template checks, "
        "and testssl.sh can assess TLS configuration. TShark can add packet observations where useful. Metasploit is only for "
        "evidence-supported, explicitly approved validation; it is not an automatic next step."
    )


def answer_standalone_product_question(question: str, history: History = ()) -> str | None:
    """Return a grounded direct product answer, or ``None`` for general AI knowledge."""

    normalized = _normalized(question)
    prior = _history_text(history)

    if re.search(r"\b(what|which|list|name)\b.*\btools?\b.*\b(have|available|mongrel)\b", normalized) or normalized in {
        "what tools do you have?",
        "what tools do you have",
    }:
        return _tool_list_answer()

    if "assess a web target" in normalized or "assessment order" in normalized and "web" in normalized:
        return _web_assessment_flow()

    first_step_question = normalized.rstrip(" ?.!\n")
    if first_step_question in {
        "what should we do first",
        "what should i do first",
        "where should we start",
        "where should i start",
    } or re.search(r"\bwhat\s+tool(?:\s+should\s+(?:we|i)\s+use)?\s+first\b", normalized):
        return _web_assessment_flow()

    tls_context = "tls" in normalized or "tls" in prior
    asks_for_selection = bool(re.search(r"\b(which|what)\b.*\btools?\b|\bwhich tool do i use\b", normalized))
    if tls_context and asks_for_selection:
        plural = "tools" in normalized or "tools" in prior
        return _tls_answer(plural)

    if "investigate this" in normalized and any(term in prior for term in ("mongrel", "exposed service", "open port", "nmap")):
        return _exposed_services_answer()

    tool = _mentioned_tool(question)
    if tool is not None and re.search(r"\b(what does|describe|explain|do with)\b", normalized):
        return _TOOL_ANSWERS[tool]

    if "mongrel" in normalized and "tool" in normalized:
        profile = build_mongrel_self_knowledge_profile()
        return (
            f"Mongrel's available tools are {', '.join(profile['tools'])}. "
            "Choose among them based on the authorized target context and the evidence gap you need to resolve."
        )

    return None
