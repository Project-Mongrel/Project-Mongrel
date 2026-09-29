"""Deterministic product knowledge for standalone Ask Mongrel."""

import re
from collections.abc import Sequence

from app.services.conversation_understanding import (
    ConversationUnderstanding,
    extract_technical_tokens,
    normalize_conversational_text,
    understand_conversation,
)
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
    return normalize_conversational_text(text)


def _history_text(history: History) -> str:
    return " ".join(text for _role, text in history[-8:]).lower()


def _tool_names_in_text(text: str) -> list[str]:
    normalized = _normalized(text)
    aliases = {name.lower(): name for name in get_mongrel_tool_names()}
    aliases["testssl"] = "testssl.sh"
    matches = []
    for alias, name in aliases.items():
        match = re.search(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", normalized)
        if match:
            matches.append((match.start(), name))
    return [name for _position, name in sorted(set(matches))]


def _profile_tool(name: str) -> tuple[str, dict] | None:
    profile = build_mongrel_self_knowledge_profile()
    for display, details in profile["tools"].items():
        if display.lower().removesuffix(".sh") == name.lower().removesuffix(".sh"):
            return display, details
    return None


def _unknown_capability_token(question: str) -> str | None:
    known = {name.lower().removesuffix(".sh") for name in get_mongrel_tool_names()}
    for token in extract_technical_tokens(question):
        lowered = token.lower().removesuffix(".sh")
        if lowered not in known and not any(lowered.startswith(f"{name} ") for name in known):
            return token
    return None


def _is_target_like_token(token: str) -> bool:
    return bool(
        token.startswith(("/", "http://", "https://"))
        or re.fullmatch(r"port\s+\d{1,5}", token, re.IGNORECASE)
        or re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?", token)
        or "." in token and not token.upper().startswith("CVE-")
    )


def _is_mongrel_capability_question(normalized: str) -> bool:
    return bool(
        re.search(r"\b(?:can|could|does|do|will|would|should)\s+mongrel\b", normalized)
        or re.search(r"\bmongrel\b.{0,50}\b(?:run|support|recommend|capabilit)\b", normalized)
    )


def _standalone_capability_answer(
    question: str,
    normalized: str,
    understanding: ConversationUnderstanding,
) -> str | None:
    inherited = bool(
        understanding.previous_user_text
        and _is_mongrel_capability_question(_normalized(understanding.previous_user_text))
        and re.search(r"\b(?:supported|support|available|run|capability)\b", normalized)
    )
    if not _is_mongrel_capability_question(normalized) and not inherited:
        return None
    unknown = _unknown_capability_token(question) or _unknown_capability_token(understanding.previous_user_text)
    if unknown:
        if _is_target_like_token(unknown):
            return (
                f"`{unknown}` looks like target or input data, not a Mongrel capability. "
                "Please clarify the authorized workflow or environment you mean; I will not infer support or execution from that value."
            )
        return (
            f"I do not recognize `{unknown}` as one of Mongrel's supported capabilities. "
            "Please clarify the product or environment you mean; I can discuss an external technology generally, "
            "but I will not silently substitute another name or claim Mongrel can run it."
        )
    tool = _mentioned_tool(question)
    if tool:
        profile_tool = _profile_tool(tool)
        display = profile_tool[0] if profile_tool else tool
        return f"Mongrel can use {display} within its authorized workflow. {_TOOL_ANSWERS[tool]}"
    return _tool_list_answer()


def _focused_follow_up_answer(understanding: ConversationUnderstanding) -> str | None:
    prior_tools = []
    for assistant_text in understanding.previous_assistant_texts or (understanding.previous_assistant_text,):
        candidate_tools = _tool_names_in_text(assistant_text)
        if len(candidate_tools) > 1:
            prior_tools = candidate_tools
            break
    if not prior_tools:
        prior_tools = _tool_names_in_text(understanding.previous_assistant_text)
    if not prior_tools:
        return None
    previous_user_normalized = _normalized(understanding.previous_user_text)
    previous_selection = re.search(r"\b(first|second|third|two|three)\b", previous_user_normalized)
    previous_index = (
        {"first": 0, "second": 1, "third": 2, "two": 1, "three": 2}[previous_selection.group(1)]
        if previous_selection
        else 0
    )
    if understanding.referenced_ordinal is not None:
        index = understanding.referenced_ordinal - 1
    elif re.search(r"\bafter\s+that\b", understanding.normalized_text):
        index = previous_index + 1
    else:
        index = previous_index
    index = min(max(index, 0), len(prior_tools) - 1)
    selected = prior_tools[index]
    selected_profile = _profile_tool(selected)
    if selected_profile is None:
        return None
    display, details = selected_profile
    initial_selection = bool(
        re.search(r"\b(?:what|which)\s+(?:tool|one)\b", understanding.normalized_text)
        and re.search(r"\bfirst\b", understanding.normalized_text)
        and "tool" not in previous_user_normalized
    )
    if index == 0 and len(prior_tools) > 1 and initial_selection:
        next_display, next_details = _profile_tool(prior_tools[1]) or (prior_tools[1], {"purpose": "the next evidence step"})
        return (
            f"Start with {display} when you need {details['purpose'].lower()} If the host is already known, "
            f"{next_display} is the more direct first step for {next_details['purpose'].lower()} "
            f"Then use {prior_tools[2] if len(prior_tools) > 2 else 'the next relevant Mongrel capability'} to fill the next evidence gap."
        )
    return f"{display} is the referenced step: {details['purpose']} {details['evidence']}"


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
            f"- {name}: {details['purpose']} Evidence: {details['evidence']} "
            f"Boundary: Does not establish {details['not_proof']}"
        )
    prompt = "\n".join(
        [
            "Standalone Ask Mongrel context:",
            "- Answer general cybersecurity and educational questions generally when appropriate.",
            "- When describing what Mongrel can run, use, or recommend, use only the supported capabilities below.",
            "- Standalone Ask has no assessment findings, target observations, scan evidence, or persisted assessment context.",
            "- Do not fabricate execution, evidence, or security conclusions, and do not execute tools.",
            "- A question about an external tool may be answered as general education, but do not claim Mongrel supports it.",
            "- When comparing tools, describe bounded capabilities and observed evidence types only. Never call reconnaissance comprehensive or complete, and never turn discovery into proof of ownership, reachability, vulnerability, exploitability, compromise, or full attack-surface coverage.",
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
    understanding = understand_conversation(question, history)

    capability_answer = _standalone_capability_answer(question, normalized, understanding)
    if capability_answer is not None:
        return capability_answer

    if re.search(r"\b(what|which|list|name)\b.*\btools?\b.*\b(have|available|mongrel)\b", normalized) or normalized in {
        "what tools do you have?",
        "what tools do you have",
    }:
        return _tool_list_answer()

    if "assess a web target" in normalized or "assessment order" in normalized and "web" in normalized:
        return _web_assessment_flow()

    if understanding.is_follow_up and (understanding.requests_detail or understanding.narrows_selection or re.search(r"\b(?:that|this|it)\b", normalized)):
        focused = _focused_follow_up_answer(understanding)
        if focused is not None:
            return focused

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
