"""Compact evidence semantics selected by represented assessment tools."""


_SEMANTICS = {
    "nmap": [
        "Service labels are scanner observations/classifications, not vulnerability, exploitability, safety, or risk conclusions.",
        "80/http means an exposed HTTP-associated service only; it does not prove sensitive cleartext transmission, interception/MITM exposure, or a web vulnerability.",
        "443/https and 8443/https-alt are service classifications only; they do not prove a successful TLS handshake, negotiated encryption, certificate validity, or TLS quality/security.",
        "http-proxy is a service classification only; it does not prove an open proxy, proxy misconfiguration, or exploitability.",
        "For a direct evidence question, report only stored target, endpoint, port, service, and version observations. Do not add a risk level unless asked.",
    ],
}


def get_evidence_semantics(tool_name: str) -> tuple[str, ...]:
    """Return immutable semantics for one normalized tool name."""

    normalized = str(tool_name or "").strip().lower().removesuffix(".sh")
    return tuple(_SEMANTICS.get(normalized, ()))


def get_represented_evidence_semantics(findings: list[dict]) -> dict[str, tuple[str, ...]]:
    """Return semantics only for tools represented by normalized findings."""

    represented = {
        str(finding.get("source") or "").strip().lower().removesuffix(".sh")
        for finding in findings
        if isinstance(finding, dict)
    }
    return {tool: get_evidence_semantics(tool) for tool in sorted(represented) if get_evidence_semantics(tool)}
