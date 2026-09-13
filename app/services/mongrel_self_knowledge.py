"""Compact, deterministic self-knowledge for assessment-scoped Ask Mongrel."""

from copy import deepcopy


_PROFILE = {
    "identity": "Mongrel is a 12-tool, evidence-driven security assessment platform.",
    "modes": {
        "Assessment Mode": "Persistent assessment and evidence workspace; history and reports reflect stored assessment evidence.",
        "Tool Mode": "Direct, single-tool use outside the assessment conversation workflow.",
        "Ask Mongrel": "Evidence-aware conversational analysis and advice; it does not automatically execute tools.",
        "Guided Metasploit": "Evidence-driven active validation with explicit user review and approval.",
        "Advanced Metasploit": "Bounded, manual, policy-controlled use; approval and authorization boundaries still apply.",
    },
    "reasoning": "Evidence -> hypothesis -> evidence gap -> most appropriate Mongrel capability -> expected evidence -> limitations -> next decision.",
    "security_knowledge": [
        "OWASP Top 10 concepts; map a concrete finding only when stored evidence supports it",
        "attack surface, reconnaissance, enumeration, and exposed services",
        "web behavior; authentication and access control; injection; SSRF; path traversal; file upload; API abuse",
        "TLS and configuration weaknesses; secret leakage; cloud misconfiguration; packet and network analysis",
        "vulnerability validation and attack chaining",
        "privilege boundaries, lateral movement, persistence, and impact at a conceptual defensive level",
        "attacker-informed paths, priorities, and validation needs without broadening execution authority",
    ],
    "tools": {
        "Nmap": {
            "purpose": "Host, port, and service discovery.",
            "evidence": "Reachability, open/closed/filtered ports, service/version classifications.",
            "not_proof": "Application behavior, vulnerability, exploitability, or secure/unsafe transport.",
            "gaps": "Unknown exposed services and listening ports.",
            "follow_ons": "httpx for web endpoints; testssl.sh for TLS; Nuclei for template checks; TShark for packet context.",
            "approval": "Active scanning remains limited to authorized scope.",
        },
        "BBOT": {
            "purpose": "Reconnaissance and asset discovery.",
            "evidence": "Discovered hosts, DNS names, URLs, and relationships reported by enabled modules.",
            "not_proof": "Ownership, reachability, vulnerability, or complete attack-surface coverage.",
            "gaps": "Unknown assets and external attack surface.",
            "follow_ons": "Nmap for services; httpx for web reachability; Katana for crawling.",
            "approval": "Discovery stays within authorized scope.",
        },
        "Nuclei": {
            "purpose": "Template-based vulnerability and exposure checks.",
            "evidence": "Template matches with matcher, target, and severity metadata.",
            "not_proof": "Universal exploitability, compromise, impact, or absence of other vulnerabilities.",
            "gaps": "Known-pattern validation on discovered services and applications.",
            "follow_ons": "Use Nmap/httpx/Katana context; Playwright for behavior; approved Metasploit only when validation is warranted.",
            "approval": "Active checks remain authorized and bounded.",
        },
        "httpx": {
            "purpose": "Probe and characterize HTTP/HTTPS endpoints.",
            "evidence": "Responses, status, title, redirects, server and technology hints.",
            "not_proof": "Vulnerability, misconfiguration, application health, compromise, or complete availability.",
            "gaps": "Whether web endpoints respond and their basic behavior after discovery.",
            "follow_ons": "Nmap/BBOT supply targets; Katana discovers paths; Playwright observes rendered behavior; testssl.sh checks TLS; Nuclei tests known patterns.",
            "approval": "Probing remains within authorized scope.",
        },
        "Playwright": {
            "purpose": "Browser-based observation of web applications.",
            "evidence": "Rendered pages, DOM state, screenshots, requests, and browser-visible flows.",
            "not_proof": "Authorization flaws, server-side security, exploitability, or complete application coverage.",
            "gaps": "Client-rendered behavior and interaction context missed by simple probes.",
            "follow_ons": "httpx/Katana identify pages; ffuf finds hidden paths; Nuclei checks supported patterns.",
            "approval": "Interactions remain bounded to the authorized workflow.",
        },
        "Katana": {
            "purpose": "Web crawling and endpoint discovery.",
            "evidence": "Observed links, URLs, paths, forms, scripts, and reachable resources.",
            "not_proof": "Vulnerability, authorization bypass, exhaustive coverage, or endpoint exploitability.",
            "gaps": "Unknown linked application surface and inputs.",
            "follow_ons": "httpx confirms response behavior; Playwright handles rendered flows; ffuf checks unlinked paths; Nuclei checks patterns.",
            "approval": "Crawling remains within authorized scope.",
        },
        "ffuf": {
            "purpose": "Bounded web fuzzing and content discovery at user-defined FUZZ positions, including supported paths, parameters, and hostnames.",
            "evidence": "Responses associated with tested paths, parameters, hostnames, or other input candidates.",
            "not_proof": "Sensitive content, access-control failure, vulnerability, or exhaustive discovery.",
            "gaps": "Potential unlinked paths, files, and parameters.",
            "follow_ons": "Use httpx/Katana baselines; inspect behavior with Playwright; validate supported patterns with Nuclei.",
            "approval": "Active fuzzing requires authorized, bounded profiles.",
        },
        "testssl.sh": {
            "purpose": "TLS protocol, cipher, and certificate assessment.",
            "evidence": "Scanner-observed TLS support, negotiation behavior, certificates, and reported issues.",
            "not_proof": "Application security, compromise, universal client impact, or secure posture from clean results.",
            "gaps": "TLS quality not established by an HTTPS port or HTTP probe.",
            "follow_ons": "Nmap/httpx identify TLS endpoints; TShark can add packet observations.",
            "approval": "Active TLS testing remains within authorized scope.",
        },
        "Gitleaks": {
            "purpose": "Detect secret-like patterns in authorized repositories or files.",
            "evidence": "Redacted matches, rule IDs, locations, and fingerprints.",
            "not_proof": "A secret's raw value, validity, ownership, usability, exposure, or compromise.",
            "gaps": "Potential credentials or tokens present in source material.",
            "follow_ons": "Review provenance and rotate through owner processes; relate only to assets supported by evidence.",
            "approval": "Never expose raw secrets; scanning stays within authorized material.",
        },
        "Prowler": {
            "purpose": "Cloud configuration and security-check assessment.",
            "evidence": "Provider-specific PASS/FAIL and metadata for individual checks/resources.",
            "not_proof": "Whole-account security, compliance, exploitability, or compromise.",
            "gaps": "Cloud control and resource configuration visibility.",
            "follow_ons": "Correlate affected resources with other stored asset evidence; verify high-impact interpretations manually.",
            "approval": "Cloud access and checks remain scoped and authorized.",
        },
        "Metasploit": {
            "purpose": "Controlled validation of evidence-supported vulnerability hypotheses.",
            "evidence": "Proposal, approval, module execution, target response, validation state, and session evidence as separate facts.",
            "not_proof": "Execution success alone does not prove exploitation, session, compromise, persistence, or impact.",
            "gaps": "Whether a well-supported suspected vulnerability can be actively validated.",
            "follow_ons": "Use Nmap/Nuclei/service evidence first; TShark Capture During Validation can correlate packets.",
            "approval": "Guided validation requires explicit human review/approval; Advanced remains bounded, manual, and policy controlled.",
        },
        "TShark": {
            "purpose": "Packet capture and PCAP analysis in three modes: Capture During Validation, Analyze PCAP, Standalone Live Capture.",
            "evidence": "Packet metadata, endpoints, protocols, timing, DNS, HTTP fields, TLS metadata, and validation-capture correlation.",
            "not_proof": "Correlation is packet-level attribution, not automatic proof of exploit, vulnerability, compromise, completed HTTP transaction, or successful TLS handshake.",
            "gaps": "Network-path behavior and packet-level context absent from scanner/application evidence.",
            "follow_ons": "Correlate with Nmap services and approved Metasploit validation; use application tools for higher-layer conclusions.",
            "approval": "Live capture and capture during active validation use existing authorization/approval controls.",
        },
    },
}


def build_mongrel_self_knowledge_profile() -> dict:
    """Return an isolated copy so callers cannot mutate the canonical profile."""

    return deepcopy(_PROFILE)


def get_mongrel_tool_names() -> tuple[str, ...]:
    """Return the canonical competition tool names in product display order."""

    return tuple(_PROFILE["tools"])
