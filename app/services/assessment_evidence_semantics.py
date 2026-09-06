"""Compact evidence semantics selected by represented assessment tools."""


_SEMANTICS = {
    "nmap": [
        "Service labels are scanner observations/classifications, not vulnerability, exploitability, safety, or risk conclusions.",
        "80/http means an exposed HTTP-associated service only; it does not prove sensitive cleartext transmission, interception/MITM exposure, or a web vulnerability.",
        "443/https and 8443/https-alt are service classifications only; they do not prove a successful TLS handshake, negotiated encryption, certificate validity, or TLS quality/security.",
        "http-proxy is a service classification only; it does not prove an open proxy, proxy misconfiguration, or exploitability.",
        "For a direct evidence question, report only stored target, endpoint, port, service, and version observations. Do not add a risk level unless asked.",
    ],
    "bbot": [
        "BBOT discoveries are reconnaissance observations; discovered subdomains, emails, IPs, technologies, and certificates do not establish ownership or reachability.",
        "A discovery does not establish vulnerability, breach, or exploitability, and no discoveries do not prove that no assets exist.",
    ],
    "nuclei": [
        "Preserve Nuclei's stored scanner severity exactly: INFO and LOW remain INFO and LOW.",
        "A template match is scanner evidence, not confirmed exploitability; template descriptions and remediation describe template intent, not necessarily realized target impact.",
        "Zero matches mean no stored matches for the templates and scope used, not that the target is safe.",
    ],
    "httpx": [
        "httpx status and response metadata are observations; technology hints do not establish a vulnerable technology and TLS metadata does not establish overall TLS safety.",
        "401 or 403 does not prove a vulnerability or WAF; 404 does not prove the host or site is absent; 429 may reflect throttling but does not prove its cause; 5xx does not establish a root cause.",
        "No or empty response does not prove the host is down.",
    ],
    "playwright": [
        "Playwright evidence is limited to the requested and rendered browser state that was observed; one observed page is not complete application coverage.",
        "Forms, inputs, JavaScript, console/network errors, or browser state do not establish XSS, SQL injection, CSRF, or an authentication vulnerability.",
        "No observed issue does not prove that an issue is absent.",
    ],
    "katana": [
        "Katana results are crawl observations; discovered URLs, parameters, and forms do not establish a vulnerability or complete coverage.",
        "An empty crawl does not prove that hidden endpoints do not exist, that the target is safe, or that it is unreachable.",
    ],
    "ffuf": [
        "ffuf paths, statuses, and sizes are fuzzing observations; an interesting or admin-looking path does not automatically establish sensitive exposure.",
        "A 200 response does not establish authorized access or vulnerability, and a redirect does not establish vulnerability.",
        "Zero results do not prove safety; results depend on the wordlist, filters, scope, runtime, and selected profile.",
    ],
    "testssl": [
        "Preserve testssl.sh scanner wording and confidence exactly; potentially VULNERABLE does not mean a confirmed exploitable vulnerability.",
        "An individual cipher, protocol, certificate, or header observation does not establish overall TLS safety, and early_data severity requires its stored context.",
        "Zero or clean observations do not provide complete TLS assurance.",
    ],
    "gitleaks": [
        "A redacted Gitleaks secret-pattern match does not establish an active, valid, or usable credential, authorization, or compromise; never expose a raw secret value.",
        "Zero findings do not prove that no secrets exist elsewhere or outside the scanned scope.",
    ],
    "prowler": [
        "Prowler PASS and FAIL apply only to the individual stored check and resource; a failed check does not establish compromise.",
        "Compliance mappings do not establish organization-wide compliance, and many passes or zero failures do not establish overall cloud security.",
        "Risk and remediation text describe check context, not proof of realized impact.",
    ],
    "metasploit": [
        "Metasploit proposal or approval state does not establish execution; subprocess completion does not establish successful module execution.",
        "Module execution does not establish exploit success, and exploit success does not establish a session unless stored session evidence says so.",
        "Do not claim execution or validation without its stored state; active validation retains explicit user review and approval.",
    ],
    "tshark": [
        "TShark packet observations do not establish exploitation or compromise, and TCP traffic does not establish a successful application transaction.",
        "TLS packets or fields do not establish a completed TLS handshake unless stored evidence proves it; correlation confidence is attribution confidence, not exploit confidence.",
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
