VALIDATION_STATES = frozenset({"VALIDATED", "DETECTED", "NOT_REPRODUCED", "INCONCLUSIVE", "BLOCKED", "FAILED"})


def parse_metasploit_validation_result(result: dict) -> dict:
    output = str(result.get("output") or "")
    error = str(result.get("error") or "")
    combined = f"{output}\n{error}".lower()
    if result.get("error_type") == "timeout":
        state = "BLOCKED"
        summary = "Metasploit validation timed out; this does not mean the target is safe."
    elif result.get("success") is not True:
        state = "FAILED"
        summary = "Metasploit validation failed to execute cleanly; this does not mean the target is safe."
    elif _contains_any(combined, ("appears vulnerable", "the target appears to be vulnerable", "is vulnerable")):
        state = "VALIDATED"
        summary = "Metasploit reported validation evidence. This is not proof of full compromise."
    elif _contains_any(combined, ("does not appear to be vulnerable", "not exploitable", "check failed")):
        state = "NOT_REPRODUCED"
        summary = "Metasploit did not reproduce the condition. This is not proof that the target is secure."
    elif _contains_any(combined, ("connection refused", "filtered", "timed out", "unreachable")):
        state = "BLOCKED"
        summary = "Metasploit validation was blocked by connectivity or filtering."
    elif _looks_like_service_detection(result, combined):
        state = "DETECTED"
        summary = "Metasploit reported service or version metadata. This is detection evidence, not proof of vulnerability, exploitation, or compromise."
    else:
        state = "INCONCLUSIVE"
        summary = "Metasploit output did not provide a conclusive validation result."
    return {
        "source": "metasploit",
        "module": result.get("module"),
        "action_type": result.get("action_type"),
        "target": result.get("target"),
        "port": result.get("port"),
        "validation_state": state,
        "summary": summary,
        "evidence_confidence": "tool_reported",
        "limitations": [
            "Metasploit validation evidence is bounded to the approved module/action/options.",
            "Appears vulnerable is validation evidence, not automatic proof of full compromise.",
            "Detected service or version metadata is not proof of vulnerability, exploitation, or compromise.",
            "Failed, blocked, timed out, or not reproduced results do not mean the target is secure.",
            "No CVE, session, persistence, impact, or attacker access is inferred unless explicitly present in tool output.",
        ],
        "raw_evidence_excerpt": _excerpt(output or error),
    }


def _contains_any(text: str, needles: tuple[str, ...]) -> bool:
    return any(needle in text for needle in needles)


def _looks_like_service_detection(result: dict, text: str) -> bool:
    module = str(result.get("module") or "").lower()
    if "scanner/" not in module:
        return False
    detection_terms = (
        "server version",
        "service version",
        "version:",
        "banner:",
        "detected",
        "ssh-2.0",
        "protocol version",
        "service info",
    )
    return _contains_any(text, detection_terms)


def _excerpt(text: str, limit: int = 1200) -> str:
    return str(text or "").replace("\r", "").strip()[:limit]
