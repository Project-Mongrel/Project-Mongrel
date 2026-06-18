import re

MAX_FORMATTED_OUTPUT_LENGTH = 3000

_TARGET_PATTERN = re.compile(r"^Nmap scan report for (?P<target>.+)$", re.IGNORECASE)
_HOST_UP_PATTERN = re.compile(r"^Host is up\b", re.IGNORECASE)
_HOST_DOWN_PATTERN = re.compile(r"^Host seems down\b|^Note: Host seems down\b", re.IGNORECASE)
_OPEN_PORT_PATTERN = re.compile(r"^(?P<port>\d+)/(?P<protocol>[a-z]+)\s+open\s+(?P<service>\S+)", re.IGNORECASE)
_DURATION_PATTERN = re.compile(r"Nmap done:.*scanned in (?P<duration>\d+(?:\.\d+)?) seconds", re.IGNORECASE)


def parse_nmap_output(output: str) -> dict:
    target = None
    host_status = None
    open_ports: list[dict[str, str]] = []
    duration = None

    for line in output.splitlines():
        stripped_line = line.strip()
        if not stripped_line:
            continue

        target_match = _TARGET_PATTERN.match(stripped_line)
        if target_match is not None:
            target = target_match.group("target")
            continue

        if _HOST_UP_PATTERN.match(stripped_line):
            host_status = "Up"
            continue

        if _HOST_DOWN_PATTERN.match(stripped_line):
            host_status = "Down"
            continue

        open_port_match = _OPEN_PORT_PATTERN.match(stripped_line)
        if open_port_match is not None:
            open_ports.append(
                {
                    "port": open_port_match.group("port"),
                    "protocol": open_port_match.group("protocol"),
                    "service": open_port_match.group("service"),
                }
            )
            continue

        duration_match = _DURATION_PATTERN.search(stripped_line)
        if duration_match is not None:
            duration = f"{duration_match.group('duration')}s"

    return {
        "target": target,
        "host_status": host_status,
        "open_ports": open_ports,
        "duration": duration,
    }


def format_nmap_result(parsed: dict, fallback_output: str = "") -> str:
    try:
        target = parsed.get("target")
        host_status = parsed.get("host_status")
        open_ports = parsed.get("open_ports")
        duration = parsed.get("duration")
        risk_level = parsed.get("risk_level")
        risk_notes = parsed.get("risk_notes")
    except AttributeError:
        return _safe_truncated_fallback(fallback_output)

    if not target and not host_status and not open_ports and not duration:
        return _safe_truncated_fallback(fallback_output)

    lines = [
        f"Target: {target or 'Unknown'}",
        "",
        f"Host Status: {host_status or 'Unknown'}",
        "",
        "Open Ports:",
    ]

    if open_ports:
        for open_port in open_ports:
            lines.append(f"{open_port['port']}/{open_port['protocol']} {open_port['service']}")
    else:
        lines.append("No open ports found.")

    if duration:
        lines.extend(["", f"Duration: {duration}"])

    if risk_level:
        lines.extend(["", f"Risk: {risk_level}"])
        notes = ", ".join(risk_notes or []) if isinstance(risk_notes, list) else str(risk_notes or "")
        lines.append(f"Notes: {notes or 'None'}")

    return "\n".join(lines)


def _safe_truncated_fallback(output: str) -> str:
    sanitized_output = output.replace("https://nmap.org", "nmap.org")
    if len(sanitized_output) <= MAX_FORMATTED_OUTPUT_LENGTH:
        return sanitized_output or "No Nmap output returned."

    return f"{sanitized_output[:MAX_FORMATTED_OUTPUT_LENGTH]}\n\n[output truncated]"
