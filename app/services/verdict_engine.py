DATABASE_PORTS: frozenset[str] = frozenset({"3306", "5432", "1433", "27017", "6379"})


def generate_mongrel_verdict(finding: dict) -> dict:
    open_ports = finding.get("open_ports") or []
    port_numbers = {str(open_port.get("port")) for open_port in open_ports}
    risk_level = str(finding.get("risk_level") or "low")
    key_findings: list[str] = []
    recommended_actions: list[str] = []

    if not open_ports:
        return {
            "risk_level": risk_level,
            "summary": "No open ports were detected.",
            "key_findings": [],
            "recommended_actions": [],
        }

    if "22" in port_numbers:
        key_findings.append("SSH remote administration service exposed.")
        recommended_actions.append("Restrict SSH access to trusted networks.")

    if "445" in port_numbers:
        key_findings.append("Windows SMB file sharing service exposed.")
        recommended_actions.append("Restrict or disable SMB if not required.")

    if "3389" in port_numbers:
        key_findings.append("Remote Desktop service exposed.")
        recommended_actions.append("Restrict RDP access and require strong authentication.")

    if port_numbers & DATABASE_PORTS:
        key_findings.append("Database service exposed.")
        recommended_actions.append("Ensure database services are not publicly accessible.")

    if len(open_ports) >= 10:
        key_findings.append("Many services are exposed on this host.")
        recommended_actions.append("Review whether all exposed services are required.")

    if not key_findings:
        key_findings.append("Open network services were detected.")
        recommended_actions.append("Review exposed services and restrict unnecessary access.")

    return {
        "risk_level": risk_level,
        "summary": _build_summary(finding, open_ports),
        "key_findings": key_findings,
        "recommended_actions": recommended_actions,
    }


def _build_summary(finding: dict, open_ports: list[dict]) -> str:
    target = finding.get("target") or "This host"
    risk_level = str(finding.get("risk_level") or "low").lower()
    open_port_count = len(open_ports)
    return f"{target} has {open_port_count} open port(s) and is currently assessed as {risk_level} risk."
