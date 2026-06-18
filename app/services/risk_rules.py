RISK_LEVELS: tuple[str, ...] = ("low", "medium", "high")
COMMON_WEB_PORTS: frozenset[str] = frozenset({"80", "443"})
DATABASE_PORTS: frozenset[str] = frozenset({"3306", "5432", "1433", "27017", "6379"})


def assess_nmap_ports(open_ports: list[dict]) -> dict:
    risk_level = "low"
    risk_notes: list[str] = []
    port_numbers = {str(open_port.get("port")) for open_port in open_ports}

    if "22" in port_numbers:
        risk_level = _max_risk_level(risk_level, "medium")
        risk_notes.append("SSH exposed")

    if "3389" in port_numbers:
        risk_level = _max_risk_level(risk_level, "high")
        risk_notes.append("RDP exposed")

    if "445" in port_numbers:
        risk_level = _max_risk_level(risk_level, "high")
        risk_notes.append("SMB exposed")

    if port_numbers & DATABASE_PORTS:
        risk_level = _max_risk_level(risk_level, "high")
        risk_notes.append("Database port exposed")

    if len(open_ports) >= 10:
        risk_level = _max_risk_level(risk_level, "medium")
        risk_notes.append("Many open ports")

    return {
        "risk_level": risk_level,
        "risk_notes": risk_notes,
    }


def _max_risk_level(current: str, candidate: str) -> str:
    if RISK_LEVELS.index(candidate) > RISK_LEVELS.index(current):
        return candidate

    return current
