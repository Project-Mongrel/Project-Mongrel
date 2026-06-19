RISK_LEVELS: tuple[str, ...] = ("low", "medium", "high")
DATABASE_PORTS: frozenset[str] = frozenset({"3306", "5432", "1433", "27017", "6379"})
RISKY_REMOVED_PORTS: frozenset[str] = frozenset({"22", "445", "3389", *DATABASE_PORTS})


def assess_change_impact(comparison: dict) -> dict:
    impact_level = "low"
    impacts: list[str] = []
    recommendations: list[str] = []
    new_port_numbers = {str(open_port.get("port")) for open_port in comparison.get("new_ports") or []}
    removed_port_numbers = {str(open_port.get("port")) for open_port in comparison.get("removed_ports") or []}

    if "22" in new_port_numbers:
        impact_level = _max_impact_level(impact_level, "medium")
        impacts.append("SSH remote administration became exposed.")
        recommendations.append("Restrict SSH to trusted networks.")

    if "445" in new_port_numbers:
        impact_level = _max_impact_level(impact_level, "high")
        impacts.append("SMB file sharing became exposed.")
        recommendations.append("Restrict or disable SMB if not required.")

    if "3389" in new_port_numbers:
        impact_level = _max_impact_level(impact_level, "high")
        impacts.append("Remote Desktop became exposed.")
        recommendations.append("Restrict RDP and require strong authentication.")

    if new_port_numbers & DATABASE_PORTS:
        impact_level = _max_impact_level(impact_level, "high")
        impacts.append("Database service became exposed.")
        recommendations.append("Ensure database access is not public.")

    if removed_port_numbers & RISKY_REMOVED_PORTS:
        impacts.append("Attack surface reduced.")
        recommendations.append("No immediate action required.")

    if not impacts:
        return {
            "impact_level": "low",
            "summary": "No material exposure changes detected.",
            "impacts": [],
            "recommendations": [],
        }

    return {
        "impact_level": impact_level,
        "summary": _build_summary(impact_level, impacts),
        "impacts": impacts,
        "recommendations": recommendations,
    }


def _max_impact_level(current: str, candidate: str) -> str:
    if RISK_LEVELS.index(candidate) > RISK_LEVELS.index(current):
        return candidate

    return current


def _build_summary(impact_level: str, impacts: list[str]) -> str:
    if impact_level == "high":
        return "High-impact exposure change detected."
    if impact_level == "medium":
        return "Medium-impact exposure change detected."

    return impacts[0]
