def compare_findings(previous: dict | None, current: dict) -> dict:
    current_ports = _ports_by_key(current.get("open_ports") or [])
    current_risk = str(current.get("risk_level") or "unknown")

    if previous is None:
        return {
            "has_previous": False,
            "new_ports": [],
            "removed_ports": [],
            "unchanged_ports": [],
            "risk_changed": False,
            "previous_risk": None,
            "current_risk": current_risk,
            "summary": "No previous scan found for this target.",
        }

    previous_ports = _ports_by_key(previous.get("open_ports") or [])
    previous_risk = str(previous.get("risk_level") or "unknown")
    new_keys = current_ports.keys() - previous_ports.keys()
    removed_keys = previous_ports.keys() - current_ports.keys()
    unchanged_keys = current_ports.keys() & previous_ports.keys()

    comparison = {
        "has_previous": True,
        "new_ports": [current_ports[key] for key in sorted(new_keys)],
        "removed_ports": [previous_ports[key] for key in sorted(removed_keys)],
        "unchanged_ports": [current_ports[key] for key in sorted(unchanged_keys)],
        "risk_changed": previous_risk != current_risk,
        "previous_risk": previous_risk,
        "current_risk": current_risk,
    }
    comparison["summary"] = _build_summary(comparison)
    return comparison


def _ports_by_key(open_ports: list[dict]) -> dict[tuple[str, str, str], dict]:
    ports = {}
    for open_port in open_ports:
        key = (
            str(open_port.get("port") or ""),
            str(open_port.get("protocol") or ""),
            str(open_port.get("service") or ""),
        )
        ports[key] = dict(open_port)

    return ports


def _build_summary(comparison: dict) -> str:
    parts = []
    if comparison["new_ports"]:
        parts.append(f"{len(comparison['new_ports'])} new port(s)")
    if comparison["removed_ports"]:
        parts.append(f"{len(comparison['removed_ports'])} removed port(s)")
    if comparison["risk_changed"]:
        parts.append(f"risk changed from {comparison['previous_risk']} to {comparison['current_risk']}")

    return ", ".join(parts) if parts else "No material changes detected."
