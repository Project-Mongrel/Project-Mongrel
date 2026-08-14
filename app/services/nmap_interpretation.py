def is_nmap_assessment_inconclusive(evidence: dict, result: dict | None = None) -> bool:
    open_ports = evidence.get("open_ports") or []
    if open_ports:
        return False

    if str(evidence.get("assessment_result") or "").strip().lower() == "inconclusive":
        return True

    if "host_status" not in evidence and result is None:
        return False

    host_status = str(evidence.get("host_status") or "").strip().lower()
    if host_status == "up":
        return False

    if result is not None and result.get("success") is not True:
        return True

    return host_status in {"", "unknown", "down"}


def apply_nmap_assessment_interpretation(evidence: dict, result: dict | None = None) -> dict:
    interpreted = dict(evidence)
    if not is_nmap_assessment_inconclusive(interpreted, result):
        return interpreted

    interpreted["assessment_result"] = "inconclusive"
    interpreted["risk_level"] = "unknown"
    notes = [str(note) for note in interpreted.get("risk_notes") or [] if str(note).strip()]
    note = "Target status could not be established"
    if note not in notes:
        notes.insert(0, note)
    interpreted["risk_notes"] = notes
    return interpreted
