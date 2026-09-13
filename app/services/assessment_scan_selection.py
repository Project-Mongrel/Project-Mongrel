from datetime import datetime


def select_latest_tool_scan(scans: list[dict], tool: str) -> dict | None:
    """Return the authoritative latest scan for a tool by chronology, then ID."""
    normalized_tool = _normalize_tool(tool)
    candidates = [scan for scan in scans if isinstance(scan, dict) and _normalize_tool(scan.get("tool")) == normalized_tool]
    return max(candidates, key=_scan_chronology_key) if candidates else None


def select_latest_scans(scans: list[dict]) -> list[dict]:
    tools = {_normalize_tool(scan.get("tool")) for scan in scans if isinstance(scan, dict)}
    return [scan for tool in tools if tool for scan in [select_latest_tool_scan(scans, tool)] if scan]


def _normalize_tool(value: object) -> str:
    return str(value or "").strip().lower().removesuffix(".sh")


def _scan_chronology_key(scan: dict) -> tuple[float, int]:
    value = scan.get("created_at") or scan.get("started_at") or scan.get("updated_at")
    if isinstance(value, datetime):
        timestamp = value.timestamp()
    else:
        try:
            timestamp = datetime.fromisoformat(str(value)).timestamp()
        except (TypeError, ValueError):
            timestamp = float("-inf")
    try:
        scan_id = int(scan.get("id") or 0)
    except (TypeError, ValueError):
        scan_id = 0
    return timestamp, scan_id
