"""Canonical assessment scan execution statuses and legacy compatibility."""

CANONICAL_SCAN_STATUSES = frozenset(
    {"running", "completed", "failed", "partial", "timed_out", "cancelled", "interrupted"}
)
TERMINAL_SCAN_STATUSES = frozenset(CANONICAL_SCAN_STATUSES - {"running"})

_LEGACY_STATUS_ALIASES = {
    "active": "running",
    "in progress": "running",
    "in_progress": "running",
    "complete": "completed",
    "succeeded": "completed",
    "successful": "completed",
    "error": "failed",
    "errored": "failed",
    "timeout": "timed_out",
    "timed out": "timed_out",
    "timedout": "timed_out",
    "canceled": "cancelled",
    "aborted": "interrupted",
}

_STATUS_LABELS = {
    "running": "Running",
    "completed": "Completed",
    "failed": "Failed",
    "partial": "Partial",
    "timed_out": "Timed out",
    "cancelled": "Cancelled",
    "interrupted": "Interrupted",
    "skipped": "Skipped",
}


def normalize_scan_status(value: object, *, default: str = "unknown") -> str:
    normalized = str(value or "").strip().lower().replace("-", "_")
    if not normalized:
        return default
    return _LEGACY_STATUS_ALIASES.get(normalized, normalized)


def scan_status_from_result(result: dict) -> str:
    """Derive execution state without converting execution into a security verdict."""

    error_type = normalize_scan_status(result.get("error_type"), default="")
    if error_type == "cancelled" or result.get("cancelled") is True:
        return "cancelled"
    if result.get("partial") is True:
        return "partial"
    if error_type == "timed_out" or result.get("timed_out") is True:
        return "timed_out"
    if result.get("success") is True:
        return "completed"
    return "failed"


def scan_status_label(value: object) -> str:
    normalized = normalize_scan_status(value)
    return _STATUS_LABELS.get(normalized, normalized.replace("_", " ").title())
