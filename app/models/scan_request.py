from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4

SUPPORTED_SCAN_TYPES: frozenset[str] = frozenset({"nmap", "nuclei", "bbot"})


@dataclass(frozen=True, slots=True)
class ScanRequest:
    id: str
    user_id: int
    scan_type: str
    status: str = "pending"
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


def create_pending_scan_request(user_id: int, scan_type: str) -> ScanRequest:
    normalized_scan_type = scan_type.lower()
    if normalized_scan_type not in SUPPORTED_SCAN_TYPES:
        supported = ", ".join(sorted(SUPPORTED_SCAN_TYPES))
        raise ValueError(f"Unsupported scan_type '{scan_type}'. Supported values: {supported}.")

    return ScanRequest(
        id=str(uuid4()),
        user_id=user_id,
        scan_type=normalized_scan_type,
    )
