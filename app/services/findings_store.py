from collections import defaultdict
from datetime import UTC, datetime
from uuid import uuid4

_findings: dict[int, list[dict]] = defaultdict(list)


def add_finding(user_id: int, finding: dict) -> dict:
    stored_finding = {
        **finding,
        "id": str(uuid4()),
        "user_id": user_id,
        "created_at": datetime.now(UTC),
    }
    _findings[user_id].append(stored_finding)
    return dict(stored_finding)


def get_user_findings(user_id: int) -> list[dict]:
    return [dict(finding) for finding in _findings.get(user_id, [])]


def clear_user_findings(user_id: int) -> None:
    _findings.pop(user_id, None)
