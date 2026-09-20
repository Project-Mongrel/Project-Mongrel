from collections import defaultdict
from dataclasses import replace
from datetime import UTC, datetime

from app.models.scan_request import ScanRequest, create_pending_scan_request
from app.services.scan_status import scan_status_from_result

_scan_requests: dict[int, list[ScanRequest]] = defaultdict(list)


def create_scan_request(user_id: int, scan_type: str) -> ScanRequest:
    scan_request = create_pending_scan_request(user_id=user_id, scan_type=scan_type)
    _scan_requests[user_id].append(scan_request)
    return scan_request


def get_user_scan_requests(user_id: int) -> list[ScanRequest]:
    return list(_scan_requests.get(user_id, []))


def get_scan_request(user_id: int, scan_request_id: str) -> ScanRequest | None:
    for scan_request in _scan_requests.get(user_id, []):
        if scan_request.id == scan_request_id:
            return scan_request

    return None


def mark_scan_request_awaiting_target(user_id: int, scan_request_id: str) -> ScanRequest:
    return _replace_scan_request(user_id, scan_request_id, status="awaiting_target")


def complete_scan_request(user_id: int, scan_request_id: str, target: str, result: dict[str, object]) -> ScanRequest:
    status = scan_status_from_result(result)
    return _replace_scan_request(
        user_id,
        scan_request_id,
        status=status,
        target=target,
        result=result,
        completed_at=datetime.now(UTC),
    )


def clear_user_scan_requests(user_id: int) -> None:
    _scan_requests.pop(user_id, None)


def _replace_scan_request(user_id: int, scan_request_id: str, **changes: object) -> ScanRequest:
    scan_requests = _scan_requests.get(user_id, [])
    for index, scan_request in enumerate(scan_requests):
        if scan_request.id == scan_request_id:
            updated_scan_request = replace(scan_request, **changes)
            scan_requests[index] = updated_scan_request
            return updated_scan_request

    raise ValueError(f"Scan request '{scan_request_id}' was not found for user '{user_id}'.")
