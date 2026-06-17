from collections import defaultdict

from app.models.scan_request import ScanRequest, create_pending_scan_request

_scan_requests: dict[int, list[ScanRequest]] = defaultdict(list)


def create_scan_request(user_id: int, scan_type: str) -> ScanRequest:
    scan_request = create_pending_scan_request(user_id=user_id, scan_type=scan_type)
    _scan_requests[user_id].append(scan_request)
    return scan_request


def get_user_scan_requests(user_id: int) -> list[ScanRequest]:
    return list(_scan_requests.get(user_id, []))


def clear_user_scan_requests(user_id: int) -> None:
    _scan_requests.pop(user_id, None)
