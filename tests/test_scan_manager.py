import pytest

from app.services.scan_manager import (
    clear_user_scan_requests,
    complete_scan_request,
    create_scan_request,
    get_scan_request,
    get_user_scan_requests,
    mark_scan_request_awaiting_target,
)


def test_scan_request_creation_works() -> None:
    clear_user_scan_requests(1001)

    scan_request = create_scan_request(user_id=1001, scan_type="nmap")

    assert scan_request.id
    assert scan_request.status == "pending"
    assert scan_request.created_at is not None


def test_scan_request_stores_user_id_and_scan_type() -> None:
    clear_user_scan_requests(1002)

    scan_request = create_scan_request(user_id=1002, scan_type="nuclei")

    assert scan_request.user_id == 1002
    assert scan_request.scan_type == "nuclei"


def test_user_scan_request_retrieval_works() -> None:
    clear_user_scan_requests(1003)
    clear_user_scan_requests(9999)

    first_request = create_scan_request(user_id=1003, scan_type="nmap")
    second_request = create_scan_request(user_id=1003, scan_type="bbot")
    create_scan_request(user_id=9999, scan_type="nuclei")

    assert get_user_scan_requests(1003) == [first_request, second_request]


def test_clear_user_scan_requests_works() -> None:
    clear_user_scan_requests(1004)
    create_scan_request(user_id=1004, scan_type="bbot")

    clear_user_scan_requests(1004)

    assert get_user_scan_requests(1004) == []


def test_scan_request_state_transitions_work() -> None:
    clear_user_scan_requests(1005)
    scan_request = create_scan_request(user_id=1005, scan_type="nmap")

    awaiting_target_request = mark_scan_request_awaiting_target(
        user_id=1005,
        scan_request_id=scan_request.id,
    )
    completed_request = complete_scan_request(
        user_id=1005,
        scan_request_id=scan_request.id,
        target="example.com",
        result={"success": True, "target": "example.com", "output": "open ports"},
    )

    assert awaiting_target_request.status == "awaiting_target"
    assert completed_request.status == "completed"
    assert completed_request.target == "example.com"
    assert completed_request.result == {"success": True, "target": "example.com", "output": "open ports"}
    assert completed_request.completed_at is not None
    assert get_scan_request(1005, scan_request.id) == completed_request


@pytest.mark.parametrize(
    ("result", "status"),
    [
        ({"success": False, "error_type": "timeout"}, "timed_out"),
        ({"success": False, "error_type": "cancelled"}, "cancelled"),
        ({"success": False, "partial": True, "error_type": "timeout"}, "partial"),
        ({"success": False}, "failed"),
    ],
)
def test_scan_request_terminal_states_remain_distinct(result: dict, status: str) -> None:
    clear_user_scan_requests(1006)
    scan_request = create_scan_request(user_id=1006, scan_type="ffuf")

    terminal = complete_scan_request(1006, scan_request.id, "example.com", result)

    assert terminal.status == status
