from app.services.findings_store import (
    add_finding,
    clear_user_findings,
    get_latest_user_finding_for_target,
    get_user_findings,
)


def test_add_finding() -> None:
    clear_user_findings(2001)

    finding = add_finding(
        user_id=2001,
        finding={
            "source": "nmap",
            "target": "127.0.0.1",
            "host_status": "Up",
            "open_ports": [],
            "duration": "0.32s",
        },
    )

    assert finding["id"]
    assert finding["user_id"] == 2001
    assert finding["source"] == "nmap"
    assert finding["created_at"] is not None


def test_get_user_findings() -> None:
    clear_user_findings(2002)
    first_finding = add_finding(user_id=2002, finding={"source": "nmap", "target": "one"})
    second_finding = add_finding(user_id=2002, finding={"source": "nmap", "target": "two"})

    assert get_user_findings(2002) == [first_finding, second_finding]


def test_user_isolation() -> None:
    clear_user_findings(2003)
    clear_user_findings(9999)
    finding = add_finding(user_id=2003, finding={"source": "nmap", "target": "mine"})
    add_finding(user_id=9999, finding={"source": "nmap", "target": "theirs"})

    assert get_user_findings(2003) == [finding]


def test_clear_findings() -> None:
    clear_user_findings(2004)
    add_finding(user_id=2004, finding={"source": "nmap", "target": "127.0.0.1"})

    clear_user_findings(2004)

    assert get_user_findings(2004) == []


def test_previous_lookup_works_with_target_key() -> None:
    clear_user_findings(2005)
    finding = add_finding(
        user_id=2005,
        finding={
            "source": "nmap",
            "target": "localhost (127.0.0.1)",
            "target_key": "127.0.0.1",
        },
    )

    assert get_latest_user_finding_for_target(2005, "127.0.0.1") == finding


def test_previous_lookup_fallback_works_without_target_key() -> None:
    clear_user_findings(2006)
    finding = add_finding(
        user_id=2006,
        finding={
            "source": "nmap",
            "target": "DESKTOP-MSP5KSM (192.168.0.24)",
        },
    )

    assert get_latest_user_finding_for_target(2006, "192.168.0.24") == finding
