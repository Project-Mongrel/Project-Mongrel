from app.services.findings_store import add_finding, clear_user_findings, get_user_findings


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
