from app.services.risk_rules import assess_nmap_ports


def test_no_open_ports_low() -> None:
    assert assess_nmap_ports([]) == {"risk_level": "low", "risk_notes": []}


def test_web_only_low() -> None:
    assert assess_nmap_ports(
        [
            {"port": "80", "protocol": "tcp", "service": "http"},
            {"port": "443", "protocol": "tcp", "service": "https"},
        ]
    ) == {"risk_level": "low", "risk_notes": []}


def test_ssh_medium() -> None:
    assessment = assess_nmap_ports([{"port": "22", "protocol": "tcp", "service": "ssh"}])

    assert assessment["risk_level"] == "medium"
    assert assessment["risk_notes"] == ["SSH exposed"]


def test_smb_high() -> None:
    assessment = assess_nmap_ports([{"port": "445", "protocol": "tcp", "service": "microsoft-ds"}])

    assert assessment["risk_level"] == "high"
    assert assessment["risk_notes"] == ["SMB exposed"]


def test_rdp_high() -> None:
    assessment = assess_nmap_ports([{"port": "3389", "protocol": "tcp", "service": "ms-wbt-server"}])

    assert assessment["risk_level"] == "high"
    assert assessment["risk_notes"] == ["RDP exposed"]


def test_database_port_high() -> None:
    assessment = assess_nmap_ports([{"port": "5432", "protocol": "tcp", "service": "postgresql"}])

    assert assessment["risk_level"] == "high"
    assert assessment["risk_notes"] == ["Database port exposed"]


def test_many_ports_medium() -> None:
    open_ports = [{"port": str(port), "protocol": "tcp", "service": "unknown"} for port in range(1000, 1010)]

    assessment = assess_nmap_ports(open_ports)

    assert assessment["risk_level"] == "medium"
    assert assessment["risk_notes"] == ["Many open ports"]
