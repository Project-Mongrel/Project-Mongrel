from app.services.verdict_engine import generate_mongrel_verdict


def test_ssh_verdict_generated() -> None:
    verdict = generate_mongrel_verdict(
        {
            "target": "127.0.0.1",
            "risk_level": "medium",
            "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}],
        }
    )

    assert verdict["risk_level"] == "medium"
    assert "SSH remote administration service exposed." in verdict["key_findings"]
    assert "Restrict SSH access to trusted networks." in verdict["recommended_actions"]


def test_smb_verdict_generated() -> None:
    verdict = generate_mongrel_verdict(
        {
            "risk_level": "high",
            "open_ports": [{"port": "445", "protocol": "tcp", "service": "microsoft-ds"}],
        }
    )

    assert "Windows SMB file sharing service exposed." in verdict["key_findings"]
    assert "Restrict or disable SMB if not required." in verdict["recommended_actions"]


def test_rdp_verdict_generated() -> None:
    verdict = generate_mongrel_verdict(
        {
            "risk_level": "high",
            "open_ports": [{"port": "3389", "protocol": "tcp", "service": "ms-wbt-server"}],
        }
    )

    assert "Remote Desktop service exposed." in verdict["key_findings"]
    assert "Restrict RDP access and require strong authentication." in verdict["recommended_actions"]


def test_database_verdict_generated() -> None:
    verdict = generate_mongrel_verdict(
        {
            "risk_level": "high",
            "open_ports": [{"port": "5432", "protocol": "tcp", "service": "postgresql"}],
        }
    )

    assert "Database service exposed." in verdict["key_findings"]
    assert "Ensure database services are not publicly accessible." in verdict["recommended_actions"]


def test_no_open_ports_verdict_generated() -> None:
    verdict = generate_mongrel_verdict({"risk_level": "low", "open_ports": []})

    assert verdict["summary"] == "No open ports were detected."
    assert verdict["key_findings"] == []
    assert verdict["recommended_actions"] == []
