from app.services.impact_engine import assess_change_impact


def test_no_material_changes() -> None:
    impact = assess_change_impact({"new_ports": [], "removed_ports": [], "unchanged_ports": []})

    assert impact == {
        "impact_level": "low",
        "summary": "No material exposure changes detected.",
        "impacts": [],
        "recommendations": [],
    }


def test_new_ssh_medium() -> None:
    impact = assess_change_impact({"new_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}]})

    assert impact["impact_level"] == "medium"
    assert "SSH remote administration became exposed." in impact["impacts"]
    assert "Restrict SSH to trusted networks." in impact["recommendations"]


def test_new_smb_high() -> None:
    impact = assess_change_impact({"new_ports": [{"port": "445", "protocol": "tcp", "service": "microsoft-ds"}]})

    assert impact["impact_level"] == "high"
    assert "SMB file sharing became exposed." in impact["impacts"]
    assert "Restrict or disable SMB if not required." in impact["recommendations"]


def test_new_rdp_high() -> None:
    impact = assess_change_impact({"new_ports": [{"port": "3389", "protocol": "tcp", "service": "rdp"}]})

    assert impact["impact_level"] == "high"
    assert "Remote Desktop became exposed." in impact["impacts"]
    assert "Restrict RDP and require strong authentication." in impact["recommendations"]


def test_new_database_high() -> None:
    impact = assess_change_impact({"new_ports": [{"port": "5432", "protocol": "tcp", "service": "postgresql"}]})

    assert impact["impact_level"] == "high"
    assert "Database service became exposed." in impact["impacts"]
    assert "Ensure database access is not public." in impact["recommendations"]


def test_removed_risky_port_reduces_attack_surface() -> None:
    impact = assess_change_impact({"new_ports": [], "removed_ports": [{"port": "445", "protocol": "tcp", "service": "microsoft-ds"}]})

    assert impact["impact_level"] == "low"
    assert "Attack surface reduced." in impact["impacts"]
    assert "No immediate action required." in impact["recommendations"]
