from app.services.comparison_engine import compare_findings


def test_no_previous_finding() -> None:
    comparison = compare_findings(None, {"risk_level": "low", "open_ports": []})

    assert comparison["has_previous"] is False
    assert comparison["summary"] == "No previous scan found for this target."


def test_new_port_detected() -> None:
    comparison = compare_findings(
        {"risk_level": "low", "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}]},
        {
            "risk_level": "high",
            "open_ports": [
                {"port": "22", "protocol": "tcp", "service": "ssh"},
                {"port": "3389", "protocol": "tcp", "service": "rdp"},
            ],
        },
    )

    assert comparison["new_ports"] == [{"port": "3389", "protocol": "tcp", "service": "rdp"}]


def test_removed_port_detected() -> None:
    comparison = compare_findings(
        {
            "risk_level": "high",
            "open_ports": [
                {"port": "22", "protocol": "tcp", "service": "ssh"},
                {"port": "445", "protocol": "tcp", "service": "microsoft-ds"},
            ],
        },
        {"risk_level": "medium", "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}]},
    )

    assert comparison["removed_ports"] == [{"port": "445", "protocol": "tcp", "service": "microsoft-ds"}]


def test_unchanged_port_detected() -> None:
    comparison = compare_findings(
        {"risk_level": "medium", "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}]},
        {"risk_level": "medium", "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}]},
    )

    assert comparison["unchanged_ports"] == [{"port": "22", "protocol": "tcp", "service": "ssh"}]


def test_risk_change_detected() -> None:
    comparison = compare_findings(
        {"risk_level": "medium", "open_ports": [{"port": "22", "protocol": "tcp", "service": "ssh"}]},
        {"risk_level": "high", "open_ports": [{"port": "445", "protocol": "tcp", "service": "microsoft-ds"}]},
    )

    assert comparison["risk_changed"] is True
    assert comparison["previous_risk"] == "medium"
    assert comparison["current_risk"] == "high"
