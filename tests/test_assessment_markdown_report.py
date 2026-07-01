from datetime import UTC, datetime

from app.services.assessment_markdown_report import generate_assessment_markdown_report


def test_assessment_markdown_report_handles_empty_assessment() -> None:
    report = generate_assessment_markdown_report(
        {
            "assessment": {
                "name": "Empty Assessment",
                "status": "active",
                "created_at": datetime(2026, 1, 1, tzinfo=UTC),
                "updated_at": datetime(2026, 1, 2, tzinfo=UTC),
            },
            "targets": [],
            "scans": [],
            "findings": [],
            "artifacts": [],
            "notes": [],
        }
    )

    assert report.startswith("# Assessment Report")
    assert "Assessment Name: Empty Assessment" in report
    assert "Primary Target(s):\n- Not set" in report
    assert "No completed assessment scans are recorded" in report
    assert "## Evidence Limitations" in report
    assert "- Absence of findings is not evidence of security." in report


def test_assessment_markdown_report_renders_multi_tool_evidence() -> None:
    context = {
        "assessment": {
            "name": "External Assessment",
            "status": "active",
            "created_at": datetime(2026, 1, 1, tzinfo=UTC),
            "updated_at": datetime(2026, 1, 2, tzinfo=UTC),
        },
        "targets": [{"address": "scanme.nmap.org"}],
        "scans": [
            {
                "tool": "nmap",
                "status": "completed",
                "risk": "medium",
                "completed_at": datetime(2026, 1, 1, 10, tzinfo=UTC),
                "finding": {
                    "summary": "SSH and HTTP observed.",
                    "target": "scanme.nmap.org",
                    "risk_level": "medium",
                    "open_ports": [
                        {"port": "22", "protocol": "tcp", "service": "ssh"},
                        {"port": "80", "protocol": "tcp", "service": "http"},
                    ],
                },
            },
            {
                "tool": "bbot",
                "status": "completed",
                "risk": "info",
                "completed_at": datetime(2026, 1, 1, 11, tzinfo=UTC),
                "finding": {
                    "summary": "Reconnaissance observations collected.",
                    "target": "scanme.nmap.org",
                    "observation_counts": {"subdomain": 2, "url": 3, "technology": 1},
                },
            },
            {
                "tool": "nuclei",
                "status": "completed",
                "risk": "high",
                "completed_at": datetime(2026, 1, 1, 12, tzinfo=UTC),
                "finding": {
                    "summary": "One matched finding observed.",
                    "target": "https://scanme.nmap.org",
                    "risk_level": "high",
                    "nuclei_findings": [
                        {
                            "name": "Example finding",
                            "template_id": "example-template",
                            "severity": "high",
                            "matched_at": "https://scanme.nmap.org/login",
                            "technology": "Apache",
                        }
                    ],
                },
            },
        ],
        "findings": [
            {
                "target": "scanme.nmap.org",
                "open_ports": [
                    {"port": "22", "protocol": "tcp", "service": "ssh"},
                    {"port": "80", "protocol": "tcp", "service": "http"},
                ],
            },
            {"target": "scanme.nmap.org", "observation_counts": {"subdomain": 2, "url": 3, "technology": 1}},
            {
                "target": "https://scanme.nmap.org",
                "nuclei_findings": [
                    {
                        "name": "Example finding",
                        "severity": "high",
                        "matched_at": "https://scanme.nmap.org/login",
                        "technology": "Apache",
                    }
                ],
            },
        ],
        "artifacts": [],
        "notes": [],
    }

    report = generate_assessment_markdown_report(context)

    assert "### Nmap" in report
    assert "### BBOT" in report
    assert "### Nuclei" in report
    assert "SSH and HTTP observed." in report
    assert "- 22/tcp ssh" in report
    assert "- Example finding (HIGH)" in report
    assert "Services\n- 22/tcp ssh\n- 80/tcp http" in report
    assert "Technologies\n- Apache" in report
    assert "## Assessment History" in report
    assert "Nmap Completed - Risk: MEDIUM" in report
    assert "- Review SSH exposure, authentication policy, and network access restrictions." in report
    assert "- Only completed tools are represented in the scan summary." in report
