from unittest.mock import patch

import pytest

from app.services.bbot_ai_assessment import (
    BBOT_AI_NUM_PREDICT,
    FALLBACK_LINES,
    build_bbot_ai_assessment_prompt,
    generate_bbot_ai_assessment,
)
from app.parsers.bbot_normalizer import normalize_bbot_output
from app.services.findings_store import close_findings_database, configure_findings_database
from app.services.investigation_store import create_investigation
from app.services.observation_store import add_observation


@pytest.fixture(autouse=True)
def sqlite_observation_store(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def test_prompt_is_grounded() -> None:
    prompt = build_bbot_ai_assessment_prompt(
        observations=[_observation("subdomain", "admin.example.com")],
        recon_summary="BBOT Recon Summary\n- admin.example.com",
        investigation={"id": "inv-1", "name": "Investigation", "target": "example.com", "status": "open"},
        target="example.com",
    )

    assert "senior penetration tester preparing reconnaissance notes for another security consultant" in prompt
    assert "Only use the supplied normalized evidence and deterministic Recon Summary." in prompt
    assert "Do not invent vulnerabilities." in prompt
    assert "Do not invent assets, findings, technologies, ports, or certificates." in prompt
    assert "Do not claim compromise." in prompt
    assert "Do not recommend exploitation." in prompt
    assert "Use cautious validation language" in prompt
    assert "Confidence must be High, Medium, or Low" in prompt
    assert "Executive Summary" in prompt
    assert "Observed Facts" in prompt
    assert "Key Findings" not in prompt
    assert "Observed Assets" in prompt
    assert "Potential Risks" in prompt
    assert "Recommended Next Actions" in prompt
    assert "Never speculate." in prompt
    assert "Never infer compromise." in prompt
    assert "Never imply a vulnerability without explicit supporting evidence." in prompt
    assert "Do not infer target ownership from IP associations or DNS data." in prompt
    assert "Do not infer active services from discovered domains, URLs, or technology names alone." in prompt
    assert "Technology identification is not vulnerability evidence." in prompt
    assert "Reconnaissance is not exploitation." in prompt
    assert "Interpretation" in prompt
    assert "Limitations" in prompt
    assert "No confirmed vulnerabilities were identified during reconnaissance" not in prompt


def test_prompt_uses_normalized_evidence_not_raw_output() -> None:
    observation = _observation("subdomain", "app.example.com")
    observation["metadata"] = {
        "raw_output": "RAW BBOT STDOUT SHOULD NOT APPEAR",
        "module": "spasmodic_melvin",
        "scan_name": "spasmodic_melvin",
    }

    prompt = build_bbot_ai_assessment_prompt(
        observations=[observation],
        recon_summary="BBOT Recon Summary",
        target="example.com",
    )

    assert "app.example.com" in prompt
    assert "RAW BBOT STDOUT SHOULD NOT APPEAR" not in prompt
    assert "spasmodic_melvin" not in prompt
    assert "metadata" not in prompt.lower()


def test_prompt_never_contains_tool_or_internal_terms() -> None:
    observation = _observation("technology", "nginx")
    observation["source"] = "bbot"
    observation["summary"] = "BBOT identified technology from module httpx"

    prompt = build_bbot_ai_assessment_prompt(
        observations=[observation],
        recon_summary="BBOT Recon Summary\nRaw Events: 2\nstdout: hidden\nstderr: hidden",
        investigation={"id": "internal-id", "name": "spasmodic_melvin", "target": "example.com", "status": "open"},
        target="example.com",
    )
    forbidden_terms = [
        "bbot",
        "spasmodic_melvin",
        "module",
        "stdout",
        "stderr",
        "json",
        "ansible",
        "dependency installation",
        "implementation details",
        "internal-id",
        "observation store",
    ]

    assert "nginx" in prompt
    assert all(term not in prompt.lower() for term in forbidden_terms)


def test_successful_ai_response() -> None:
    investigation = create_investigation(user_id=11001, target="example.com")
    add_observation(
        user_id=11001,
        investigation_id=investigation["id"],
        source="bbot",
        observation_type="subdomain",
        value="admin.example.com",
        target="example.com",
    )
    ai_response = "\n".join(
        [
            "Executive Summary",
            "- Several externally visible assets were observed.",
            "Observed Facts",
            "- admin.example.com was observed.",
            "Confidence:",
            "Medium",
        ]
    )

    with patch("app.services.bbot_ai_assessment.ask_ai", return_value=ai_response):
        lines = generate_bbot_ai_assessment(11001, investigation_id=investigation["id"], target="example.com")

    assert lines == ai_response.splitlines()


def test_ai_disabled_fallback() -> None:
    investigation = create_investigation(user_id=11002, target="example.com")
    add_observation(
        user_id=11002,
        investigation_id=investigation["id"],
        source="bbot",
        observation_type="subdomain",
        value="app.example.com",
        target="example.com",
    )

    with patch("app.services.bbot_ai_assessment.ask_ai", return_value="AI integration is not configured yet."):
        assert generate_bbot_ai_assessment(11002, investigation_id=investigation["id"], target="example.com") == FALLBACK_LINES


def test_ai_error_fallback() -> None:
    investigation = create_investigation(user_id=11003, target="example.com")
    add_observation(
        user_id=11003,
        investigation_id=investigation["id"],
        source="bbot",
        observation_type="url",
        value="https://app.example.com",
        target="example.com",
    )

    with patch("app.services.bbot_ai_assessment.ask_ai", side_effect=RuntimeError("boom")):
        assert generate_bbot_ai_assessment(11003, investigation_id=investigation["id"], target="example.com") == FALLBACK_LINES


def test_empty_observations_returns_limited_evidence_assessment() -> None:
    lines = generate_bbot_ai_assessment(11004, target="example.com")
    text = "\n".join(lines)

    assert "Executive Summary" in text
    assert "Observed Facts" in text
    assert "Observed Assets" in text
    assert "Potential Risks" in text
    assert "Confidence\nLow" in text
    assert "Recommended Next Actions" in text
    assert "Evidence is limited" in text
    assert "No vulnerability or compromise conclusion can be drawn" in text
    assert "Limited reconnaissance output does not prove the target is secure or that no vulnerabilities exist." in text
    assert "BBOT" not in text
    assert "Observation Store" not in text


def test_confidence_section_exists() -> None:
    lines = generate_bbot_ai_assessment(11005, target="example.com")

    assert "Confidence" in lines


def test_ai_response_scanner_internals_are_removed() -> None:
    investigation = create_investigation(user_id=11006, target="example.com")
    add_observation(
        user_id=11006,
        investigation_id=investigation["id"],
        source="bbot",
        observation_type="subdomain",
        value="app.example.com",
        target="example.com",
    )
    ai_response = "\n".join(
        [
            "Executive Summary",
            "- app.example.com was observed.",
            "- BBOT module spasmodic_melvin wrote JSON to stdout.",
            "Confidence:",
            "Medium",
            "Recommended Next Actions",
            "- Enumerate discovered web applications.",
        ]
    )

    with patch("app.services.bbot_ai_assessment.ask_ai", return_value=ai_response):
        lines = generate_bbot_ai_assessment(11006, investigation_id=investigation["id"], target="example.com")

    text = "\n".join(lines)
    assert "app.example.com was observed" in text
    assert "Enumerate discovered web applications" in text
    assert "spasmodic_melvin" not in text
    assert "stdout" not in text


def test_ai_response_speculation_from_technology_is_removed() -> None:
    investigation = create_investigation(user_id=11007, target="example.com")
    add_observation(
        user_id=11007,
        investigation_id=investigation["id"],
        source="bbot",
        observation_type="technology",
        value="Apache HTTP Server",
        target="example.com",
    )
    ai_response = "\n".join(
        [
            "Executive Summary",
            "- Apache HTTP Server detected.",
            "Observed Facts",
            "- Apache HTTP Server detected.",
            "Potential Risks",
            "- Apache is likely vulnerable.",
            "- Detected software versions should be validated against current CVEs.",
            "Recommended Next Actions",
            "- Review detected software versions.",
        ]
    )

    with patch("app.services.bbot_ai_assessment.ask_ai", return_value=ai_response):
        lines = generate_bbot_ai_assessment(11007, investigation_id=investigation["id"], target="example.com")

    text = "\n".join(lines)
    assert "Apache HTTP Server detected." in text
    assert "Detected software versions should be validated against current CVEs." in text
    assert "Review detected software versions." in text
    assert "likely vulnerable" not in text


def test_ai_response_social_media_risk_inference_is_removed() -> None:
    investigation = create_investigation(user_id=11008, target="example.com")
    add_observation(
        user_id=11008,
        investigation_id=investigation["id"],
        source="bbot",
        observation_type="social_profile",
        value="https://github.com/example",
        target="example.com",
    )
    ai_response = "\n".join(
        [
            "Observed Facts",
            "- GitHub profile referenced.",
            "Potential Risks",
            "- Popular social media platforms suggest potential exposure.",
            "- Public repositories should be reviewed for exposed secrets.",
            "Recommended Next Actions",
            "- Inspect public repositories for exposed credentials.",
        ]
    )

    with patch("app.services.bbot_ai_assessment.ask_ai", return_value=ai_response):
        lines = generate_bbot_ai_assessment(11008, investigation_id=investigation["id"], target="example.com")

    text = "\n".join(lines)
    assert "GitHub profile referenced." in text
    assert "Public repositories should be reviewed for exposed secrets." in text
    assert "Inspect public repositories for exposed credentials." in text
    assert "suggest" not in text.lower()
    assert "potential exposure" not in text.lower()


def test_ai_response_distinguishes_observations_from_recommendations() -> None:
    investigation = create_investigation(user_id=11009, target="example.com")
    add_observation(
        user_id=11009,
        investigation_id=investigation["id"],
        source="bbot",
        observation_type="url",
        value="https://app.example.com",
        target="example.com",
    )
    ai_response = "\n".join(
        [
            "Observed Facts",
            "- Public HTTP endpoint discovered.",
            "Potential Risks",
            "- Public-facing services should undergo vulnerability assessment.",
            "Recommended Next Actions",
            "- Run Nuclei against discovered domains or URLs where authorized.",
            "- Enumerate identified web applications.",
        ]
    )

    with patch("app.services.bbot_ai_assessment.ask_ai", return_value=ai_response):
        lines = generate_bbot_ai_assessment(11009, investigation_id=investigation["id"], target="example.com")

    text = "\n".join(lines)
    assert text.index("Observed Facts") < text.index("Recommended Next Actions")
    assert "- Public HTTP endpoint discovered." in text
    assert "- Run Nuclei against discovered domains or URLs where authorized." in text


def test_prompt_includes_discovered_subdomains_and_urls() -> None:
    prompt = build_bbot_ai_assessment_prompt(
        observations=[
            _observation("subdomain", "app.example.com"),
            _observation("url", "https://app.example.com/login"),
        ],
        recon_summary="BBOT Recon Summary",
        target="example.com",
    )

    assert "DNS names: app.example.com" in prompt
    assert "URLs: https://app.example.com/login" in prompt


def test_prompt_includes_technology_and_dns_without_vulnerability_shortcut() -> None:
    prompt = build_bbot_ai_assessment_prompt(
        observations=[
            _observation("technology", "nginx"),
            _observation("dns_record", "app.example.com A 192.0.2.10"),
        ],
        recon_summary="BBOT Recon Summary",
        target="example.com",
    )

    assert "Technologies: nginx" in prompt
    assert "DNS records: app.example.com A 192.0.2.10" in prompt
    assert "Technology identification is not vulnerability evidence." in prompt


def test_prompt_includes_ip_and_email_without_ownership_or_breach_claims() -> None:
    prompt = build_bbot_ai_assessment_prompt(
        observations=[
            _observation("ip_address", "192.0.2.10"),
            _observation("email", "security@example.com"),
        ],
        recon_summary="BBOT Recon Summary",
        target="example.com",
    )

    assert "IP addresses: 192.0.2.10" in prompt
    assert "Email addresses: security@example.com" in prompt
    assert "Do not infer target ownership from IP associations or DNS data." in prompt
    assert "Do not infer sensitive data exposure, breach, or insecure configuration from discovery evidence alone." in prompt


def test_open_tcp_port_normalizes_as_open_port_not_ip_address() -> None:
    observations = normalize_bbot_output(
        "\n".join([
            '{"type":"OPEN_TCP_PORT","data":"btjoinery.ie:443"}',
            '{"type":"IP_ADDRESS","data":"192.0.2.10"}',
        ]),
        "btjoinery.ie",
        11012,
        investigation_id="inv-live",
    )

    by_value = {observation["value"]: observation["observation_type"] for observation in observations}
    assert by_value["btjoinery.ie:443"] == "open_port"
    assert by_value["192.0.2.10"] == "ip_address"


def test_bbot_ai_uses_dedicated_output_budget() -> None:
    investigation = create_investigation(user_id=11013, target="example.com")
    add_observation(
        user_id=11013,
        investigation_id=investigation["id"],
        source="bbot",
        observation_type="subdomain",
        value="app.example.com",
        target="example.com",
    )

    with patch("app.services.bbot_ai_assessment.ask_ai", return_value="Executive Summary\n- app.example.com was observed.") as ask_ai:
        generate_bbot_ai_assessment(11013, investigation_id=investigation["id"], target="example.com")

    assert ask_ai.call_args.kwargs["num_predict"] == BBOT_AI_NUM_PREDICT
    assert ask_ai.call_args.kwargs["path"] == "bbot_ai_assessment"


def test_live_shape_fallback_preserves_counts_and_no_ownership_inference() -> None:
    observations = _live_shape_observations()
    ai_response = "\n".join([
        "Executive Summary",
        "- The target is part of Blacknight infrastructure.",
        "Observed Facts",
        "- No active services or technologies were identified.",
    ])

    with patch("app.services.bbot_ai_assessment.ask_ai", return_value=ai_response):
        lines = generate_bbot_ai_assessment(
            11014,
            target="btjoinery.ie",
            observations=observations,
            recon_summary="BBOT Recon Summary",
        )

    text = "\n".join(lines)
    assert "DNS names/subdomains: 9" in text
    assert "IP addresses: 6" in text
    assert "DNS records: 19" in text
    assert "Open-port endpoints: 5" in text
    assert "Technologies: 0" in text
    assert "target is part of Blacknight infrastructure" not in text
    assert "No active services or technologies were identified" not in text
    assert "observed infrastructure relationships only" in text
    assert "not proof that the target is owned by or part of a provider" in text


@pytest.mark.parametrize(
    "bad_claim",
    [
        "No active services were identified.",
        "No active services or technologies were identified.",
        "The target is part of Blacknight infrastructure.",
        "The domain belongs to Blacknight infrastructure.",
    ],
)
def test_bbot_unsupported_live_claim_classes_fall_back(bad_claim: str) -> None:
    observations = [_observation("subdomain", "www.example.com")]

    with patch("app.services.bbot_ai_assessment.ask_ai", return_value=f"Executive Summary\n- {bad_claim}"):
        lines = generate_bbot_ai_assessment(
            11015,
            target="example.com",
            observations=observations,
            recon_summary="BBOT Recon Summary",
        )

    text = "\n".join(lines)
    assert bad_claim not in text
    assert "Normalized reconnaissance evidence" in text
    assert "do not prove ownership" in text


@pytest.mark.parametrize(
    "truncated_response",
    [
        "Executive Summary\n- Findings are based on DNS records and IP",
        "Executive Summary\n- One subdomain was observed.\n\n**Observed Assets",
    ],
)
def test_bbot_truncated_response_uses_grounded_fallback(truncated_response: str) -> None:
    observations = [_observation("subdomain", "www.example.com")]

    with patch("app.services.bbot_ai_assessment.ask_ai", return_value=truncated_response):
        lines = generate_bbot_ai_assessment(
            11016,
            target="example.com",
            observations=observations,
            recon_summary="BBOT Recon Summary",
        )

    text = "\n".join(lines)
    assert "Normalized reconnaissance evidence" in text
    assert "Observed Assets" in text
    assert "Findings are based on DNS records and IP" not in text


@pytest.mark.parametrize(
    "unsupported_claim",
    [
        "The target is insecure.",
        "These subdomains are vulnerable.",
    ],
)
def test_unsupported_recon_security_claims_are_withheld(unsupported_claim: str) -> None:
    investigation = create_investigation(user_id=11010, target="example.com")
    add_observation(
        user_id=11010,
        investigation_id=investigation["id"],
        source="bbot",
        observation_type="subdomain",
        value="app.example.com",
        target="example.com",
    )

    with patch("app.services.bbot_ai_assessment.ask_ai", return_value=f"Executive Summary\n- {unsupported_claim}"):
        lines = generate_bbot_ai_assessment(11010, investigation_id=investigation["id"], target="example.com")

    text = "\n".join(lines)
    assert "Normalized reconnaissance evidence" in text
    assert unsupported_claim not in text


@pytest.mark.parametrize(
    "legitimate_statement",
    [
        "BBOT discovered 12 subdomains.",
        "This discovery does not establish a vulnerability.",
    ],
)
def test_evidence_scoped_recon_statements_are_allowed(legitimate_statement: str) -> None:
    investigation = create_investigation(user_id=11011, target="example.com")
    add_observation(
        user_id=11011,
        investigation_id=investigation["id"],
        source="bbot",
        observation_type="subdomain",
        value="app.example.com",
        target="example.com",
    )

    ai_response = f"Executive Summary\n- {legitimate_statement}\nConfidence\nMedium"

    with patch("app.services.bbot_ai_assessment.ask_ai", return_value=ai_response):
        lines = generate_bbot_ai_assessment(11011, investigation_id=investigation["id"], target="example.com")

    assert legitimate_statement in "\n".join(lines)


def _observation(observation_type: str, value: str) -> dict:
    return {
        "source": "bbot",
        "observation_type": observation_type,
        "value": value,
        "target": "example.com",
        "confidence": "medium",
        "risk_level": "info",
        "summary": f"BBOT identified {observation_type}: {value}",
    }


def _live_shape_observations() -> list[dict]:
    observations: list[dict] = []
    subdomains = [
        "btjoinery.ie",
        "www.btjoinery.ie",
        "ns1.blacknight.com",
        "ns2.blacknight.com",
        "ns3.blacknight.com",
        "ns4.blacknight.com",
        "btjoinery-ie.mail.protection.outlook.com",
        "ext-cust.squarespace.com",
        "autodiscover.btjoinery.ie",
    ]
    ips = ["198.51.100.10", "198.51.100.11", "198.51.100.12", "192.0.2.20", "192.0.2.21", "203.0.113.44"]
    dns_records = [f"host{index}.btjoinery.ie A 192.0.2.{index}" for index in range(1, 20)]
    open_ports = [
        "btjoinery.ie:80",
        "btjoinery.ie:443",
        "www.btjoinery.ie:443",
        "btjoinery-ie.mail.protection.outlook.com:25",
        "btjoinery-ie.mail.protection.outlook.com:80",
    ]
    for value in subdomains:
        observations.append(_observation("subdomain", value))
    for value in ips:
        observations.append(_observation("ip_address", value))
    for value in dns_records:
        observations.append(_observation("dns_record", value))
    for value in open_ports:
        observations.append(_observation("open_port", value))
    assert len(observations) == 39
    return observations
