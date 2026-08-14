import pytest

from app.services.bbot_summary import build_bbot_recon_summary
from app.services.findings_store import close_findings_database, configure_findings_database
from app.services.observation_store import add_observation


@pytest.fixture(autouse=True)
def sqlite_observation_store(tmp_path):
    configure_findings_database(tmp_path / "mongrel.db")
    yield
    close_findings_database()
    configure_findings_database(None)


def test_empty_observations() -> None:
    summary = build_bbot_recon_summary(user_id=1001, target="example.com")

    assert "BBOT Recon Summary" in summary
    assert "example.com" in summary
    assert "Observations Collected: 0" in summary
    assert "No significant BBOT discoveries stored yet." in summary
    assert "Continue reconnaissance using additional observation sources." in summary


def test_subdomains_summary() -> None:
    _add(1002, "subdomain", "app.example.com")

    summary = build_bbot_recon_summary(user_id=1002, target="example.com")

    assert "1 subdomains" in summary
    assert "app.example.com" in summary
    assert "Run Nuclei against discovered domains or URLs where authorized." in summary


def test_urls_summary() -> None:
    _add(1003, "url", "https://app.example.com/login")

    summary = build_bbot_recon_summary(user_id=1003, target="example.com")

    assert "1 URLs" in summary
    assert "https://app.example.com/login" in summary
    assert "Run Nuclei against discovered domains or URLs where authorized." in summary


def test_ips_summary() -> None:
    _add(1004, "ip_address", "192.0.2.10")

    summary = build_bbot_recon_summary(user_id=1004, target="example.com")

    assert "1 IP addresses" in summary
    assert "192.0.2.10" in summary


def test_technologies_summary() -> None:
    _add(1005, "technology", "nginx")

    summary = build_bbot_recon_summary(user_id=1005, target="example.com")

    assert "1 technologies" in summary
    assert "nginx" in summary
    assert "Review observed technologies and versions against current advisories where version evidence exists." in summary


def test_certificates_summary() -> None:
    _add(1006, "certificate", "CN=example.com")

    summary = build_bbot_recon_summary(user_id=1006, target="example.com")

    assert "1 certificates" in summary
    assert "CN=example.com" in summary
    assert "Review certificate validity and intended exposure." in summary


def test_emails_summary() -> None:
    _add(1007, "email", "security@example.com")

    summary = build_bbot_recon_summary(user_id=1007, target="example.com")

    assert "1 email addresses" in summary
    assert "security@example.com" in summary


def test_mixed_observations_summary() -> None:
    _add(1008, "subdomain", "app.example.com")
    _add(1008, "url", "https://app.example.com")
    _add(1008, "ip_address", "192.0.2.10")
    _add(1008, "dns_record", "app.example.com A 192.0.2.10")
    _add(1008, "technology", "nginx")
    _add(1008, "certificate", "CN=app.example.com")
    _add(1008, "email", "security@example.com")

    summary = build_bbot_recon_summary(user_id=1008, target="example.com")

    assert "Observations Collected: 7" in summary
    assert "1 subdomains" in summary
    assert "1 URLs" in summary
    assert "1 IP addresses" in summary
    assert "1 DNS records" in summary
    assert "1 technologies" in summary
    assert "1 certificates" in summary
    assert "1 email addresses" in summary


def test_admin_like_host_detection() -> None:
    _add(1009, "subdomain", "admin.example.com")

    summary = build_bbot_recon_summary(user_id=1009, target="example.com")

    assert "Review authentication requirements and intended exposure for admin-like hostnames." in summary


def test_recommendation_generation_is_deterministic() -> None:
    _add(1010, "technology", "nginx")
    _add(1010, "certificate", "CN=example.com")
    _add(1010, "subdomain", "vpn.example.com")

    first = build_bbot_recon_summary(user_id=1010, target="example.com")
    second = build_bbot_recon_summary(user_id=1010, target="example.com")

    assert first == second
    assert first.index("Run Nuclei") < first.index("Review observed technologies")
    assert first.index("Review observed technologies") < first.index("Review certificate")
    assert first.index("Review certificate") < first.index("Review authentication")


def test_filters_by_investigation_and_target() -> None:
    _add(1011, "subdomain", "app.example.com", investigation_id="inv-1", target="example.com")
    _add(1011, "subdomain", "api.other.com", investigation_id="inv-2", target="other.com")

    summary = build_bbot_recon_summary(user_id=1011, investigation_id="inv-1", target="example.com")

    assert "Observations Collected: 1" in summary
    assert "app.example.com" in summary
    assert "api.other.com" not in summary


def _add(
    user_id: int,
    observation_type: str,
    value: str,
    investigation_id: str = "inv-1",
    target: str = "example.com",
) -> None:
    add_observation(
        user_id=user_id,
        investigation_id=investigation_id,
        source="bbot",
        observation_type=observation_type,
        value=value,
        target=target,
    )
