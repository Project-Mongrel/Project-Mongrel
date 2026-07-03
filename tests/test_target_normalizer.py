import pytest

from app.services.target_normalizer import (
    normalize_for_bbot,
    normalize_for_ffuf,
    normalize_for_httpx,
    normalize_for_katana,
    normalize_for_nmap,
    normalize_for_nuclei,
    normalize_for_playwright,
    normalize_target_key,
)


def test_none_or_empty_target_returns_none() -> None:
    assert normalize_target_key(None) is None
    assert normalize_target_key("   ") is None


def test_parenthesized_localhost_ip_normalizes_to_ip() -> None:
    assert normalize_target_key("localhost (127.0.0.1)") == "127.0.0.1"


def test_parenthesized_desktop_ip_normalizes_to_ip() -> None:
    assert normalize_target_key("DESKTOP-MSP5KSM (192.168.0.24)") == "192.168.0.24"


def test_plain_ipv4_returns_ip() -> None:
    assert normalize_target_key("127.0.0.1") == "127.0.0.1"


def test_hostname_matching_is_lowercase() -> None:
    assert normalize_target_key("Example.COM") == "example.com"


@pytest.mark.parametrize(
    ("raw_target", "expected_target"),
    [
        ("scanme.nmap.org", "scanme.nmap.org"),
        ("https://scanme.nmap.org", "scanme.nmap.org"),
        ("Https://scanme.nmap.org", "scanme.nmap.org"),
        ("http://example.com/path?x=1", "example.com"),
        ("www.example.com", "www.example.com"),
        ("192.168.1.10", "192.168.1.10"),
    ],
)
def test_normalize_for_nmap(raw_target: str, expected_target: str) -> None:
    assert normalize_for_nmap(raw_target) == expected_target


@pytest.mark.parametrize(
    ("raw_target", "expected_target"),
    [
        ("scanme.nmap.org", "scanme.nmap.org"),
        ("https://scanme.nmap.org", "scanme.nmap.org"),
        ("Https://scanme.nmap.org", "scanme.nmap.org"),
        ("http://example.com/path?x=1", "example.com"),
        ("www.example.com", "www.example.com"),
        ("192.168.1.10", "192.168.1.10"),
    ],
)
def test_normalize_for_bbot(raw_target: str, expected_target: str) -> None:
    assert normalize_for_bbot(raw_target) == expected_target


@pytest.mark.parametrize(
    ("raw_target", "expected_target"),
    [
        ("scanme.nmap.org", "https://scanme.nmap.org"),
        ("https://scanme.nmap.org", "https://scanme.nmap.org"),
        ("Https://scanme.nmap.org", "https://scanme.nmap.org"),
        ("http://example.com/path?x=1", "http://example.com/path?x=1"),
        ("www.example.com", "https://www.example.com"),
        ("192.168.1.10", "https://192.168.1.10"),
    ],
)
def test_normalize_for_nuclei(raw_target: str, expected_target: str) -> None:
    assert normalize_for_nuclei(raw_target) == expected_target


@pytest.mark.parametrize(
    ("raw_target", "expected_target"),
    [
        ("scanme.nmap.org", "https://scanme.nmap.org"),
        ("https://scanme.nmap.org", "https://scanme.nmap.org"),
        ("http://example.com/path?x=1", "http://example.com/path?x=1"),
    ],
)
def test_normalize_for_httpx(raw_target: str, expected_target: str) -> None:
    assert normalize_for_httpx(raw_target) == expected_target


@pytest.mark.parametrize(
    ("raw_target", "expected_target"),
    [
        ("scanme.nmap.org", "https://scanme.nmap.org"),
        ("https://scanme.nmap.org", "https://scanme.nmap.org"),
        ("http://example.com/path?x=1", "http://example.com/path?x=1"),
    ],
)
def test_normalize_for_katana(raw_target: str, expected_target: str) -> None:
    assert normalize_for_katana(raw_target) == expected_target


@pytest.mark.parametrize(
    ("raw_target", "expected_target"),
    [
        ("scanme.nmap.org", "https://scanme.nmap.org"),
        ("https://scanme.nmap.org", "https://scanme.nmap.org"),
        ("http://example.com/path?x=1", "http://example.com/path?x=1"),
    ],
)
def test_normalize_for_playwright(raw_target: str, expected_target: str) -> None:
    assert normalize_for_playwright(raw_target) == expected_target


@pytest.mark.parametrize(
    ("raw_target", "expected_target"),
    [
        ("scanme.nmap.org", "https://scanme.nmap.org"),
        ("https://scanme.nmap.org", "https://scanme.nmap.org"),
        ("http://example.com/path?x=1", "http://example.com/path?x=1"),
    ],
)
def test_normalize_for_ffuf(raw_target: str, expected_target: str) -> None:
    assert normalize_for_ffuf(raw_target) == expected_target


@pytest.mark.parametrize(
    "normalizer",
    [normalize_for_nmap, normalize_for_bbot, normalize_for_nuclei, normalize_for_httpx, normalize_for_katana, normalize_for_playwright, normalize_for_ffuf],
)
def test_unsupported_scheme_rejected(normalizer: object) -> None:
    with pytest.raises(ValueError, match="valid http or https URL or hostname"):
        normalizer("ftp://example.com")


@pytest.mark.parametrize(
    "normalizer",
    [normalize_for_nmap, normalize_for_bbot, normalize_for_nuclei, normalize_for_httpx, normalize_for_katana, normalize_for_playwright, normalize_for_ffuf],
)
def test_empty_input_rejected(normalizer: object) -> None:
    with pytest.raises(ValueError, match="cannot be empty"):
        normalizer("   ")


@pytest.mark.parametrize(
    "normalizer",
    [normalize_for_nmap, normalize_for_bbot, normalize_for_nuclei, normalize_for_httpx, normalize_for_katana, normalize_for_playwright, normalize_for_ffuf],
)
def test_malformed_input_rejected(normalizer: object) -> None:
    with pytest.raises(ValueError, match="malformed|valid http or https"):
        normalizer("https:///scanme.nmap.org")
