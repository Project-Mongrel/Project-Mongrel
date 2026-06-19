from app.services.target_normalizer import normalize_target_key


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
