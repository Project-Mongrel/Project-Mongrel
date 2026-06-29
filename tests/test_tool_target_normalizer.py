import pytest

from app.tools.target_normalizer import normalize_target


@pytest.mark.parametrize(
    ("raw_target", "expected_target"),
    [
        ("https://example.com", "example.com"),
        ("http://example.com", "example.com"),
        ("https://www.example.com/shop", "www.example.com"),
        ("https://example.com:8443/admin", "example.com"),
        ("example.com", "example.com"),
        ("192.168.1.1", "192.168.1.1"),
    ],
)
def test_normalize_target(raw_target: str, expected_target: str) -> None:
    assert normalize_target(raw_target) == expected_target


def test_normalize_target_empty_rejected() -> None:
    with pytest.raises(ValueError, match="cannot be empty"):
        normalize_target("   ")
