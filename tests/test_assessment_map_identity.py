import json

import pytest

from app.services.assessment_map_identity import (
    IDENTITY_SCHEMA_VERSION,
    canonical_application_origin,
    canonical_endpoint,
    canonical_finding,
    canonical_hostname,
    canonical_ip,
    canonical_service,
    canonical_technology,
    identity_from_payload,
)


def test_hostname_idna_lowercase_and_one_trailing_dot() -> None:
    identity = canonical_hostname("BÜCHER.Example.")
    assert identity.payload == {"hostname": "xn--bcher-kva.example"}
    assert "BÜCHER" not in identity.canonical_key
    with pytest.raises(ValueError, match="Invalid hostname"):
        canonical_hostname("example.com..")


def test_ipv4_and_ipv6_use_canonical_compressed_forms() -> None:
    assert canonical_ip("192.0.2.10").payload == {"address": "192.0.2.10"}
    assert canonical_ip("2001:0db8:0:0:0:0:0:1").payload == {"address": "2001:db8::1"}


def test_service_identity_validates_transport_and_port() -> None:
    service = canonical_service("Example.COM.", "TCP", 443)
    assert service.payload["transport"] == "tcp"
    assert service.payload["port"] == 443
    with pytest.raises(ValueError, match="port"):
        canonical_service("example.com", "tcp", 0)


def test_origin_omits_default_port_and_preserves_non_default_port() -> None:
    default = canonical_application_origin("HTTPS://Example.com:443/path")
    implicit = canonical_application_origin("https://example.com/")
    non_default = canonical_application_origin("https://example.com:8443/")
    assert default.identity_hash == implicit.identity_hash
    assert "port" not in default.payload
    assert non_default.payload["port"] == 8443
    assert non_default.identity_hash != default.identity_hash


def test_ipv6_origins_are_canonical_and_default_ports_are_omitted() -> None:
    expanded = canonical_application_origin("https://[2001:0db8:0:0:0:0:0:1]:443/path")
    compressed = canonical_application_origin("https://[2001:db8::1]/")
    non_default = canonical_application_origin("https://[2001:db8::1]:8443/")
    assert expanded.identity_hash == compressed.identity_hash
    assert "port" not in expanded.payload
    assert non_default.payload["port"] == 8443


def test_endpoint_drops_credentials_fragment_and_query_values_but_keeps_names() -> None:
    endpoint = canonical_endpoint(
        "https://alice:secret@Example.com:443/Admin/Login?token=private&q=One&q=Two&empty=#section"
    )
    assert endpoint.payload["path"] == "/Admin/Login"
    assert endpoint.payload["query_parameter_names"] == ["empty", "q", "token"]
    assert all(value not in endpoint.canonical_key for value in ("alice", "secret", "private", "section", "One", "Two"))


def test_endpoint_drops_percent_encoded_credentials_and_query_values() -> None:
    endpoint = canonical_endpoint(
        "https://alice%40example:sec%2Fret@example.com/path?token=sec%72et&name=private%20value#hidden"
    )
    assert endpoint.payload["query_parameter_names"] == ["name", "token"]
    assert all(
        value not in endpoint.canonical_key
        for value in ("alice", "sec%2Fret", "secret", "private%20value", "hidden")
    )


def test_endpoint_path_case_is_preserved_without_semantic_collapsing() -> None:
    upper = canonical_endpoint("https://example.com/A/../B")
    lower = canonical_endpoint("https://example.com/a/../B")
    assert upper.payload["path"] == "/A/../B"
    assert lower.payload["path"] == "/a/../B"
    assert upper.identity_hash != lower.identity_hash


def test_identity_hash_is_versioned_sorted_and_deterministic() -> None:
    first = identity_from_payload("technology", {"b": 2, "a": 1})
    second = identity_from_payload("technology", {"a": 1, "b": 2})
    assert first.version == IDENTITY_SCHEMA_VERSION
    assert first.canonical_key == second.canonical_key
    assert first.identity_hash == second.identity_hash
    envelope = json.loads(first.canonical_key)
    assert envelope["version"] == IDENTITY_SCHEMA_VERSION


def test_missing_null_and_zero_remain_distinct() -> None:
    missing = identity_from_payload("technology", {})
    null = identity_from_payload("technology", {"version": None})
    zero = identity_from_payload("technology", {"version": 0})
    assert len({missing.identity_hash, null.identity_hash, zero.identity_hash}) == 3


def test_technology_version_is_not_part_of_product_identity() -> None:
    first = canonical_technology("  NGINX ", version="1.24")
    second = canonical_technology("nginx", version="1.25")
    assert first.payload == {"product": "nginx"}
    assert first.identity_hash == second.identity_hash


def test_finding_uses_stable_tool_identifier_and_affected_surface() -> None:
    surface = canonical_endpoint("https://example.com/login")
    first = canonical_finding("Nuclei", "weak-hsts", surface, matcher="header")
    second = canonical_finding("nuclei", "weak-hsts", surface, matcher="header")
    other = canonical_finding("nuclei", "weak-hsts", canonical_endpoint("https://example.com/admin"), matcher="header")
    assert first.identity_hash == second.identity_hash
    assert first.identity_hash != other.identity_hash
