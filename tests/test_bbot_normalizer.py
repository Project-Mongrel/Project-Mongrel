from app.parsers.bbot_normalizer import normalize_bbot_output, summarize_observations


def _types_and_values(observations: list[dict]) -> set[tuple[str, str]]:
    return {(observation["observation_type"], observation["value"]) for observation in observations}


def test_extracts_subdomains_from_text() -> None:
    observations = normalize_bbot_output("Found app.example.com and api.example.com", "example.com", 1001)

    assert ("subdomain", "app.example.com") in _types_and_values(observations)
    assert ("subdomain", "api.example.com") in _types_and_values(observations)


def test_extracts_urls_from_text() -> None:
    observations = normalize_bbot_output("Visit https://app.example.com/login", "example.com", 1001)

    assert ("url", "https://app.example.com/login") in _types_and_values(observations)


def test_extracts_ip_addresses_from_text() -> None:
    observations = normalize_bbot_output("Resolved to 192.0.2.10", "example.com", 1001)

    assert ("ip_address", "192.0.2.10") in _types_and_values(observations)


def test_extracts_emails_from_text() -> None:
    observations = normalize_bbot_output("Contact security@example.com", "example.com", 1001)

    assert ("email", "security@example.com") in _types_and_values(observations)


def test_extracts_observations_from_json_lines() -> None:
    raw_output = (
        '{"type":"DNS_NAME","data":"app.example.com"}\n'
        '{"type":"URL","data":"https://app.example.com"}\n'
        '{"technology":"nginx"}\n'
    )

    observations = normalize_bbot_output(raw_output, "example.com", 1001, investigation_id="inv-1")
    values = _types_and_values(observations)

    assert ("subdomain", "app.example.com") in values
    assert ("url", "https://app.example.com") in values
    assert ("technology", "nginx") in values
    assert all(observation["investigation_id"] == "inv-1" for observation in observations)


def test_deduplicates_repeated_observations() -> None:
    observations = normalize_bbot_output("app.example.com\napp.example.com", "example.com", 1001)

    assert [observation for observation in observations if observation["value"] == "app.example.com"] == [observations[0]]


def test_tolerates_malformed_lines() -> None:
    observations = normalize_bbot_output('{"type":"DNS_NAME","data":"app.example.com"}\n{bad json', "example.com", 1001)

    assert ("subdomain", "app.example.com") in _types_and_values(observations)


def test_returns_raw_event_for_unknown_structured_event() -> None:
    observations = normalize_bbot_output({"type": "UNKNOWN_EVENT", "data": "opaque value"}, "example.com", 1001)

    assert ("raw_event", "opaque value") in _types_and_values(observations)


def test_summarizes_observation_counts() -> None:
    observations = normalize_bbot_output(
        "app.example.com\nhttps://app.example.com\nsecurity@example.com\n192.0.2.10",
        "example.com",
        1001,
    )

    summary = summarize_observations(observations)

    assert summary["subdomain"] >= 1
    assert summary["url"] == 1
    assert summary["email"] == 1
    assert summary["ip_address"] == 1
