import pytest

from app.parsers.nuclei_parser import (
    NucleiParserError,
    parse_nuclei_json,
    parse_nuclei_jsonl,
    parse_nuclei_results,
)


def test_parse_nuclei_jsonl_with_multiple_findings() -> None:
    results = parse_nuclei_jsonl(
        "\n".join(
            [
                '{"template-id":"http-missing-security-headers","info":{"name":"Missing Security Headers","severity":"low","tags":["http","headers"],"reference":["https://example.com/ref"],"description":"Missing headers.","remediation":"Add headers."},"host":"https://example.com","matched-at":"https://example.com/login"}',
                '{"templateID":"ssh-detect","info":{"name":"SSH Detect","severity":"medium"},"host":"example.com","matched":"example.com:22"}',
            ]
        )
    )

    assert results == [
        {
            "template_id": "http-missing-security-headers",
            "severity": "low",
            "name": "Missing Security Headers",
            "host": "https://example.com",
            "matched_at": "https://example.com/login",
            "tags": ["http", "headers"],
            "references": ["https://example.com/ref"],
            "description": "Missing headers.",
            "remediation": "Add headers.",
        },
        {
            "template_id": "ssh-detect",
            "severity": "medium",
            "name": "SSH Detect",
            "host": "example.com",
            "matched_at": "example.com:22",
            "tags": [],
            "references": [],
            "description": None,
            "remediation": None,
        },
    ]


def test_parse_nuclei_results_auto_detects_jsonl_object_lines() -> None:
    results = parse_nuclei_results(
        '{"template-id":"one","info":{"severity":"low"},"host":"https://one.example"}\n'
        '{"template-id":"two","info":{"severity":"high"},"host":"https://two.example"}'
    )

    assert [result["template_id"] for result in results] == ["one", "two"]


def test_parse_nuclei_json_array() -> None:
    results = parse_nuclei_results(
        '[{"template-id":"one","info":{"name":"One","severity":"high"},"host":"https://one.example"},'
        '{"template-id":"two","info":{"name":"Two","severity":"critical"},"host":"https://two.example"}]'
    )

    assert [result["template_id"] for result in results] == ["one", "two"]
    assert [result["severity"] for result in results] == ["high", "critical"]


def test_parse_single_nuclei_json_object() -> None:
    results = parse_nuclei_results(
        '{"templateID":"single-template","info":{"name":"Single Finding","severity":"LOW"},"url":"https://example.com"}'
    )

    assert results == [
        {
            "template_id": "single-template",
            "severity": "low",
            "name": "Single Finding",
            "host": "https://example.com",
            "matched_at": "https://example.com",
            "tags": [],
            "references": [],
            "description": None,
            "remediation": None,
        }
    ]


def test_unknown_severity_normalizes_to_info() -> None:
    results = parse_nuclei_json('{"template-id":"unknown-severity","info":{"severity":"weird"},"host":"example.com"}')

    assert results[0]["severity"] == "info"


def test_missing_optional_fields_do_not_crash_parser() -> None:
    results = parse_nuclei_json('{"template-id":"minimal"}')

    assert results == [
        {
            "template_id": "minimal",
            "severity": "info",
            "name": None,
            "host": None,
            "matched_at": None,
            "tags": [],
            "references": [],
            "description": None,
            "remediation": None,
        }
    ]


def test_malformed_json_raises_clear_parser_error() -> None:
    with pytest.raises(NucleiParserError, match="Unable to parse Nuclei JSON"):
        parse_nuclei_results("{not-json")


def test_empty_file_raises_clear_parser_error() -> None:
    with pytest.raises(NucleiParserError, match="Nuclei results file is empty"):
        parse_nuclei_results("  \n  ")


def test_tags_as_string_and_list() -> None:
    from_string = parse_nuclei_json('{"info":{"tags":"http,headers"}}')
    from_list = parse_nuclei_json('{"info":{"tags":["http","headers"]}}')

    assert from_string[0]["tags"] == ["http", "headers"]
    assert from_list[0]["tags"] == ["http", "headers"]


def test_references_as_string_and_list() -> None:
    from_string = parse_nuclei_json('{"info":{"reference":"https://example.com/ref"}}')
    from_list = parse_nuclei_json('{"info":{"reference":["https://example.com/ref1","https://example.com/ref2"]}}')

    assert from_string[0]["references"] == ["https://example.com/ref"]
    assert from_list[0]["references"] == ["https://example.com/ref1", "https://example.com/ref2"]


def test_matched_at_fallback_behavior() -> None:
    matched = parse_nuclei_json('{"matched":"https://example.com/matched","host":"https://example.com"}')
    url = parse_nuclei_json('{"url":"https://example.com/url","host":"https://example.com"}')
    host = parse_nuclei_json('{"host":"https://example.com"}')

    assert matched[0]["matched_at"] == "https://example.com/matched"
    assert url[0]["matched_at"] == "https://example.com/url"
    assert host[0]["matched_at"] == "https://example.com"
