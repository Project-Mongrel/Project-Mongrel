import json
from typing import Any


ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class NucleiParserError(ValueError):
    pass


def parse_nuclei_results(text: str) -> list[dict]:
    content = _validate_content(text)
    non_empty_lines = [line for line in content.splitlines() if line.strip()]
    if content.startswith("{") and len(non_empty_lines) > 1:
        return parse_nuclei_jsonl(content)

    if content.startswith("[") or content.startswith("{"):
        return parse_nuclei_json(content)

    return parse_nuclei_jsonl(content)


def parse_nuclei_json(text: str) -> list[dict]:
    content = _validate_content(text)
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise NucleiParserError("Unable to parse Nuclei JSON.") from exc

    if isinstance(payload, list):
        return [_normalize_finding(item) for item in payload if isinstance(item, dict)]

    if isinstance(payload, dict):
        return [_normalize_finding(payload)]

    raise NucleiParserError("Nuclei JSON must be an object or array.")


def parse_nuclei_jsonl(text: str) -> list[dict]:
    content = _validate_content(text)
    findings = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped_line = line.strip()
        if not stripped_line:
            continue

        try:
            payload = json.loads(stripped_line)
        except json.JSONDecodeError as exc:
            raise NucleiParserError(f"Unable to parse Nuclei JSONL on line {line_number}.") from exc

        if not isinstance(payload, dict):
            raise NucleiParserError(f"Nuclei JSONL line {line_number} must be an object.")

        findings.append(_normalize_finding(payload))

    if not findings:
        raise NucleiParserError("Nuclei results file is empty.")

    return findings


def _validate_content(text: str) -> str:
    content = text.strip()
    if not content:
        raise NucleiParserError("Nuclei results file is empty.")

    return content


def _normalize_finding(raw_finding: dict[str, Any]) -> dict:
    info = raw_finding.get("info")
    if not isinstance(info, dict):
        info = {}

    return {
        "template_id": _first_string(raw_finding.get("template-id"), raw_finding.get("templateID")),
        "severity": _normalize_severity(_first_string(info.get("severity"), raw_finding.get("severity"))),
        "name": _first_string(info.get("name"), raw_finding.get("name")),
        "host": _first_string(raw_finding.get("host"), raw_finding.get("url")),
        "matched_at": _first_string(raw_finding.get("matched-at"), raw_finding.get("matched"), raw_finding.get("url"), raw_finding.get("host")),
        "tags": _normalize_list(info.get("tags")),
        "references": _normalize_list(info.get("reference")),
        "description": _first_string(info.get("description"), raw_finding.get("description")),
        "remediation": _first_string(info.get("remediation"), raw_finding.get("remediation")),
    }


def _normalize_severity(severity: str | None) -> str:
    normalized = str(severity or "").strip().lower()
    if normalized in ALLOWED_SEVERITIES:
        return normalized

    return "info"


def _normalize_list(value: Any) -> list[str]:
    if value is None:
        return []

    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]

    if isinstance(value, str):
        if "," in value:
            return [item.strip() for item in value.split(",") if item.strip()]

        stripped_value = value.strip()
        return [stripped_value] if stripped_value else []

    return [str(value).strip()] if str(value).strip() else []


def _first_string(*values: Any) -> str | None:
    for value in values:
        if value is None:
            continue

        text = str(value).strip()
        if text:
            return text

    return None
