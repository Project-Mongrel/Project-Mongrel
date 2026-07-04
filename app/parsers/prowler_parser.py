import json


class ProwlerParserError(ValueError):
    pass


def normalize_prowler_output(output: str | list | dict, provider: str | None = None) -> dict:
    records = _decode_records(output)
    findings = [_normalize_record(record, provider=provider) for record in records]
    return {
        "provider": str(provider or _first_non_empty(finding.get("provider") for finding in findings) or ""),
        "finding_count": len(findings),
        "status_summary": _count_values(finding.get("status") for finding in findings),
        "severity_summary": _count_values(finding.get("severity") for finding in findings),
        "service_summary": _count_values(finding.get("service") for finding in findings),
        "findings": findings,
        "source_confidence": "scanner_reported",
        "limitations": [
            "Prowler findings are scanner-reported cloud posture evidence.",
            "PASS results are preserved as PASS and are not vulnerabilities.",
            "FAIL results are failed checks, not confirmed exploitability or compromise.",
        ],
    }


def _decode_records(output: str | list | dict) -> list[dict]:
    if isinstance(output, list):
        if not all(isinstance(item, dict) for item in output):
            raise ProwlerParserError("Malformed Prowler JSON: expected objects.")
        return output
    if isinstance(output, dict):
        for key in ("findings", "Findings", "results", "Results", "events", "Events"):
            if isinstance(output.get(key), list):
                return _decode_records(output[key])
        return [output]
    text = str(output or "").strip()
    if not text:
        return []
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProwlerParserError("Unable to parse Prowler JSON output.") from exc
    return _decode_records(decoded)


def _normalize_record(record: dict, provider: str | None = None) -> dict:
    cloud = _as_dict(record.get("cloud"))
    finding_info = _as_dict(record.get("finding_info"))
    metadata = _as_dict(record.get("metadata"))
    product = _as_dict(metadata.get("product"))
    feature = _as_dict(product.get("feature"))
    resources = record.get("resources") if isinstance(record.get("resources"), list) else []
    resource = _as_dict(resources[0]) if resources else {}
    resource_group = _as_dict(resource.get("group"))
    remediation = _as_dict(record.get("remediation"))

    status = _safe_text(_first(record, "status_code", "status", "status_detail"))
    normalized = {
        "provider": _safe_text(provider or cloud.get("provider") or _first(record, "provider")),
        "check_id": _safe_text(metadata.get("event_code") or finding_info.get("uid") or _first(record, "check_id", "checkId")),
        "check_title": _safe_text(finding_info.get("title") or _first(record, "check_title", "checkTitle", "title")),
        "status": status,
        "status_interpretation": _status_interpretation(status),
        "severity": _safe_text(_first(record, "severity", "severity_id")),
        "service": _safe_text(_first(record, "service") or resource_group.get("name") or feature.get("name") or _first(record, "class_name")),
        "region": _safe_text(resource.get("region") or cloud.get("region") or _first(record, "region")),
        "resource_identifier": _safe_text(resource.get("uid") or resource.get("id") or _first(record, "resource_identifier", "resource_id")),
        "resource_name": _safe_text(resource.get("name") or _first(record, "resource_name")),
        "finding_identifier": _safe_text(finding_info.get("uid") or _first(record, "finding_identifier", "finding_id")),
        "description": _safe_text(finding_info.get("desc") or _first(record, "description", "message")),
        "risk": _safe_text(_first(record, "risk_details", "risk")),
        "remediation": {
            "description": _safe_text(remediation.get("desc") or remediation.get("description")),
            "references": [_safe_text(reference) for reference in _as_list(remediation.get("references")) if _safe_text(reference)],
        },
        "source_confidence": "scanner_reported",
    }
    return normalized


def _status_interpretation(status: str) -> str:
    normalized = str(status or "").upper()
    if normalized == "PASS":
        return "scanner_reported_passed_check"
    if normalized == "FAIL":
        return "scanner_reported_failed_check"
    return "scanner_reported_status"


def _first(record: dict, *keys: str) -> object:
    for key in keys:
        if key in record and record[key] not in (None, ""):
            return record[key]
    return None


def _first_non_empty(values: object) -> object:
    for value in values:
        if value not in (None, ""):
            return value
    return None


def _as_dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _as_list(value: object) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _safe_text(value: object) -> str:
    return str(value or "").replace("\n", " ").strip()[:1000]


def _count_values(values: object) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        cleaned = str(value or "unknown").strip() or "unknown"
        counts[cleaned] = counts.get(cleaned, 0) + 1
    return counts
