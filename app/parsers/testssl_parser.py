import json
from urllib.parse import urlparse

PROTOCOL_IDS = {
    "SSLv2": "SSLv2",
    "SSLv3": "SSLv3",
    "TLS1": "TLS 1.0",
    "TLS1_0": "TLS 1.0",
    "TLS1_1": "TLS 1.1",
    "TLS1_2": "TLS 1.2",
    "TLS1_3": "TLS 1.3",
    "TLS 1": "TLS 1.0",
    "TLS 1.0": "TLS 1.0",
    "TLS 1.1": "TLS 1.1",
    "TLS 1.2": "TLS 1.2",
    "TLS 1.3": "TLS 1.3",
}
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLS1", "TLS1_0", "TLS1_1", "TLS 1", "TLS 1.0", "TLS 1.1"}
CERT_ID_MAP = {
    "cert_commonName": "common_name",
    "cert_commonname": "common_name",
    "cert_cn": "common_name",
    "cert_subject": "subject",
    "cert_subjectAltName": "subject_alt_names",
    "cert_subjectaltname": "subject_alt_names",
    "cert_SAN": "subject_alt_names",
    "cert_san": "subject_alt_names",
    "cert_issuer": "issuer",
    "cert_notBefore": "not_before",
    "cert_notbefore": "not_before",
    "cert_notBefore_local": "not_before",
    "cert_notAfter": "not_after",
    "cert_notafter": "not_after",
    "cert_notAfter_local": "not_after",
    "cert_expirationStatus": "expiration_status",
    "cert_expiration_status": "expiration_status",
    "cert_serialNumber": "serial_number",
    "cert_serialnumber": "serial_number",
    "cert_fingerprintSHA256": "fingerprint_sha256",
    "cert_fingerprint_sha256": "fingerprint_sha256",
}
VULNERABILITY_PREFIXES = (
    "heartbleed",
    "ccs",
    "ticketbleed",
    "robot",
    "secure_renego",
    "secure_client_renego",
    "crime",
    "breach",
    "poodle",
    "fallback_scsv",
    "sweet32",
    "freak",
    "drown",
    "logjam",
    "beast",
    "lucky13",
    "rc4",
)
HEADER_IDS = {"HSTS", "HPKP", "header_HSTS", "header_server", "security_headers"}


class TestsslParserError(ValueError):
    pass


def normalize_testssl_output(output: str | list | dict, target: str | None = None) -> dict:
    records = _decode_records(output)
    target_info = _target_info(target, records)
    evidence = {
        **target_info,
        "scan_status": "completed",
        "protocols": [],
        "certificate": {},
        "expiry": {},
        "cipher_findings": [],
        "weak_protocols": [],
        "vulnerabilities": [],
        "security_headers": [],
        "notable_findings": [],
        "raw_json": records,
        "limitations": [
            "testssl.sh evidence reflects TLS configuration only.",
            "Findings are not proof of overall site security.",
        ],
    }

    for record in records:
        if not isinstance(record, dict):
            continue
        item_id = str(record.get("id") or record.get("idName") or record.get("id_name") or record.get("name") or "").strip()
        finding = _finding_text(record)
        severity = str(record.get("severity") or record.get("severityLevel") or "").strip().upper()
        normalized_protocol_id = _normalize_protocol_id(item_id)
        if normalized_protocol_id in PROTOCOL_IDS:
            protocol = {"id": item_id, "name": PROTOCOL_IDS[normalized_protocol_id], "finding": finding, "severity": severity}
            evidence["protocols"].append(protocol)
            if normalized_protocol_id in WEAK_PROTOCOLS and _looks_supported(finding, severity):
                evidence["weak_protocols"].append(f"{PROTOCOL_IDS[normalized_protocol_id]}: {finding or 'reported supported'}")
            continue
        cert_key = CERT_ID_MAP.get(item_id) or CERT_ID_MAP.get(item_id.lower())
        if cert_key:
            evidence["certificate"][cert_key] = finding
            if cert_key in {"not_after", "expiration_status"}:
                evidence["expiry"][cert_key] = finding
            continue
        lowered_id = item_id.lower()
        if "cipher" in lowered_id or "fs_" in lowered_id or lowered_id.startswith("grade"):
            evidence["cipher_findings"].append(_finding_record(item_id, finding, severity))
            continue
        if item_id in HEADER_IDS or "hsts" in lowered_id or "header" in lowered_id:
            evidence["security_headers"].append(_finding_record(item_id, finding, severity))
            continue
        if any(lowered_id.startswith(prefix) or prefix in lowered_id for prefix in VULNERABILITY_PREFIXES):
            evidence["vulnerabilities"].append(_finding_record(item_id, finding, severity))
            continue
        if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "WARN", "WARNING"}:
            evidence["notable_findings"].append(_finding_record(item_id, finding, severity))

    evidence["protocols"] = _dedupe_records(evidence["protocols"], key="id")
    for key in ("cipher_findings", "vulnerabilities", "security_headers", "notable_findings"):
        evidence[key] = _dedupe_records(evidence[key], key="id")
    evidence["weak_protocols"] = _unique(evidence["weak_protocols"])
    return evidence


def summarize_testssl_evidence(evidence: dict) -> dict:
    protocols = evidence.get("protocols") or []
    supported = [item.get("name") for item in protocols if _looks_supported(item.get("finding"), item.get("severity"))]
    cert = evidence.get("certificate") or {}
    notable = [item for item in (evidence.get("vulnerabilities") or []) + (evidence.get("notable_findings") or []) + (evidence.get("cipher_findings") or []) if _is_notable_finding(item)]
    return {
        "protocol_count": len(protocols),
        "supported_protocols": _unique([str(value) for value in supported if value]),
        "certificate_summary": _certificate_summary(cert),
        "notable_count": len(notable),
        "weak_protocol_count": len(evidence.get("weak_protocols") or []),
    }


def _decode_records(output: str | list | dict) -> list[dict]:
    if isinstance(output, list):
        return _flatten_records(output)
    if isinstance(output, dict):
        return _flatten_records([output])
    text = str(output or "").strip()
    if not text:
        return []
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError as exc:
        raise TestsslParserError("Unable to parse testssl.sh JSON output.") from exc
    return _decode_records(decoded)


def _flatten_records(values: list[object]) -> list[dict]:
    records: list[dict] = []
    for value in values:
        if isinstance(value, list):
            records.extend(_flatten_records(value))
            continue
        if not isinstance(value, dict):
            continue
        if _is_testssl_finding_record(value):
            records.append(value)
        for key in ("scanResult", "serverDefaults", "protocols", "vulnerabilities", "cipherTests", "ciphers", "headers", "records", "results"):
            child = value.get(key)
            if isinstance(child, list):
                records.extend(_flatten_records(child))
            elif isinstance(child, dict):
                records.extend(_flatten_records([child]))
    return records


def _is_testssl_finding_record(value: dict) -> bool:
    return any(key in value for key in ("id", "idName", "id_name")) and any(
        key in value for key in ("finding", "findingDetails", "value", "message", "severity", "severityLevel")
    )


def _target_info(target: str | None, records: list[dict]) -> dict:
    value = str(target or "").strip()
    if not value and records:
        value = str(records[0].get("scanHost") or records[0].get("host") or records[0].get("ip") or "").strip()
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname or value.split(":")[0] if value else ""
    port = parsed.port or (443 if value else None)
    return {"target": value, "host": host, "port": port}


def _finding_text(record: dict) -> str:
    for key in ("finding", "findingDetails", "value", "message"):
        value = record.get(key)
        if value is not None:
            if isinstance(value, list):
                return ", ".join(str(item).strip() for item in value if str(item).strip())
            if isinstance(value, dict):
                return ", ".join(f"{key}={item}" for key, item in value.items() if item is not None)
            return str(value).strip()
    return ""


def _normalize_protocol_id(item_id: str) -> str:
    normalized = item_id.strip()
    lowered = normalized.lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "ssl_2": "SSLv2",
        "sslv2": "SSLv2",
        "ssl_3": "SSLv3",
        "sslv3": "SSLv3",
        "tls_1": "TLS1",
        "tls_1_0": "TLS1_0",
        "tls1": "TLS1",
        "tls1_0": "TLS1_0",
        "tls_1_1": "TLS1_1",
        "tls1_1": "TLS1_1",
        "tls_1_2": "TLS1_2",
        "tls1_2": "TLS1_2",
        "tls_1_3": "TLS1_3",
        "tls1_3": "TLS1_3",
    }
    return aliases.get(lowered, normalized)


def _finding_record(item_id: str, finding: str, severity: str) -> dict:
    return {"id": item_id, "finding": finding, "severity": severity or "INFO"}


def _looks_supported(finding: object, severity: object = None) -> bool:
    text = str(finding or "").lower()
    sev = str(severity or "").upper()
    if sev in {"OK", "INFO"} and any(term in text for term in ("not offered", "not supported", "no ")):
        return False
    return any(term in text for term in ("offered", "supported", "yes", "enabled", "available"))


def _is_notable_finding(item: dict) -> bool:
    severity = str(item.get("severity") or "").upper()
    finding = str(item.get("finding") or "").lower()
    if severity in {"HIGH", "CRITICAL", "MEDIUM", "LOW", "WARN", "WARNING"}:
        return True
    return not any(term in finding for term in ("not vulnerable", "not offered", "not supported", "no vulnerability"))


def _certificate_summary(cert: dict) -> str:
    parts = []
    if cert.get("common_name"):
        parts.append(f"CN={cert['common_name']}")
    if cert.get("issuer"):
        parts.append(f"Issuer={cert['issuer']}")
    if cert.get("not_after"):
        parts.append(f"Expires={cert['not_after']}")
    return "; ".join(parts) if parts else "No certificate metadata extracted."


def _dedupe_records(records: list[dict], key: str) -> list[dict]:
    seen = set()
    results = []
    for record in records:
        marker = str(record.get(key) or record).lower()
        if marker in seen:
            continue
        seen.add(marker)
        results.append(record)
    return results


def _unique(values: list[str]) -> list[str]:
    seen = set()
    results = []
    for value in values:
        cleaned = str(value or "").strip()
        key = cleaned.lower()
        if cleaned and key not in seen:
            seen.add(key)
            results.append(cleaned)
    return results
