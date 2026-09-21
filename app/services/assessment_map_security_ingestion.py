"""Nuclei finding and testssl.sh TLS evidence mapping rules."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Protocol
from urllib.parse import urlparse

from app.services.assessment_map_identity import (
    CanonicalIdentity,
    canonical_endpoint,
    canonical_finding,
    canonical_hostname,
    canonical_ip,
    canonical_service,
)

STRUCTURED_ARTIFACT_TYPES = {"nuclei": frozenset(), "testssl": frozenset()}
_EXPLICIT_NUCLEI_MATCH_SOURCES = frozenset({"matched-at", "matched"})
_NUCLEI_SERVICE_TRANSPORTS = frozenset({"tcp", "udp"})
_NON_ISSUE_RESULT_TERMS = frozenset({
    "false", "no", "off", "disabled", "passed", "ok", "not vulnerable", "not offered",
    "not supported", "not affected", "no vulnerability", "not present", "not detected",
})
_ISSUE_RESULT_TERMS = frozenset({
    "true", "yes", "on", "enabled", "offered", "supported", "vulnerable",
    "potentially vulnerable", "not ok", "failed",
})
_ISSUE_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL", "WARN", "WARNING"})
_TESTSSL_ISSUE_PREFIXES = frozenset({
    "heartbleed", "ccs", "ticketbleed", "robot", "secure_renego", "secure_client_renego",
    "crime", "breach", "poodle", "fallback_scsv", "sweet32", "freak", "drown", "logjam",
    "beast", "lucky13", "rc4",
})
_TESTSSL_OBSERVATION_ONLY_PREFIXES = frozenset({"tls", "ssl", "cert", "header", "hsts", "hpkp", "grade"})
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_CWE_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)
_GHSA_RE = re.compile(r"^GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}$", re.IGNORECASE)
_SAFE_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$")
_SECRET_TAG_TERMS = (
    "token", "secret", "password", "passwd", "api_key", "api-key", "apikey",
    "access_key", "access-key", "private_key", "private-key", "credential",
    "session", "auth", "bearer",
)
_AMBIGUOUS_RESULT = "ambiguous"


class MappingWriter(Protocol):
    root_path: str
    def entity(self, identity: CanonicalIdentity, evidence_kind: str, path: str) -> Any: ...
    def assertion(self, subject: Any, predicate: str, *, evidence_kind: str, path: str,
                  object_entity: Any | None = None, value: Any = ...) -> Any: ...
    def skipped_optional(self, reason: str) -> None: ...


def project_security_source(tool: str, data: dict[str, Any]) -> dict[str, Any]:
    if tool == "nuclei":
        records = data.get("nuclei_findings")
        return {"source": data.get("source"), "nuclei_findings": _project_nuclei(records)}
    if tool == "testssl":
        evidence = data.get("testssl_evidence")
        return {"source": data.get("source"), "testssl_evidence": _project_testssl(evidence)}
    raise ValueError("Unsupported security evidence tool.")


def security_coverage_metadata(tool: str, data: dict[str, Any]) -> dict[str, Any]:
    if tool == "nuclei":
        records = data.get("nuclei_findings")
        return {"match_count": len(records)} if isinstance(records, list) else {}
    evidence = data.get("testssl_evidence")
    if not isinstance(evidence, dict):
        return {}
    return {
        "protocol_count": len(evidence.get("protocols") or []) if isinstance(evidence.get("protocols") or [], list) else 0,
        "cipher_record_count": len(evidence.get("cipher_findings") or []) if isinstance(evidence.get("cipher_findings") or [], list) else 0,
        "header_record_count": len(evidence.get("security_headers") or []) if isinstance(evidence.get("security_headers") or [], list) else 0,
        "vulnerability_record_count": len(evidence.get("vulnerabilities") or []) if isinstance(evidence.get("vulnerabilities") or [], list) else 0,
        "notable_record_count": len(evidence.get("notable_findings") or []) if isinstance(evidence.get("notable_findings") or [], list) else 0,
        "certificate_observation_count": len(evidence.get("certificate") or {}) if isinstance(evidence.get("certificate") or {}, dict) else 0,
    }


def map_security_source(tool: str, data: dict[str, Any], writer: MappingWriter) -> None:
    source_tool = str(data.get("source") or "").strip().lower().removesuffix(".sh")
    if source_tool and source_tool != tool:
        raise ValueError("Linked structured evidence does not match the scan tool.")
    if tool == "nuclei":
        _map_nuclei(data, writer)
    elif tool == "testssl":
        _map_testssl(data, writer)
    else:
        raise ValueError("Unsupported security evidence tool.")


def _map_nuclei(data: dict[str, Any], writer: MappingWriter) -> None:
    records = data.get("nuclei_findings")
    if not isinstance(records, list):
        raise ValueError("Missing normalized Nuclei findings.")
    mapped = 0
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            writer.skipped_optional("malformed_nuclei_record")
            continue
        base = f"{writer.root_path}.nuclei_findings[{index}]"
        template_id = _safe_identifier(record.get("template_id"))
        surface = _nuclei_surface(record)
        surface_identity = surface.identity if surface is not None else None
        if template_id is None or surface_identity is None:
            writer.skipped_optional("unsupported_nuclei_match")
            continue
        surface_row = writer.entity(surface_identity, "nuclei_matched_surface", f"{base}.matched_at")
        if surface.port is not None and surface.transport is None:
            writer.assertion(surface_row, "has_observed_port", value=surface.port,
                             evidence_kind="nuclei_matched_port", path=f"{base}.matched_at")
        matcher = _safe_label(record.get("matcher_name"))
        finding_identity = canonical_finding("nuclei", template_id, surface_identity, matcher=matcher)
        finding = writer.entity(finding_identity, "nuclei_template_match", f"{base}.template_id")
        writer.assertion(finding, "finding_affects", object_entity=surface_row,
                         evidence_kind="nuclei_template_match", path=f"{base}.matched_at")
        for predicate, field in (
            ("has_template_id", "template_id"), ("has_matcher", "matcher_name"),
            ("has_scanner_severity", "severity"), ("has_finding_name", "name"),
            ("has_template_type", "template_type"),
        ):
            value = record.get(field)
            if value not in (None, ""):
                writer.assertion(finding, predicate, value=str(value), evidence_kind=predicate,
                                 path=f"{base}.{field}")
        for field, predicate in (("tags", "has_tag"), ("references", "has_reference")):
            values = record.get(field) or []
            if not isinstance(values, list):
                writer.skipped_optional(f"malformed_nuclei_{field}")
                continue
            for value_index, value in enumerate(values):
                sanitized = _safe_reference(value) if field == "references" else _safe_tag(value)
                if sanitized is not None:
                    writer.assertion(finding, predicate, value=sanitized, evidence_kind=predicate,
                                     path=f"{base}.{field}[{value_index}]")
                else:
                    writer.skipped_optional(f"unsupported_nuclei_{field[:-1]}")
        mapped += 1
    if not mapped:
        raise ValueError("No supported matched Nuclei evidence.")


def _map_testssl(data: dict[str, Any], writer: MappingWriter) -> None:
    evidence = data.get("testssl_evidence")
    if not isinstance(evidence, dict):
        raise ValueError("Missing normalized testssl.sh evidence.")
    host_identity = _network_identity(evidence.get("host"))
    port = _port(evidence.get("port"))
    if host_identity is None or port is None:
        raise ValueError("testssl.sh evidence has no explicit TLS service target.")
    host = writer.entity(host_identity, "testssl_target", f"{writer.root_path}.testssl_evidence.host")
    service_identity = canonical_service(_network_value(host_identity), "tcp", port)
    service = writer.entity(service_identity, "testssl_tls_service", f"{writer.root_path}.testssl_evidence")
    writer.assertion(host, "exposes_service", object_entity=service, evidence_kind="testssl_tls_service",
                     path=f"{writer.root_path}.testssl_evidence.port")
    writer.assertion(service, "has_transport", value="tcp", evidence_kind="testssl_transport",
                     path=f"{writer.root_path}.testssl_evidence")
    writer.assertion(service, "has_port", value=port, evidence_kind="testssl_port",
                     path=f"{writer.root_path}.testssl_evidence.port")
    mapped = 0
    protocols = evidence.get("protocols") or []
    if not isinstance(protocols, list):
        writer.skipped_optional("malformed_testssl_protocols")
        protocols = []
    for index, record in enumerate(protocols):
        if _map_tls_record(writer, service, service_identity, record, "protocol", index,
                           f"{writer.root_path}.testssl_evidence.protocols"):
            mapped += 1
    for category, key, predicate in (
        ("cipher", "cipher_findings", "has_cipher_observation"),
        ("header", "security_headers", "has_header_observation"),
        ("vulnerability", "vulnerabilities", "has_scanner_result"),
        ("notable", "notable_findings", "has_scanner_result"),
    ):
        records = evidence.get(key) or []
        if not isinstance(records, list):
            writer.skipped_optional(f"malformed_testssl_{key}")
            continue
        for index, record in enumerate(records):
            if _map_tls_record(writer, service, service_identity, record, category, index,
                               f"{writer.root_path}.testssl_evidence.{key}", predicate=predicate):
                mapped += 1
    certificate = evidence.get("certificate") or {}
    if not isinstance(certificate, dict):
        writer.skipped_optional("malformed_testssl_certificate")
        certificate = {}
    certificate_fields = {
        "common_name": "has_certificate_common_name", "subject": "has_certificate_subject",
        "subject_alt_names": "has_certificate_san", "issuer": "has_certificate_issuer",
        "not_before": "has_certificate_not_before", "not_after": "has_certificate_not_after",
        "expiration_status": "has_certificate_expiration_status",
        "serial_number": "has_certificate_serial", "fingerprint_sha256": "has_certificate_sha256",
    }
    for field, predicate in certificate_fields.items():
        value = _safe_certificate_value(field, certificate.get(field))
        if value is None:
            continue
        writer.assertion(service, predicate, value=value, evidence_kind=predicate,
                         path=f"{writer.root_path}.testssl_evidence.certificate.{field}")
        mapped += 1
    if not mapped:
        raise ValueError("No supported structured testssl.sh observations.")


def _map_tls_record(writer: MappingWriter, service: Any, service_identity: CanonicalIdentity,
                    record: object, category: str, index: int, root: str,
                    predicate: str = "has_protocol_observation") -> bool:
    if not isinstance(record, dict):
        writer.skipped_optional(f"malformed_testssl_{category}_record")
        return False
    record_id = _safe_identifier(record.get("id"))
    finding_text = _safe_finding_text(record.get("finding"))
    severity = _safe_label(record.get("severity"))
    if record_id is None or finding_text is None:
        writer.skipped_optional(f"malformed_testssl_{category}_record")
        return False
    base = f"{root}[{index}]"
    observation = {"id": record_id, "finding": finding_text, "severity": severity or ""}
    writer.assertion(service, predicate, value=observation, evidence_kind=f"testssl_{category}", path=f"{base}.id")
    writer.assertion(service, f"{predicate}_finding", value=finding_text,
                     evidence_kind=f"testssl_{category}_finding", path=f"{base}.finding")
    if severity:
        writer.assertion(service, f"{predicate}_severity", value=severity,
                         evidence_kind=f"testssl_{category}_severity", path=f"{base}.severity")
    if _is_issue_record(category, record_id, severity, finding_text):
        identity = canonical_finding("testssl", record_id, service_identity, matcher=category)
        finding = writer.entity(identity, "testssl_issue", f"{base}.id")
        writer.assertion(finding, "finding_affects", object_entity=service,
                         evidence_kind="testssl_issue", path=f"{base}.id")
        writer.assertion(finding, "has_scanner_severity", value=severity,
                         evidence_kind="has_scanner_severity", path=f"{base}.severity")
        writer.assertion(finding, "has_scanner_result", value=finding_text,
                         evidence_kind="has_scanner_result", path=f"{base}.finding")
    return True


class _NucleiSurface:
    def __init__(self, identity: CanonicalIdentity, *, port: int | None = None, transport: str | None = None):
        self.identity = identity
        self.port = port
        self.transport = transport


def _nuclei_surface(record: dict[str, Any]) -> _NucleiSurface | None:
    source = record.get("matched_surface_source")
    if source not in _EXPLICIT_NUCLEI_MATCH_SOURCES:
        return None
    matched = record.get("matched_at")
    if not isinstance(matched, str) or not matched.strip():
        return None
    transport = _nuclei_transport(record)
    try:
        return _NucleiSurface(canonical_endpoint(matched))
    except ValueError:
        pass
    host, port = _split_host_port(matched)
    if host is not None and port is not None:
        if transport is not None:
            try:
                return _NucleiSurface(canonical_service(host, transport, port), port=port, transport=transport)
            except ValueError:
                return None
        host_identity = _network_identity(host)
        return _NucleiSurface(host_identity, port=port) if host_identity is not None else None
    host_identity = _network_identity(_strip_ipv6_brackets(matched))
    return _NucleiSurface(host_identity) if host_identity is not None else None


def _project_nuclei(value: object) -> object:
    if not isinstance(value, list):
        return {"malformed_type": type(value).__name__}
    projected = []
    for record in value:
        if not isinstance(record, dict):
            projected.append({"malformed": True})
            continue
        surface = _nuclei_surface(record)
        projected.append({
            "template_id": _safe_identifier(record.get("template_id")),
            "matcher_name": _safe_label(record.get("matcher_name")),
            "severity": _safe_label(record.get("severity")),
            "name": _safe_label(record.get("name")),
            "template_type": _safe_label(record.get("template_type")),
            "matched_surface_source": record.get("matched_surface_source"),
            "surface": surface.identity.canonical_key if surface is not None else "invalid",
            "surface_port": surface.port if surface is not None else None,
            "surface_transport": surface.transport if surface is not None else None,
            "tags": [_safe_tag(item) for item in record.get("tags") or []]
            if isinstance(record.get("tags") or [], list) else {"malformed": True},
            "references": [_safe_reference(item) for item in record.get("references") or []]
            if isinstance(record.get("references") or [], list) else {"malformed": True},
        })
    return projected


def _project_testssl(value: object) -> object:
    if not isinstance(value, dict):
        return {"malformed_type": type(value).__name__}
    host = _network_identity(value.get("host"))
    projected: dict[str, Any] = {
        "host": host.canonical_key if host is not None else "invalid",
        "port": _port(value.get("port")),
    }
    for key in ("protocols", "cipher_findings", "security_headers", "vulnerabilities", "notable_findings"):
        records = value.get(key) or []
        projected[key] = [
            {"id": _safe_identifier(item.get("id")), "finding": _safe_finding_text(item.get("finding")),
             "severity": _safe_label(item.get("severity"))}
            if isinstance(item, dict) else {"malformed": True}
            for item in records
        ] if isinstance(records, list) else {"malformed": True}
    certificate = value.get("certificate") or {}
    projected["certificate"] = {
        field: _safe_certificate_value(field, raw)
        for field, raw in certificate.items()
        if field in {"common_name", "subject", "subject_alt_names", "issuer", "not_before", "not_after",
                     "expiration_status", "serial_number", "fingerprint_sha256"}
    } if isinstance(certificate, dict) else {"malformed": True}
    return projected


def _is_issue_record(category: str, record_id: str, severity: str | None, finding: str) -> bool:
    result = _normalized_result(finding)
    lowered_id = record_id.casefold()
    if lowered_id.startswith("secure_renego") and _contains_result_term(finding, "not supported"):
        return True
    if result == _AMBIGUOUS_RESULT:
        return False
    if result in _NON_ISSUE_RESULT_TERMS:
        return False
    if category == "protocol":
        return _normalize_tls_protocol_id(record_id) in {"sslv2", "sslv3", "tls1", "tls1_0", "tls1_1"} and result in _ISSUE_RESULT_TERMS
    if category == "header":
        return False
    if category == "cipher":
        return str(severity or "").upper() in _ISSUE_SEVERITIES and result in _ISSUE_RESULT_TERMS
    if category in {"vulnerability", "notable"}:
        if any(lowered_id.startswith(prefix) or prefix in lowered_id for prefix in _TESTSSL_OBSERVATION_ONLY_PREFIXES):
            return False
        if any(lowered_id.startswith(prefix) or prefix in lowered_id for prefix in _TESTSSL_ISSUE_PREFIXES):
            return result in _ISSUE_RESULT_TERMS
        return False
    return False


def _network_identity(value: object) -> CanonicalIdentity | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        ipaddress.ip_address(text)
    except ValueError:
        try:
            return canonical_hostname(text)
        except ValueError:
            return None
    return canonical_ip(text)


def _network_value(identity: CanonicalIdentity) -> str:
    return str(identity.payload.get("address") or identity.payload.get("hostname") or "")


def _split_host_port(value: str) -> tuple[str | None, int | None]:
    text = value.strip()
    if text.startswith("[") and "]:" in text:
        host, raw_port = text[1:].split("]:", 1)
    else:
        if text.count(":") > 1:
            return None, None
        host, separator, raw_port = text.rpartition(":")
        if not separator:
            return None, None
    port = _port(raw_port)
    return (host or None, port)


def _strip_ipv6_brackets(value: str) -> str:
    text = value.strip()
    return text[1:-1] if text.startswith("[") and text.endswith("]") else text


def _nuclei_transport(record: dict[str, Any]) -> str | None:
    for field in ("transport", "protocol", "template_type"):
        value = str(record.get(field) or "").strip().lower()
        if value in _NUCLEI_SERVICE_TRANSPORTS:
            return value
    return None


def _port(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _safe_identifier(value: object) -> str | None:
    cleaned = str(value or "").strip()
    if not cleaned or len(cleaned) > 200 or re.fullmatch(r"[A-Za-z0-9_.:/-]+", cleaned) is None:
        return None
    return cleaned


def _safe_label(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = " ".join(str(value or "").split())
    if not cleaned or len(cleaned) > 500:
        return None
    return cleaned


def _safe_tag(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    lowered = cleaned.casefold()
    if (
        not cleaned
        or "?" in cleaned
        or "#" in cleaned
        or ":" in cleaned
        or "/" in cleaned
        or "=" in cleaned
        or "@" in cleaned
        or any(term in lowered for term in _SECRET_TAG_TERMS)
        or _SAFE_TAG_RE.fullmatch(cleaned) is None
    ):
        return None
    return cleaned


def _safe_reference(value: object) -> object | None:
    if not isinstance(value, str):
        return None
    text = str(value or "").strip()
    if not text:
        return None
    upper = text.upper()
    if _CVE_RE.fullmatch(upper) or _CWE_RE.fullmatch(upper) or _GHSA_RE.fullmatch(upper):
        return upper
    try:
        parsed = urlparse(text)
        if parsed.scheme.lower() not in {"http", "https"}:
            return None
        return canonical_endpoint(text).payload
    except ValueError:
        return None


def _safe_finding_text(value: object) -> str | None:
    text = " ".join(str(value or "").split())
    return text[:1000] if text else None


def _safe_certificate_value(field: str, value: object) -> str | None:
    text = " ".join(str(value or "").split())
    if not text:
        return None
    if field == "fingerprint_sha256":
        compact = re.sub(r"[\s:-]", "", text).lower()
        return compact if re.fullmatch(r"[0-9a-f]{64}", compact) else None
    return text[:1000]


def _normalized_result(value: object) -> str:
    text = " ".join(str(value or "").casefold().split())
    if text in _ISSUE_RESULT_TERMS or text in _NON_ISSUE_RESULT_TERMS:
        return text
    non_issue_terms = {term for term in _NON_ISSUE_RESULT_TERMS if _contains_result_term(text, term)}
    issue_terms = {term for term in _ISSUE_RESULT_TERMS if _contains_result_term(text, term)}
    if non_issue_terms and issue_terms:
        return _AMBIGUOUS_RESULT
    if non_issue_terms:
        return max(non_issue_terms, key=len)
    if issue_terms:
        return max(issue_terms, key=len)
    return text


def _normalize_tls_protocol_id(value: object) -> str:
    return str(value or "").strip().casefold().replace("-", "_").replace(" ", "_").replace(".", "_")


def _contains_result_term(value: object, term: str) -> bool:
    text = " ".join(str(value or "").casefold().split())
    escaped = re.escape(term.casefold()).replace(r"\ ", r"\s+")
    return re.search(rf"(?<![a-z0-9]){escaped}(?![a-z0-9])", text) is not None
