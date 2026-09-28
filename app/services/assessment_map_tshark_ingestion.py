"""Pure assessment-map rules for TShark packet metadata and validation correlation."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Protocol
from urllib.parse import urlsplit

from app.services.assessment_map_identity import (
    CanonicalIdentity,
    canonical_endpoint,
    canonical_finding,
    canonical_hostname,
    canonical_ip,
    canonical_service,
)

STRUCTURED_ARTIFACT_TYPES = {
    "tshark": frozenset({
        "tshark_normalized_evidence",
        "tshark_metasploit_correlation_record",
        "tshark_validation_capture_provenance",
    }),
}
_SAFE_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/+@ -]{0,199}$")
_SAFE_PROTOCOL_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,31}$")
_SENSITIVE_TERMS = (
    "authorization", "bearer", "cookie", "credential", "password", "passwd",
    "secret", "token", "api_key", "apikey", "private_key", "private-key",
)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
)


class MappingWriter(Protocol):
    root_path: str
    def entity(self, identity: CanonicalIdentity, evidence_kind: str, path: str) -> Any: ...
    def assertion(self, subject: Any, predicate: str, *, evidence_kind: str, path: str,
                  object_entity: Any | None = None, value: Any = ...) -> Any: ...
    def skipped_optional(self, reason: str) -> None: ...


def project_tshark_source(tool: str, data: dict[str, Any]) -> dict[str, Any]:
    if tool != "tshark":
        raise ValueError("Unsupported packet evidence tool.")
    source = str(data.get("source") or "").strip().lower()
    if source == "tshark_metasploit_correlation":
        return _project_correlation(data)
    if source == "tshark_capture_during_validation":
        return _project_capture_provenance(data)
    return _project_tshark_evidence(data)


def tshark_coverage_metadata(tool: str, data: dict[str, Any]) -> dict[str, Any]:
    if tool != "tshark":
        return {}
    source = str(data.get("source") or "").strip().lower()
    if source == "tshark_metasploit_correlation":
        return {
            "source": "tshark_metasploit_correlation",
            "correlation_outcome": _safe_label(data.get("correlation_outcome")),
            "correlation_confidence": _safe_label(data.get("correlation_confidence")),
        }
    return {
        "source": source or "tshark",
        "packet_count": _nonnegative_int(data.get("packet_count")),
        "byte_count": _nonnegative_int(data.get("byte_count")),
        "execution_status": _safe_label(data.get("execution_status")),
    }


def map_tshark_source(tool: str, data: dict[str, Any], writer: MappingWriter) -> None:
    if tool != "tshark":
        raise ValueError("Unsupported packet evidence tool.")
    source = str(data.get("source") or "").strip().lower()
    if source == "tshark_metasploit_correlation":
        _map_correlation(data, writer)
    elif source == "tshark_capture_during_validation":
        _map_capture_provenance(data, writer)
    else:
        _map_tshark_evidence(data, writer)


def _map_tshark_evidence(data: dict[str, Any], writer: MappingWriter) -> None:
    if str(data.get("source") or "tshark").strip().lower() != "tshark":
        raise ValueError("TShark normalized evidence has an unsupported source.")
    mapped = 0
    capture = None
    capture_surface = _first_surface(data)
    if capture_surface is not None:
        surface_path = _first_surface_path(data, writer.root_path)
        capture_entity = writer.entity(capture_surface, "tshark_capture_surface", surface_path)
        stable = _capture_stable_id(data)
        capture = writer.entity(canonical_finding("tshark", stable, capture_surface, matcher="capture"),
                                "tshark_capture_metadata", f"{writer.root_path}.packet_count")
        writer.assertion(capture, "capture_observed_surface", object_entity=capture_entity,
                         evidence_kind="tshark_capture_surface", path=surface_path)
        mapped += 1
        for predicate, field in (
            ("has_packet_count", "packet_count"),
            ("has_byte_count", "byte_count"),
            ("has_capture_start", "capture_start"),
            ("has_capture_end", "capture_end"),
            ("has_execution_status", "execution_status"),
        ):
            value = _safe_value(data.get(field))
            if value not in (None, ""):
                writer.assertion(capture, predicate, value=value, evidence_kind=predicate, path=f"{writer.root_path}.{field}")

    for index, item in enumerate(data.get("observed_endpoints") or []):
        if not isinstance(item, dict):
            writer.skipped_optional("malformed_tshark_endpoint")
            continue
        identity = _ip_identity(item.get("address"))
        if identity is None:
            writer.skipped_optional("unsupported_tshark_endpoint")
            continue
        endpoint = writer.entity(identity, "tshark_observed_endpoint", f"{writer.root_path}.observed_endpoints[{index}].address")
        if capture is not None:
            writer.assertion(capture, "observed_endpoint", object_entity=endpoint,
                             evidence_kind="tshark_observed_endpoint", path=f"{writer.root_path}.observed_endpoints[{index}].address")
        packet_count = _nonnegative_int(item.get("packet_count"))
        if packet_count is not None:
            writer.assertion(endpoint, "has_packet_count", value=packet_count,
                             evidence_kind="tshark_endpoint_packet_count", path=f"{writer.root_path}.observed_endpoints[{index}].packet_count")
        mapped += 1

    for index, item in enumerate(data.get("observed_protocols") or []):
        if not isinstance(item, dict):
            writer.skipped_optional("malformed_tshark_protocol")
            continue
        protocol = _safe_protocol(item.get("protocol"))
        if not protocol or capture is None:
            writer.skipped_optional("unsupported_tshark_protocol")
            continue
        writer.assertion(capture, "observed_protocol", value=protocol,
                         evidence_kind="tshark_observed_protocol", path=f"{writer.root_path}.observed_protocols[{index}].protocol")
        mapped += 1

    mapped += _map_conversations(data, writer, capture)
    mapped += _map_dns(data, writer, capture)
    mapped += _map_http(data, writer, capture)
    mapped += _map_tls(data, writer, capture)
    if not mapped:
        raise ValueError("No supported normalized TShark packet evidence.")


def _map_conversations(data: dict[str, Any], writer: MappingWriter, capture: Any | None) -> int:
    mapped = 0
    for index, item in enumerate(data.get("observed_conversations") or []):
        if not isinstance(item, dict):
            writer.skipped_optional("malformed_tshark_conversation")
            continue
        src_identity = _ip_identity(item.get("src"))
        dst_identity = _ip_identity(item.get("dst"))
        if src_identity is None or dst_identity is None:
            writer.skipped_optional("unsupported_tshark_conversation")
            continue
        base = f"{writer.root_path}.observed_conversations[{index}]"
        src = writer.entity(src_identity, "tshark_conversation_src", f"{base}.src")
        dst = writer.entity(dst_identity, "tshark_conversation_dst", f"{base}.dst")
        writer.assertion(src, "observed_network_flow_to", object_entity=dst,
                         evidence_kind="tshark_observed_flow", path=base)
        if capture is not None:
            writer.assertion(capture, "observed_network_flow", object_entity=dst,
                             evidence_kind="tshark_observed_flow", path=base)
        transport = _safe_protocol(item.get("transport"))
        for side, field in ((src, "src_port"), (dst, "dst_port")):
            port = _positive_port(item.get(field))
            if transport and port is not None:
                service = writer.entity(canonical_service(_network_value(side), transport, port),
                                        "tshark_observed_port_traffic", f"{base}.{field}")
                writer.assertion(side, "observed_port_traffic", object_entity=service,
                                 evidence_kind="tshark_observed_port", path=f"{base}.{field}")
        for predicate, field in (
            ("has_transport_protocol", "transport"),
            ("has_highest_protocol", "highest_protocol"),
            ("has_packet_count", "packet_count"),
            ("has_byte_count", "byte_count"),
        ):
            value = _safe_value(item.get(field))
            if value not in (None, ""):
                writer.assertion(dst, predicate, value=value, evidence_kind=f"tshark_{field}", path=f"{base}.{field}")
        mapped += 1
    return mapped


def _map_dns(data: dict[str, Any], writer: MappingWriter, capture: Any | None) -> int:
    mapped = 0
    for index, item in enumerate(data.get("dns_observations") or []):
        if not isinstance(item, dict):
            writer.skipped_optional("malformed_tshark_dns")
            continue
        base = f"{writer.root_path}.dns_observations[{index}]"
        src = writer.entity(_ip_identity(item.get("src")), "tshark_dns_src", f"{base}.src") if _ip_identity(item.get("src")) else None
        query = _hostname_identity(item.get("query_name"))
        response_ip = _ip_identity(item.get("response_address"))
        response_name = _hostname_identity(item.get("response_name"))
        if query is not None:
            query_entity = writer.entity(query, "tshark_dns_query_name", f"{base}.query_name")
            if src is not None:
                writer.assertion(src, "observed_dns_query", object_entity=query_entity,
                                 evidence_kind="tshark_dns_query", path=f"{base}.query_name")
            if capture is not None:
                writer.assertion(capture, "observed_dns_query", object_entity=query_entity,
                                 evidence_kind="tshark_dns_query", path=f"{base}.query_name")
            mapped += 1
        subject = writer.entity(response_name, "tshark_dns_response_name", f"{base}.response_name") if response_name is not None else None
        if subject is not None and response_ip is not None:
            response = writer.entity(response_ip, "tshark_dns_response_address", f"{base}.response_address")
            writer.assertion(subject, "observed_dns_response_address", object_entity=response,
                             evidence_kind="tshark_dns_response", path=f"{base}.response_address")
            mapped += 1
    return mapped


def _map_http(data: dict[str, Any], writer: MappingWriter, capture: Any | None) -> int:
    mapped = 0
    for index, item in enumerate(data.get("http_observations") or []):
        if not isinstance(item, dict):
            writer.skipped_optional("malformed_tshark_http")
            continue
        base = f"{writer.root_path}.http_observations[{index}]"
        dst_identity = _ip_identity(item.get("dst"))
        dst = writer.entity(dst_identity, "tshark_http_dst", f"{base}.dst") if dst_identity is not None else None
        host_identity = _hostname_identity(item.get("host"))
        if host_identity is not None:
            host = writer.entity(host_identity, "tshark_http_host", f"{base}.host")
            if dst is not None:
                writer.assertion(dst, "observed_http_host", object_entity=host,
                                 evidence_kind="tshark_http_host", path=f"{base}.host")
            if capture is not None:
                writer.assertion(capture, "observed_http_host", object_entity=host,
                                 evidence_kind="tshark_http_host", path=f"{base}.host")
            endpoint_identity = _http_endpoint_identity(item.get("host"), item.get("uri"))
            if endpoint_identity is not None:
                endpoint = writer.entity(endpoint_identity, "tshark_http_request_endpoint", f"{base}.uri")
                writer.assertion(host, "observed_http_request_endpoint", object_entity=endpoint,
                                 evidence_kind="tshark_http_uri", path=f"{base}.uri")
            mapped += 1
        for predicate, field in (("has_http_method", "method"), ("has_http_response_code", "response_code")):
            value = _safe_label(item.get(field))
            if value and dst is not None:
                writer.assertion(dst, predicate, value=value, evidence_kind=f"tshark_{field}", path=f"{base}.{field}")
                mapped += 1
    return mapped


def _map_tls(data: dict[str, Any], writer: MappingWriter, capture: Any | None) -> int:
    mapped = 0
    for index, item in enumerate(data.get("tls_observations") or []):
        if not isinstance(item, dict):
            writer.skipped_optional("malformed_tshark_tls")
            continue
        base = f"{writer.root_path}.tls_observations[{index}]"
        dst_identity = _ip_identity(item.get("dst"))
        dst = writer.entity(dst_identity, "tshark_tls_dst", f"{base}.dst") if dst_identity is not None else None
        sni_identity = _hostname_identity(item.get("sni"))
        if sni_identity is not None:
            sni = writer.entity(sni_identity, "tshark_tls_sni", f"{base}.sni")
            if dst is not None:
                writer.assertion(dst, "observed_tls_sni", object_entity=sni,
                                 evidence_kind="tshark_tls_sni", path=f"{base}.sni")
            if capture is not None:
                writer.assertion(capture, "observed_tls_sni", object_entity=sni,
                                 evidence_kind="tshark_tls_sni", path=f"{base}.sni")
            mapped += 1
        version = _safe_label(item.get("version"))
        if version and dst is not None:
            writer.assertion(dst, "observed_tls_version_field", value=version,
                             evidence_kind="tshark_tls_version", path=f"{base}.version")
            mapped += 1
    return mapped


def _map_capture_provenance(data: dict[str, Any], writer: MappingWriter) -> None:
    target_identity = _target_identity(data.get("target"))
    if target_identity is None:
        raise ValueError("TShark validation-capture provenance has no supported target.")
    target = writer.entity(target_identity, "tshark_capture_validation_target", f"{writer.root_path}.target")
    finding = writer.entity(canonical_finding("tshark", _hash_id(data.get("capture_proposal_id") or data), target_identity, matcher="capture_during_validation"),
                            "tshark_capture_validation_provenance", f"{writer.root_path}.capture_proposal_id")
    writer.assertion(finding, "capture_targets_validation_surface", object_entity=target,
                     evidence_kind="tshark_capture_validation_target", path=f"{writer.root_path}.target")
    port = _positive_port(data.get("port"))
    if port is not None:
        service = writer.entity(canonical_service(_target_network_value(data.get("target")), "tcp", port),
                                "tshark_capture_validation_service", f"{writer.root_path}.port")
        writer.assertion(finding, "capture_targets_validation_service", object_entity=service,
                         evidence_kind="tshark_capture_validation_port", path=f"{writer.root_path}.port")
    for predicate, field in (
        ("has_capture_proposal_id", "capture_proposal_id"),
        ("has_validation_proposal_id", "validation_proposal_id"),
        ("has_capture_interface", "interface"),
        ("has_capture_started_at", "capture_started_at"),
        ("has_capture_ended_at", "capture_ended_at"),
        ("has_validation_started_at", "validation_started_at"),
        ("has_validation_ended_at", "validation_ended_at"),
    ):
        value = _safe_label(data.get(field))
        if value:
            writer.assertion(finding, predicate, value=value, evidence_kind=predicate, path=f"{writer.root_path}.{field}")


def _map_correlation(data: dict[str, Any], writer: MappingWriter) -> None:
    target_identity = _target_identity(data.get("target_hostname"))
    if target_identity is None:
        raise ValueError("TShark correlation record has no supported target.")
    target = writer.entity(target_identity, "tshark_correlation_target", f"{writer.root_path}.target_hostname")
    correlation = writer.entity(canonical_finding("tshark", _hash_id(_correlation_key(data)), target_identity, matcher="metasploit_correlation"),
                                "tshark_metasploit_correlation", f"{writer.root_path}.correlation_outcome")
    writer.assertion(correlation, "correlates_validation_capture_target", object_entity=target,
                     evidence_kind="tshark_correlation_target", path=f"{writer.root_path}.target_hostname")
    port = _positive_port(data.get("expected_port"))
    if port is not None:
        service = writer.entity(canonical_service(_target_network_value(data.get("target_hostname")), "tcp", port),
                                "tshark_correlation_expected_service", f"{writer.root_path}.expected_port")
        writer.assertion(correlation, "correlates_validation_expected_service", object_entity=service,
                         evidence_kind="tshark_correlation_expected_port", path=f"{writer.root_path}.expected_port")
    for predicate, field in (
        ("has_correlation_confidence", "correlation_confidence"),
        ("has_correlation_outcome", "correlation_outcome"),
        ("has_agreement_state", "agreement_disagreement_state"),
        ("has_validation_proposal_id", "validation_proposal_id"),
        ("has_capture_proposal_id", "capture_proposal_id"),
        ("has_capture_provenance_id", "capture_provenance_id"),
        ("has_validation_result_id", "validation_result_id"),
    ):
        value = _safe_label(data.get(field))
        if value:
            writer.assertion(correlation, predicate, value=value, evidence_kind=predicate, path=f"{writer.root_path}.{field}")
    meaning = _safe_text(data.get("correlation_confidence_meaning"), limit=500)
    if meaning:
        writer.assertion(correlation, "has_correlation_confidence_meaning", value=meaning,
                         evidence_kind="tshark_correlation_confidence_meaning", path=f"{writer.root_path}.correlation_confidence_meaning")
    tshark = data.get("tshark") if isinstance(data.get("tshark"), dict) else {}
    for index, item in enumerate(tshark.get("relevant_conversations") or []):
        if not isinstance(item, dict):
            continue
        dst_identity = _ip_identity(item.get("dst"))
        if dst_identity is None:
            continue
        dst = writer.entity(dst_identity, "tshark_correlated_flow_endpoint", f"{writer.root_path}.tshark.relevant_conversations[{index}].dst")
        writer.assertion(correlation, "has_correlated_packet_endpoint", object_entity=dst,
                         evidence_kind="tshark_correlated_endpoint", path=f"{writer.root_path}.tshark.relevant_conversations[{index}].dst")


def _project_tshark_evidence(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": "tshark",
        "execution_status": _safe_label(data.get("execution_status")),
        "success": data.get("success") is True,
        "packet_count": _nonnegative_int(data.get("packet_count")),
        "byte_count": _nonnegative_int(data.get("byte_count")),
        "capture_start": _safe_label(data.get("capture_start")),
        "capture_end": _safe_label(data.get("capture_end")),
        "observed_protocols": [_project_item(item, ("protocol", "packet_count")) for item in (data.get("observed_protocols") or [])[:20] if isinstance(item, dict)],
        "observed_endpoints": [_project_item(item, ("address", "packet_count")) for item in (data.get("observed_endpoints") or [])[:50] if isinstance(item, dict)],
        "observed_conversations": [_project_item(item, ("src", "dst", "src_port", "dst_port", "transport", "highest_protocol", "packet_count", "byte_count")) for item in (data.get("observed_conversations") or [])[:50] if isinstance(item, dict)],
        "dns_observations": [_project_item(item, ("src", "dst", "query_name", "response_name", "response_address")) for item in (data.get("dns_observations") or [])[:50] if isinstance(item, dict)],
        "http_observations": [_project_item(item, ("src", "dst", "method", "host", "uri", "response_code")) for item in (data.get("http_observations") or [])[:50] if isinstance(item, dict)],
        "tls_observations": [_project_item(item, ("src", "dst", "sni", "version")) for item in (data.get("tls_observations") or [])[:50] if isinstance(item, dict)],
        "truncation": data.get("truncation") if isinstance(data.get("truncation"), dict) else {},
    }


def _project_capture_provenance(data: dict[str, Any]) -> dict[str, Any]:
    return {
        key: _safe_label(data.get(key))
        for key in (
            "source", "validation_proposal_id", "capture_proposal_id", "target", "module",
            "action", "port", "interface", "capture_started_at", "capture_ended_at",
            "validation_started_at", "validation_ended_at",
        )
        if key in data
    }


def _project_correlation(data: dict[str, Any]) -> dict[str, Any]:
    projected = {
        key: _safe_label(data.get(key))
        for key in (
            "source", "schema_version", "validation_proposal_id", "validation_result_id",
            "capture_proposal_id", "capture_provenance_id", "target_hostname",
            "expected_port", "correlation_confidence", "correlation_outcome",
            "agreement_disagreement_state",
        )
        if key in data
    }
    if "correlation_confidence_meaning" in data:
        projected["correlation_confidence_meaning"] = _safe_text(data.get("correlation_confidence_meaning"), limit=500)
    return projected


def _project_item(item: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    projected = {}
    for field in fields:
        value = _safe_text(item.get(field), limit=500) if field == "uri" else _safe_value(item.get(field))
        if value not in (None, ""):
            projected[field] = value
    return projected


def _first_surface(data: dict[str, Any]) -> CanonicalIdentity | None:
    for item in data.get("observed_endpoints") or []:
        if isinstance(item, dict):
            identity = _ip_identity(item.get("address"))
            if identity is not None:
                return identity
    for collection, field in (("observed_conversations", "dst"), ("dns_observations", "dst"), ("http_observations", "dst"), ("tls_observations", "dst")):
        for item in data.get(collection) or []:
            if isinstance(item, dict):
                identity = _ip_identity(item.get(field))
                if identity is not None:
                    return identity
    return None


def _first_surface_path(data: dict[str, Any], root_path: str) -> str:
    for collection, field in (("observed_endpoints", "address"), ("observed_conversations", "dst"), ("dns_observations", "dst"), ("http_observations", "dst"), ("tls_observations", "dst")):
        for index, item in enumerate(data.get(collection) or []):
            if isinstance(item, dict) and _ip_identity(item.get(field)) is not None:
                return f"{root_path}.{collection}[{index}].{field}"
    return f"{root_path}.source"


def _capture_stable_id(data: dict[str, Any]) -> str:
    material = {
        "source_file": data.get("source_file") if isinstance(data.get("source_file"), dict) else {},
        "packet_count": data.get("packet_count"),
        "byte_count": data.get("byte_count"),
        "capture_start": data.get("capture_start"),
        "capture_end": data.get("capture_end"),
    }
    return _hash_id(material)


def _correlation_key(data: dict[str, Any]) -> str:
    return "|".join(str(data.get(field) or "") for field in (
        "validation_proposal_id", "capture_proposal_id", "capture_provenance_id",
        "validation_result_id", "target_hostname", "expected_port",
    ))


def _target_identity(value: object) -> CanonicalIdentity | None:
    text = str(value or "").strip()
    if not text or _looks_sensitive(text):
        return None
    try:
        return canonical_ip(text.strip("[]"))
    except ValueError:
        return _hostname_identity(text)


def _ip_identity(value: object) -> CanonicalIdentity | None:
    text = str(value or "").strip()
    if not text or _looks_sensitive(text):
        return None
    try:
        return canonical_ip(text.strip("[]"))
    except ValueError:
        return None


def _hostname_identity(value: object) -> CanonicalIdentity | None:
    text = str(value or "").strip().rstrip(".")
    if not text or _looks_sensitive(text):
        return None
    try:
        return canonical_hostname(text)
    except ValueError:
        return None


def _http_endpoint_identity(host: object, uri: object) -> CanonicalIdentity | None:
    host_text = str(host or "").strip()
    uri_text = str(uri or "").strip() or "/"
    if not host_text or _looks_sensitive(host_text) or _looks_sensitive(uri_text):
        return None
    if not uri_text.startswith("/"):
        uri_text = "/" + uri_text
    try:
        parsed = urlsplit(uri_text)
        if parsed.scheme or parsed.netloc:
            return None
        return canonical_endpoint(f"http://{host_text}{uri_text}")
    except ValueError:
        return None


def _network_value(entity_row: Any) -> str:
    try:
        payload = entity_row["canonical_key"]
    except (TypeError, KeyError):
        return ""
    match = re.search(r'"address"\s*:\s*"([^"]+)"', str(payload))
    return match.group(1) if match else ""


def _target_network_value(value: object) -> str:
    return str(value or "").strip().strip("[]")


def _safe_value(value: object) -> object:
    if isinstance(value, bool):
        return value
    integer = _nonnegative_int(value)
    if integer is not None and str(value).strip().isdigit():
        return integer
    return _safe_label(value)


def _safe_label(value: object) -> str | None:
    text = " ".join(str(value or "").split())
    return text if _SAFE_LABEL_RE.fullmatch(text) and not _looks_sensitive(text) else None


def _safe_text(value: object, *, limit: int = 300) -> str | None:
    text = " ".join(str(value or "").split())[:limit]
    return text if text and not _looks_sensitive(text) else None


def _safe_protocol(value: object) -> str | None:
    text = str(value or "").strip().lower()
    return text if _SAFE_PROTOCOL_RE.fullmatch(text) and not _looks_sensitive(text) else None


def _positive_port(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(str(value or "").strip())
    except ValueError:
        return None
    return parsed if 1 <= parsed <= 65535 else None


def _nonnegative_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(str(value or "").strip())
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _hash_id(value: object) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _looks_sensitive(value: object) -> bool:
    text = str(value or "")
    lowered = text.lower()
    return any(term in lowered for term in _SENSITIVE_TERMS) or any(pattern.search(text) for pattern in _SECRET_VALUE_PATTERNS)
