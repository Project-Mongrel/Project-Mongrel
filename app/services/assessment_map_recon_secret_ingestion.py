"""Pure assessment-map rules for BBOT reconnaissance and redacted Gitleaks evidence."""

from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath
from typing import Any, Protocol
from urllib.parse import urlsplit

from app.services.assessment_map_identity import (
    CanonicalIdentity,
    canonical_application_origin,
    canonical_endpoint,
    canonical_hostname,
    canonical_ip,
    canonical_service,
    canonical_technology,
    identity_from_payload,
)

STRUCTURED_ARTIFACT_TYPES = {"bbot": frozenset(), "gitleaks": frozenset()}
_SAFE_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/+@ -]{0,199}$")
_SAFE_RULE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:+/-]{0,199}$")
_BBOT_SERVICE_RE = re.compile(r"^\[?([^\]]+)\]?:([0-9]{1,5})$")
_DNS_ADDRESS_RE = re.compile(r"^([^\s]+)\s+(?:A|AAAA)\s+([^\s]+)$", re.IGNORECASE)
_SENSITIVE_TERMS = (
    "authorization", "bearer", "cookie", "credential", "password", "passwd",
    "secret", "token", "api_key", "apikey", "private_key", "private-key",
)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\b(?:[A-Fa-f0-9]{40,}|[A-Za-z0-9+/]{48,}={0,2})\b"),
)


class MappingWriter(Protocol):
    root_path: str
    def entity(self, identity: CanonicalIdentity, evidence_kind: str, path: str) -> Any: ...
    def assertion(self, subject: Any, predicate: str, *, evidence_kind: str, path: str,
                  object_entity: Any | None = None, value: Any = ...) -> Any: ...
    def skipped_optional(self, reason: str) -> None: ...


def project_recon_secret_source(tool: str, data: dict[str, Any]) -> dict[str, Any]:
    """Project only fields that are safe and meaningful to assessment mapping."""

    if tool == "bbot":
        observations = data.get("observations")
        if not isinstance(observations, list):
            projected: object = {"malformed_type": type(observations).__name__}
        else:
            projected = [_project_bbot_observation(item) for item in observations]
        return {"source": data.get("source"), "observations": projected}
    if tool == "gitleaks":
        evidence = data.get("gitleaks_evidence")
        findings = evidence.get("findings") if isinstance(evidence, dict) else None
        if not isinstance(findings, list):
            projected_findings: object = {"malformed_type": type(findings).__name__}
        else:
            projected_findings = [_project_gitleaks_finding(item) for item in findings]
        return {"source": data.get("source"), "gitleaks_findings": projected_findings}
    raise ValueError("Unsupported reconnaissance or secret-evidence tool.")


def recon_secret_coverage_metadata(tool: str, data: dict[str, Any]) -> dict[str, Any]:
    if tool == "bbot":
        observations = data.get("observations")
        if not isinstance(observations, list):
            return {}
        counts: dict[str, int] = {}
        for item in observations:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("observation_type") or "unknown").strip().lower()
            counts[kind] = counts.get(kind, 0) + 1
        return {"observation_count": len(observations), "observation_types": counts}
    evidence = data.get("gitleaks_evidence")
    findings = evidence.get("findings") if isinstance(evidence, dict) else None
    return {"redacted_finding_count": len(findings)} if isinstance(findings, list) else {}


def map_recon_secret_source(tool: str, data: dict[str, Any], writer: MappingWriter) -> None:
    source_tool = str(data.get("source") or "").strip().lower().removesuffix(".sh")
    if source_tool and source_tool != tool:
        raise ValueError("Linked structured evidence does not match the scan tool.")
    if tool == "bbot":
        _map_bbot(data, writer)
    elif tool == "gitleaks":
        _map_gitleaks(data, writer)
    else:
        raise ValueError("Unsupported reconnaissance or secret-evidence tool.")


def _map_bbot(data: dict[str, Any], writer: MappingWriter) -> None:
    observations = data.get("observations")
    if not isinstance(observations, list):
        raise ValueError("Missing normalized BBOT observations.")
    mapped = 0
    for index, observation in enumerate(observations):
        if not isinstance(observation, dict):
            writer.skipped_optional("malformed_bbot_observation")
            continue
        base = f"{writer.root_path}.observations[{index}]"
        kind = str(observation.get("observation_type") or "").strip().lower()
        value = str(observation.get("value") or "").strip()
        raw_event = _raw_event(observation)
        event_type = _safe_label(raw_event.get("type") or raw_event.get("event_type"))
        primary = _map_bbot_primary(kind, value, raw_event, writer, base)
        if primary is None:
            writer.skipped_optional(f"unsupported_bbot_{kind or 'observation'}")
            continue
        mapped += 1
        if event_type:
            event_type_field = "type" if raw_event.get("type") not in (None, "") else "event_type"
            writer.assertion(primary, "has_bbot_event_type", value=event_type,
                             evidence_kind="bbot_event_type",
                             path=f"{base}.metadata.raw_event.{event_type_field}")
        module = _safe_label(raw_event.get("module"))
        if module:
            writer.assertion(primary, "has_bbot_module", value=module,
                             evidence_kind="bbot_module", path=f"{base}.metadata.raw_event.module")
        _map_bbot_explicit_source(primary, raw_event.get("source"), writer, base)
        _map_bbot_resolved_addresses(primary, kind, raw_event, writer, base)
    if not mapped:
        raise ValueError("No supported normalized BBOT observations.")


def _map_bbot_primary(kind: str, value: str, raw_event: dict, writer: MappingWriter, base: str) -> Any | None:
    try:
        if kind == "subdomain":
            return writer.entity(canonical_hostname(value), "bbot_hostname", f"{base}.value")
        if kind in {"ip_address", "open_port"}:
            service = _bbot_service(raw_event, value)
            if service is not None:
                host_identity, service_identity = service
                host = writer.entity(host_identity, "bbot_service_host", f"{base}.value")
                service_row = writer.entity(service_identity, "bbot_network_service", f"{base}.value")
                writer.assertion(host, "exposes_service", object_entity=service_row,
                                 evidence_kind="bbot_open_tcp_port", path=f"{base}.value")
                return service_row
            if kind == "open_port":
                return None
            return writer.entity(canonical_ip(value), "bbot_ip", f"{base}.value")
        if kind == "url":
            application = writer.entity(canonical_application_origin(value), "bbot_url", f"{base}.value")
            endpoint = writer.entity(canonical_endpoint(value), "bbot_url", f"{base}.value")
            writer.assertion(application, "exposes_endpoint", object_entity=endpoint,
                             evidence_kind="bbot_url", path=f"{base}.value")
            return endpoint
        if kind == "technology":
            technology = writer.entity(canonical_technology(value), "bbot_technology", f"{base}.value")
            surface = _explicit_surface(raw_event)
            if surface is not None:
                surface_row = writer.entity(surface, "bbot_technology_surface", _surface_path(base, raw_event))
                writer.assertion(surface_row, "uses_technology", object_entity=technology,
                                 evidence_kind="bbot_technology", path=f"{base}.value")
            return technology
        if kind == "dns_record":
            match = _DNS_ADDRESS_RE.fullmatch(value)
            if match:
                hostname = writer.entity(canonical_hostname(match.group(1)), "bbot_dns_name", f"{base}.value")
                address = writer.entity(canonical_ip(match.group(2)), "bbot_dns_address", f"{base}.value")
                writer.assertion(hostname, "observed_address", object_entity=address,
                                 evidence_kind="bbot_dns_record", path=f"{base}.value")
                return hostname
    except ValueError:
        return None
    return None


def _map_bbot_explicit_source(primary: Any, value: object, writer: MappingWriter, base: str) -> None:
    source = _canonical_surface(value)
    if source is None:
        return
    source_row = writer.entity(source, "bbot_event_source", f"{base}.metadata.raw_event.source")
    if int(source_row["id"]) != int(primary["id"]):
        writer.assertion(primary, "discovered_from", object_entity=source_row,
                         evidence_kind="bbot_event_source", path=f"{base}.metadata.raw_event.source")


def _map_bbot_resolved_addresses(primary: Any, kind: str, raw_event: dict,
                                  writer: MappingWriter, base: str) -> None:
    if kind != "subdomain":
        return
    values = raw_event.get("resolved_hosts") or raw_event.get("resolved_host")
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list):
        return
    field = "resolved_hosts" if "resolved_hosts" in raw_event else "resolved_host"
    for index, value in enumerate(values[:20]):
        try:
            address = writer.entity(canonical_ip(str(value)), "bbot_resolved_address",
                                    f"{base}.metadata.raw_event.{field}[{index}]")
        except ValueError:
            writer.skipped_optional("malformed_bbot_resolved_address")
            continue
        writer.assertion(primary, "observed_address", object_entity=address,
                         evidence_kind="bbot_resolved_address",
                         path=f"{base}.metadata.raw_event.{field}[{index}]")


def _map_gitleaks(data: dict[str, Any], writer: MappingWriter) -> None:
    evidence = data.get("gitleaks_evidence")
    findings = evidence.get("findings") if isinstance(evidence, dict) else None
    if not isinstance(findings, list):
        raise ValueError("Missing normalized Gitleaks findings.")
    mapped = 0
    for index, finding_data in enumerate(findings):
        if not isinstance(finding_data, dict):
            writer.skipped_optional("malformed_gitleaks_finding")
            continue
        base = f"{writer.root_path}.gitleaks_evidence.findings[{index}]"
        rule_id = _safe_rule(finding_data.get("rule_id"))
        source_path = _safe_source_path(finding_data.get("file_path"))
        if rule_id is None or source_path is None:
            writer.skipped_optional("unsupported_gitleaks_finding")
            continue
        line_number = _positive_int(finding_data.get("line_number"))
        stable_material = f"{rule_id}\0{source_path}\0{line_number or 0}".encode("utf-8")
        stable_id = hashlib.sha256(stable_material).hexdigest()
        identity = identity_from_payload("finding", {
            "tool": "gitleaks", "stable_id": stable_id,
            "affected_surface_type": "redacted_source_location",
            "affected_surface_hash": hashlib.sha256(source_path.encode("utf-8")).hexdigest(),
        })
        finding = writer.entity(identity, "gitleaks_redacted_match", f"{base}.rule_id")
        writer.assertion(finding, "has_rule_id", value=rule_id,
                         evidence_kind="gitleaks_rule", path=f"{base}.rule_id")
        writer.assertion(finding, "observed_in_source_path", value=source_path,
                         evidence_kind="gitleaks_source_path", path=f"{base}.file_path")
        if line_number is not None:
            writer.assertion(finding, "has_line_number", value=line_number,
                             evidence_kind="gitleaks_line", path=f"{base}.line_number")
        for field, predicate in (("severity", "has_scanner_severity"), ("provider", "has_provider")):
            value = _safe_label(finding_data.get(field))
            if value:
                writer.assertion(finding, predicate, value=value, evidence_kind=predicate,
                                 path=f"{base}.{field}")
        tags = finding_data.get("tags") or []
        if isinstance(tags, list):
            for tag_index, tag in enumerate(tags[:10]):
                safe_tag = _safe_label(tag)
                if safe_tag:
                    writer.assertion(finding, "has_tag", value=safe_tag,
                                     evidence_kind="gitleaks_tag", path=f"{base}.tags[{tag_index}]")
        else:
            writer.skipped_optional("malformed_gitleaks_tags")
        mapped += 1
    if not mapped:
        raise ValueError("No supported redacted Gitleaks findings.")


def _project_bbot_observation(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"malformed_type": type(value).__name__}
    raw_event = _raw_event(value)
    projected_event = {
        key: raw_event.get(key)
        for key in ("type", "event_type", "module", "source", "host", "url", "port", "protocol", "resolved_host", "resolved_hosts")
        if key in raw_event
    }
    return {
        "observation_type": value.get("observation_type"),
        "value": value.get("value"),
        "metadata": {"raw_event": projected_event} if projected_event else {},
    }


def _project_gitleaks_finding(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"malformed_type": type(value).__name__}
    return {
        key: value.get(key)
        for key in ("rule_id", "file_path", "line_number", "severity", "provider", "tags")
        if key in value
    }


def _raw_event(observation: dict[str, Any]) -> dict[str, Any]:
    metadata = observation.get("metadata")
    event = metadata.get("raw_event") if isinstance(metadata, dict) else None
    return event if isinstance(event, dict) else {}


def _bbot_service(raw_event: dict[str, Any], fallback: str) -> tuple[CanonicalIdentity, CanonicalIdentity] | None:
    event_type = str(raw_event.get("type") or raw_event.get("event_type") or "").strip().lower()
    if event_type.replace("-", "_") != "open_tcp_port":
        return None
    host_value = str(raw_event.get("host") or fallback).strip()
    port_value = raw_event.get("port")
    if port_value in (None, ""):
        match = _BBOT_SERVICE_RE.fullmatch(str(raw_event.get("data") or fallback).strip())
        if match is None:
            return None
        host_value, port_value = match.groups()
    host = _network_identity(host_value)
    port = _positive_int(port_value)
    if host is None or port is None or port > 65535:
        return None
    return host, canonical_service(_network_value(host), "tcp", port)


def _explicit_surface(raw_event: dict[str, Any]) -> CanonicalIdentity | None:
    for field in ("url", "host"):
        surface = _canonical_surface(raw_event.get(field))
        if surface is not None:
            return surface
    return None


def _surface_path(base: str, raw_event: dict[str, Any]) -> str:
    return f"{base}.metadata.raw_event.url" if raw_event.get("url") else f"{base}.metadata.raw_event.host"


def _canonical_surface(value: object) -> CanonicalIdentity | None:
    text = str(value or "").strip()
    if not text or _looks_sensitive(text):
        return None
    try:
        parsed = urlsplit(text)
    except ValueError:
        parsed = None
    if parsed is not None and parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
        try:
            return canonical_endpoint(text)
        except ValueError:
            return None
    return _network_identity(text)


def _network_identity(value: object) -> CanonicalIdentity | None:
    text = str(value or "").strip().strip("[]")
    try:
        return canonical_ip(text)
    except ValueError:
        try:
            return canonical_hostname(text)
        except ValueError:
            return None


def _network_value(identity: CanonicalIdentity) -> str:
    return str(identity.payload.get("address") or identity.payload.get("hostname") or "")


def _safe_source_path(value: object) -> str | None:
    text = str(value or "").replace("\\", "/").strip()
    if not text or "\x00" in text or "://" in text or text.startswith("/"):
        return None
    path = PurePosixPath(text)
    if any(part in {"", ".", ".."} for part in path.parts):
        return None
    safe_parts = ["[redacted-path]" if _looks_sensitive(part) else part for part in path.parts]
    normalized = "/".join(safe_parts)
    if len(normalized) > 500:
        return None
    return normalized


def _safe_rule(value: object) -> str | None:
    text = str(value or "").strip()
    return text if _SAFE_RULE_RE.fullmatch(text) else None


def _safe_label(value: object) -> str | None:
    text = " ".join(str(value or "").split())
    return text if _SAFE_LABEL_RE.fullmatch(text) and not _looks_sensitive(text) else None


def _positive_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _looks_sensitive(value: str) -> bool:
    text = str(value or "")
    lowered = text.lower()
    return any(term in lowered for term in _SENSITIVE_TERMS) or any(
        pattern.search(text) for pattern in _SECRET_VALUE_PATTERNS
    )
