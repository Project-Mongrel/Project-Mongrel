"""Pure assessment-map rules for Prowler cloud evidence and Metasploit validation."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Protocol
from urllib.parse import urlsplit

from app.services.assessment_map_identity import (
    CanonicalIdentity,
    canonical_cloud_account,
    canonical_cloud_region,
    canonical_cloud_resource,
    canonical_endpoint,
    canonical_finding,
    canonical_hostname,
    canonical_ip,
    canonical_service,
)

STRUCTURED_ARTIFACT_TYPES = {"prowler": frozenset(), "metasploit": frozenset()}
_SAFE_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/+@ -]{0,199}$")
_SAFE_MODULE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./:-]{0,199}$")
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
    def validation_attempt(self, **kwargs: Any) -> Any: ...


def project_cloud_validation_source(tool: str, data: dict[str, Any]) -> dict[str, Any]:
    if tool == "prowler":
        evidence = data.get("prowler_evidence")
        findings = evidence.get("findings") if isinstance(evidence, dict) else None
        projected = [_project_prowler_finding(item) for item in findings] if isinstance(findings, list) else {
            "malformed_type": type(findings).__name__,
        }
        return {
            "source": data.get("source"),
            "provider": evidence.get("provider") if isinstance(evidence, dict) else data.get("provider"),
            "cloud_context": evidence.get("cloud_context") if isinstance(evidence, dict) else data.get("cloud_context"),
            "findings": projected,
        }
    if tool == "metasploit":
        evidence = data.get("metasploit_evidence")
        metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        return {
            "source": data.get("source"),
            "metadata": {
                key: metadata.get(key)
                for key in ("proposal_id", "module", "action_type", "port", "risk_tier", "expected_effect")
                if key in metadata
            },
            "metasploit_evidence": _project_metasploit_evidence(evidence),
        }
    raise ValueError("Unsupported cloud or validation evidence tool.")


def cloud_validation_coverage_metadata(tool: str, data: dict[str, Any]) -> dict[str, Any]:
    if tool == "prowler":
        evidence = data.get("prowler_evidence")
        findings = evidence.get("findings") if isinstance(evidence, dict) else None
        if not isinstance(findings, list):
            return {}
        statuses: dict[str, int] = {}
        for item in findings:
            if not isinstance(item, dict):
                continue
            status = (_safe_label(str(item.get("status") or "").strip().upper()) or "unknown")
            statuses[status] = statuses.get(status, 0) + 1
        return {"finding_count": len(findings), "status_summary": statuses}
    evidence = data.get("metasploit_evidence")
    if not isinstance(evidence, dict):
        return {}
    return {
        "validation_state": _safe_label(evidence.get("validation_state")),
        "session_established": evidence.get("session_established") is True,
        "module_executed": evidence.get("module_executed") is True,
    }


def map_cloud_validation_source(tool: str, data: dict[str, Any], writer: MappingWriter) -> None:
    source_tool = str(data.get("source") or "").strip().lower().removesuffix(".sh")
    if source_tool and source_tool != tool:
        raise ValueError("Linked structured evidence does not match the scan tool.")
    if tool == "prowler":
        _map_prowler(data, writer)
    elif tool == "metasploit":
        _map_metasploit(data, writer)
    else:
        raise ValueError("Unsupported cloud or validation evidence tool.")


def _map_prowler(data: dict[str, Any], writer: MappingWriter) -> None:
    evidence = data.get("prowler_evidence")
    findings = evidence.get("findings") if isinstance(evidence, dict) else None
    if not isinstance(findings, list):
        raise ValueError("Missing normalized Prowler findings.")
    provider_root = _safe_label(evidence.get("provider") if isinstance(evidence, dict) else data.get("provider"))
    cloud_context = _safe_label(evidence.get("cloud_context") if isinstance(evidence, dict) else data.get("cloud_context"))
    mapped = 0
    for index, finding_data in enumerate(findings):
        if not isinstance(finding_data, dict):
            writer.skipped_optional("malformed_prowler_finding")
            continue
        base = f"{writer.root_path}.prowler_evidence.findings[{index}]"
        check_id = _safe_label(finding_data.get("check_id"))
        status = _safe_label(finding_data.get("status"))
        provider = _safe_label(finding_data.get("provider")) or provider_root
        account_id = _safe_label(finding_data.get("account_id")) or (f"context:{cloud_context}" if cloud_context else None)
        if not provider or not account_id or not check_id or not status:
            writer.skipped_optional("unsupported_prowler_finding")
            continue
        account = writer.entity(canonical_cloud_account(provider, account_id), "prowler_cloud_account", _account_path(base, finding_data))
        region_text = _safe_label(finding_data.get("region"))
        region = None
        if region_text:
            region = writer.entity(canonical_cloud_region(provider, account_id, region_text), "prowler_cloud_region", f"{base}.region")
            writer.assertion(account, "contains_cloud_region", object_entity=region,
                             evidence_kind="prowler_region", path=f"{base}.region")
        resource = _prowler_resource(provider, account_id, finding_data, base)
        surface = account
        surface_identity = canonical_cloud_account(provider, account_id)
        if resource is not None:
            resource_identity, resource_path = resource
            resource_row = writer.entity(resource_identity, "prowler_cloud_resource", resource_path)
            parent = region or account
            writer.assertion(parent, "contains_cloud_resource", object_entity=resource_row,
                             evidence_kind="prowler_resource", path=resource_path)
            surface = resource_row
            surface_identity = resource_identity
        stable_id = str(finding_data.get("finding_identifier") or check_id)
        finding = writer.entity(canonical_finding("prowler", stable_id, surface_identity, matcher=check_id),
                                "prowler_check_finding", f"{base}.check_id")
        affected_path = _resource_path(base, finding_data) if resource is not None else _account_path(base, finding_data)
        writer.assertion(finding, "finding_affects", object_entity=surface,
                         evidence_kind="prowler_check_resource", path=affected_path)
        for predicate, field in (
            ("has_check_id", "check_id"),
            ("has_finding_name", "check_title"),
            ("has_scanner_status", "status"),
            ("has_status_interpretation", "status_interpretation"),
            ("has_scanner_severity", "severity"),
            ("has_cloud_service", "service"),
            ("has_cloud_provider", "provider"),
        ):
            value = _safe_label(finding_data.get(field))
            if value:
                writer.assertion(finding, predicate, value=value, evidence_kind=predicate, path=f"{base}.{field}")
        service = _safe_label(finding_data.get("service"))
        if service:
            writer.assertion(surface, "has_cloud_service", value=service,
                             evidence_kind="prowler_cloud_service", path=f"{base}.service")
        mapped += 1
    if not mapped:
        raise ValueError("No supported normalized Prowler findings.")


def _map_metasploit(data: dict[str, Any], writer: MappingWriter) -> None:
    evidence = data.get("metasploit_evidence")
    if not isinstance(evidence, dict):
        raise ValueError("Missing normalized Metasploit evidence.")
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    base = f"{writer.root_path}.metasploit_evidence"
    target_identity = _target_identity(evidence.get("target") or data.get("target"))
    port = _positive_int(evidence.get("port") or metadata.get("port"))
    if target_identity is None:
        raise ValueError("Metasploit evidence has no supported target.")
    target = writer.entity(target_identity, "metasploit_target", f"{base}.target")
    surface = target
    surface_identity = target_identity
    if port is not None:
        host_value = _network_value(target_identity)
        service_identity = canonical_service(host_value, "tcp", port)
        service = writer.entity(service_identity, "metasploit_target_service", f"{base}.port")
        writer.assertion(target, "exposes_service", object_entity=service,
                         evidence_kind="metasploit_target_service", path=f"{base}.port")
        surface = service
        surface_identity = service_identity
    module = _safe_module(evidence.get("module") or metadata.get("module"))
    action = _safe_label(evidence.get("action_type") or metadata.get("action_type"))
    state = _safe_label(evidence.get("validation_state"))
    if not module or not action or not state:
        raise ValueError("Metasploit evidence has no supported validation state.")
    proposal_id = _safe_label(metadata.get("proposal_id"))
    stable_material = proposal_id or "|".join(str(value) for value in (module, action, evidence.get("target"), port, state))
    validation = writer.entity(canonical_finding("metasploit", _hash_id(stable_material), surface_identity, matcher=module),
                               "metasploit_validation", f"{base}.validation_state")
    writer.assertion(validation, "validation_targets", object_entity=surface,
                     evidence_kind="metasploit_validation_target", path=f"{base}.target")
    for predicate, field, value in (
        ("has_module", "module", module),
        ("has_action_type", "action_type", action),
        ("has_validation_state", "validation_state", state),
        ("has_evidence_confidence", "evidence_confidence", _safe_label(evidence.get("evidence_confidence"))),
    ):
        if value:
            writer.assertion(validation, predicate, value=value, evidence_kind=predicate, path=f"{base}.{field}")
    for field, predicate in (
        ("subprocess_success", "has_subprocess_success"),
        ("module_executed", "has_module_executed"),
        ("session_established", "has_session_established"),
    ):
        if field in evidence and isinstance(evidence.get(field), bool):
            writer.assertion(validation, predicate, value=bool(evidence.get(field)),
                             evidence_kind=predicate, path=f"{base}.{field}")
    if proposal_id:
        writer.assertion(validation, "has_proposal_id", value=proposal_id,
                         evidence_kind="metasploit_proposal", path=f"{writer.root_path}.metadata.proposal_id")
    writer.validation_attempt(
        attempt_key=proposal_id or _hash_id(stable_material),
        proposal_id=proposal_id,
        module=module,
        action_type=action,
        validation_state=state,
        target_entity_id=int(target["id"]),
        service_entity_id=int(surface["id"]) if surface is not target else None,
        finding_entity_id=int(validation["id"]),
        session_established=evidence.get("session_established") if isinstance(evidence.get("session_established"), bool) else None,
        limitations=[str(item) for item in evidence.get("limitations") or [] if isinstance(item, str)][:10],
    )


def _project_prowler_finding(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"malformed_type": type(value).__name__}
    return {
        key: _safe_label(value.get(key))
        for key in (
            "provider", "account_id", "account_name", "check_id", "check_title", "status",
            "status_interpretation", "severity", "service", "region", "resource_identifier",
            "resource_name", "finding_identifier",
        )
        if key in value
    }


def _project_metasploit_evidence(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"malformed_type": type(value).__name__}
    projected = {
        key: value.get(key)
        for key in (
            "source", "module", "action_type", "target", "port", "validation_state",
            "subprocess_success", "module_executed", "session_established", "evidence_confidence",
            "limitations",
        )
        if key in value
    }
    return projected


def _prowler_resource(provider: str, account_id: str, finding: dict[str, Any], base: str) -> tuple[CanonicalIdentity, str] | None:
    resource_id = _safe_label(finding.get("resource_identifier"))
    resource_name = _safe_label(finding.get("resource_name"))
    if not resource_id and not resource_name:
        return None
    return (
        canonical_cloud_resource(
            provider,
            account_id,
            region=_safe_label(finding.get("region")),
            service=_safe_label(finding.get("service")),
            resource_id=resource_id,
            resource_name=resource_name,
        ),
        _resource_path(base, finding),
    )


def _account_path(base: str, finding: dict[str, Any]) -> str:
    return f"{base}.account_id" if finding.get("account_id") else f"{base}.provider"


def _resource_path(base: str, finding: dict[str, Any]) -> str:
    return f"{base}.resource_identifier" if finding.get("resource_identifier") else f"{base}.resource_name"


def _target_identity(value: object) -> CanonicalIdentity | None:
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
            pass
        text = parsed.hostname
    try:
        return canonical_ip(text.strip("[]"))
    except ValueError:
        try:
            return canonical_hostname(text)
        except ValueError:
            return None


def _network_value(identity: CanonicalIdentity) -> str:
    if identity.entity_type == "endpoint":
        origin = identity.payload.get("origin") if isinstance(identity.payload.get("origin"), dict) else {}
        host_key = origin.get("host_key")
        if isinstance(host_key, str):
            try:
                import json
                payload = json.loads(host_key).get("payload") or {}
                return str(payload.get("address") or payload.get("hostname") or "")
            except (TypeError, ValueError):
                return ""
    return str(identity.payload.get("address") or identity.payload.get("hostname") or "")


def _safe_label(value: object) -> str | None:
    text = " ".join(str(value or "").split())
    return text if _SAFE_LABEL_RE.fullmatch(text) and not _looks_sensitive(text) else None


def _safe_module(value: object) -> str | None:
    text = str(value or "").strip()
    return text if _SAFE_MODULE_RE.fullmatch(text) and not _looks_sensitive(text) else None


def _positive_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if 1 <= parsed <= 65535 else None


def _hash_id(value: object) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _looks_sensitive(value: object) -> bool:
    text = str(value or "")
    lowered = text.lower()
    return any(term in lowered for term in _SENSITIVE_TERMS) or any(pattern.search(text) for pattern in _SECRET_VALUE_PATTERNS)
