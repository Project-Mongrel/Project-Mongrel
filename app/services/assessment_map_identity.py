"""Deterministic, non-LLM identities for assessment relationship mapping."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote_plus, urlsplit

IDENTITY_SCHEMA_VERSION = "assessment-map.identity.v1"
ENTITY_TYPES = frozenset({
    "hostname", "ip", "service", "application", "endpoint", "technology", "finding",
    "cloud_account", "cloud_region", "cloud_resource",
})
_TRANSPORT_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,15}")


@dataclass(frozen=True, slots=True)
class CanonicalIdentity:
    entity_type: str
    version: str
    canonical_key: str
    identity_hash: str
    payload: dict[str, Any]


def identity_from_payload(entity_type: str, payload: dict[str, Any]) -> CanonicalIdentity:
    """Hash versioned sorted JSON while preserving null and zero distinctly."""

    normalized_type = str(entity_type or "").strip().lower()
    if normalized_type not in ENTITY_TYPES:
        raise ValueError("Unsupported assessment-map entity type.")
    if not isinstance(payload, dict):
        raise ValueError("Canonical identity payload must be a mapping.")
    envelope = {"payload": payload, "type": normalized_type, "version": IDENTITY_SCHEMA_VERSION}
    canonical_key = json.dumps(envelope, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return CanonicalIdentity(
        entity_type=normalized_type,
        version=IDENTITY_SCHEMA_VERSION,
        canonical_key=canonical_key,
        identity_hash=hashlib.sha256(canonical_key.encode("utf-8")).hexdigest(),
        payload=dict(payload),
    )


def canonical_hostname(value: str) -> CanonicalIdentity:
    return identity_from_payload("hostname", {"hostname": _normalize_hostname(value)})


def canonical_ip(value: str) -> CanonicalIdentity:
    try:
        normalized = ipaddress.ip_address(str(value or "").strip()).compressed
    except ValueError as exc:
        raise ValueError("Invalid IP address.") from exc
    return identity_from_payload("ip", {"address": normalized})


def canonical_service(host: str, transport: str, port: int) -> CanonicalIdentity:
    host_identity = _canonical_network_host(host)
    normalized_transport = str(transport or "").strip().lower()
    if not _TRANSPORT_PATTERN.fullmatch(normalized_transport):
        raise ValueError("Invalid service transport.")
    normalized_port = _validated_port(port)
    return identity_from_payload(
        "service",
        {
            "host_hash": host_identity.identity_hash,
            "host_key": host_identity.canonical_key,
            "port": normalized_port,
            "transport": normalized_transport,
        },
    )


def canonical_application_origin(value: str) -> CanonicalIdentity:
    origin = _normalize_origin(value)
    return identity_from_payload("application", origin)


def canonical_endpoint(value: str) -> CanonicalIdentity:
    parsed = _split_web_url(value)
    origin = _normalize_origin_parts(parsed)
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    parameter_names = sorted(set(_query_parameter_names(parsed.query)))
    return identity_from_payload(
        "endpoint",
        {
            "origin": origin,
            "path": path,
            "query_parameter_names": parameter_names,
        },
    )


def canonical_technology(name: str, *, version: str | None = None) -> CanonicalIdentity:
    del version  # Versions are evidence attributes, never part of product identity.
    normalized = " ".join(str(name or "").split()).casefold()
    if not normalized:
        raise ValueError("Technology name is required.")
    return identity_from_payload("technology", {"product": normalized})


def canonical_cloud_account(provider: str, account_id: str) -> CanonicalIdentity:
    normalized_provider = _normalize_cloud_component(provider, field="provider")
    normalized_account = _normalize_cloud_component(account_id, field="account")
    return identity_from_payload(
        "cloud_account",
        {"provider": normalized_provider, "account_id": normalized_account},
    )


def canonical_cloud_region(provider: str, account_id: str, region: str) -> CanonicalIdentity:
    account = canonical_cloud_account(provider, account_id)
    normalized_region = _normalize_cloud_component(region, field="region")
    return identity_from_payload(
        "cloud_region",
        {
            "provider": account.payload["provider"],
            "account_hash": account.identity_hash,
            "account_key": account.canonical_key,
            "region": normalized_region,
        },
    )


def canonical_cloud_resource(
    provider: str,
    account_id: str,
    *,
    region: str | None = None,
    service: str | None = None,
    resource_id: str | None = None,
    resource_name: str | None = None,
) -> CanonicalIdentity:
    account = canonical_cloud_account(provider, account_id)
    normalized_resource_id = _normalize_cloud_component(resource_id, field="resource_id", required=False)
    normalized_resource_name = _normalize_cloud_component(resource_name, field="resource_name", required=False)
    if normalized_resource_id is None and normalized_resource_name is None:
        raise ValueError("Cloud resource requires a resource identifier or name.")
    payload: dict[str, Any] = {
        "provider": account.payload["provider"],
        "account_hash": account.identity_hash,
        "account_key": account.canonical_key,
        "resource_id": normalized_resource_id,
        "resource_name": normalized_resource_name,
    }
    normalized_region = _normalize_cloud_component(region, field="region", required=False)
    normalized_service = _normalize_cloud_component(service, field="service", required=False)
    if normalized_region is not None:
        payload["region"] = normalized_region
    if normalized_service is not None:
        payload["service"] = normalized_service
    return identity_from_payload("cloud_resource", payload)


def canonical_finding(
    tool: str,
    stable_id: str,
    affected_surface: CanonicalIdentity,
    *,
    matcher: str | None = None,
) -> CanonicalIdentity:
    normalized_tool = str(tool or "").strip().lower().removesuffix(".sh")
    normalized_id = str(stable_id or "").strip()
    if not normalized_tool or not normalized_id:
        raise ValueError("Finding tool and stable identifier are required.")
    if affected_surface.entity_type not in ENTITY_TYPES - {"finding"}:
        raise ValueError("Finding affected surface must be a canonical non-finding entity.")
    payload: dict[str, Any] = {
        "affected_surface_hash": affected_surface.identity_hash,
        "affected_surface_type": affected_surface.entity_type,
        "stable_id": normalized_id,
        "tool": normalized_tool,
    }
    normalized_matcher = str(matcher or "").strip()
    if normalized_matcher:
        payload["matcher"] = normalized_matcher
    return identity_from_payload("finding", payload)


def _normalize_cloud_component(value: object, *, field: str, required: bool = True) -> str | None:
    normalized = " ".join(str(value or "").replace("\x00", "").split())
    if not normalized:
        if required:
            raise ValueError(f"Cloud {field} is required.")
        return None
    if len(normalized) > 300:
        raise ValueError(f"Cloud {field} is too long.")
    lowered = normalized.lower()
    if any(marker in lowered for marker in (
        "authorization", "bearer ", "cookie", "password", "secret", "token", "api_key", "apikey",
        "private_key", "credential",
    )):
        raise ValueError(f"Cloud {field} appears sensitive.")
    return normalized.casefold() if field in {"provider", "region", "service"} else normalized


def _normalize_hostname(value: str) -> str:
    normalized = str(value or "").strip()
    if normalized.endswith("."):
        normalized = normalized[:-1]
    if not normalized or normalized.endswith("."):
        raise ValueError("Invalid hostname.")
    try:
        ascii_name = normalized.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid hostname.") from exc
    if len(ascii_name) > 253:
        raise ValueError("Invalid hostname.")
    labels = ascii_name.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or re.fullmatch(r"[a-z0-9-]+", label) is None
        for label in labels
    ):
        raise ValueError("Invalid hostname.")
    return ascii_name


def _canonical_network_host(value: str) -> CanonicalIdentity:
    cleaned = str(value or "").strip()
    try:
        return canonical_ip(cleaned)
    except ValueError:
        return canonical_hostname(cleaned)


def _validated_port(value: int) -> int:
    if isinstance(value, bool):
        raise ValueError("Invalid service port.")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid service port.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("Invalid service port.")
    return port


def _split_web_url(value: str):
    cleaned = str(value or "").strip()
    if not cleaned:
        raise ValueError("Web URL is required.")
    parsed = urlsplit(cleaned)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Web URL must use http or https and include a host.")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("Web URL has an invalid port.") from exc
    return parsed


def _normalize_origin(value: str) -> dict[str, Any]:
    return _normalize_origin_parts(_split_web_url(value))


def _normalize_origin_parts(parsed: object) -> dict[str, Any]:
    scheme = str(parsed.scheme).lower()
    host_identity = _canonical_network_host(str(parsed.hostname))
    port = parsed.port
    if port is not None:
        port = _validated_port(port)
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    origin: dict[str, Any] = {
        "host_hash": host_identity.identity_hash,
        "host_key": host_identity.canonical_key,
        "scheme": scheme,
    }
    if port is not None:
        origin["port"] = port
    return origin


def _query_parameter_names(query: str) -> list[str]:
    names: list[str] = []
    for field in str(query or "").split("&"):
        if not field:
            continue
        raw_name = field.split("=", 1)[0]
        name = unquote_plus(raw_name)
        if name:
            names.append(name)
    return names
