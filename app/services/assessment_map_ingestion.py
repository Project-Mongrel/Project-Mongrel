"""Explicit, owner-scoped ingestion of one stored assessment scan into the map."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Any

from app.services.assessment_map_identity import (
    CanonicalIdentity,
    canonical_application_origin,
    canonical_endpoint,
    canonical_hostname,
    canonical_ip,
    canonical_service,
    canonical_technology,
)
from app.services.assessment_map_store import (
    AssessmentMapIdentityCollisionError,
    AssessmentMapScopeError,
    initialize_assessment_map_schema,
)
from app.services.findings_store import _get_connection
from app.services.sqlite_runtime import run_locked_transaction

INGESTION_VERSION = 1
DIGEST_VERSION = "assessment-map.ingestion-source.v1"
SUPPORTED_TOOLS = frozenset({"nmap", "httpx"})
STRUCTURED_ARTIFACT_TYPES = {
    "nmap": frozenset({"nmap_normalized_evidence", "nmap_structured_evidence", "nmap_json"}),
    "httpx": frozenset({"httpx_normalized_evidence", "httpx_structured_evidence", "httpx_json"}),
}
_SAFE_RESPONSE_HEADER_NAMES = frozenset(
    {
        "content-length",
        "content-type",
        "server",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
    }
)
_MISSING = object()


class AssessmentMapIngestionError(RuntimeError):
    """Sanitized ingestion failure that contains no stored evidence."""


@dataclass(frozen=True, slots=True)
class _Source:
    data: dict[str, Any]
    root_path: str
    finding_id: str | None = None
    artifact_id: int | None = None


@dataclass(slots=True)
class _Counts:
    entities: set[int]
    assertions: set[int]
    evidence: set[int]

    @classmethod
    def empty(cls) -> "_Counts":
        return cls(set(), set(), set())


def ingest_assessment_scan(*, user_id: int, assessment_id: int, scan_id: int) -> dict:
    """Ingest one scan; ledger counts are unique canonical rows referenced by its projection."""

    initialize_assessment_map_schema()
    connection = _get_connection()

    def operation(active: sqlite3.Connection) -> dict:
        active.execute("BEGIN IMMEDIATE")
        scan = _require_owned_scan(active, user_id, assessment_id, scan_id)
        tool = str(scan["tool"] or "").strip().lower().removesuffix(".sh")
        sources, source_error = _load_structured_sources(active, user_id, assessment_id, scan, tool)
        material = _canonical_digest_projection(scan, tool, sources, source_error)
        digest = _digest(material)
        existing = _ledger(active, user_id, assessment_id, scan_id, digest)
        head = _projection_head(active, user_id, assessment_id, scan_id)
        if (
            existing is not None
            and existing["status"] == "complete"
            and head is not None
            and head["source_digest"] == digest
        ):
            return _row(existing)
        if existing is not None and existing["status"] in {"skipped", "failed"}:
            return _row(existing)

        if tool not in SUPPORTED_TOOLS:
            return _write_ledger(active, user_id, assessment_id, scan_id, digest, "skipped", error_code="unsupported_tool")
        if source_error is not None:
            return _write_ledger(active, user_id, assessment_id, scan_id, digest, source_error[0], error_code=source_error[1])
        if not sources:
            return _write_ledger(active, user_id, assessment_id, scan_id, digest, "skipped", error_code="missing_structured_evidence")

        active.execute("SAVEPOINT assessment_map_scan_ingestion")
        try:
            counts = _Counts.empty()
            for source in sources:
                if tool == "nmap":
                    _ingest_nmap_source(active, user_id, assessment_id, scan, source, counts)
                else:
                    _ingest_httpx_source(active, user_id, assessment_id, scan, source, counts)
            if not counts.entities and not counts.assertions:
                raise AssessmentMapIngestionError("No supported structured observations were available.")
        except (AssessmentMapIngestionError, ValueError, TypeError, AssessmentMapIdentityCollisionError):
            active.execute("ROLLBACK TO SAVEPOINT assessment_map_scan_ingestion")
            active.execute("RELEASE SAVEPOINT assessment_map_scan_ingestion")
            return _write_ledger(active, user_id, assessment_id, scan_id, digest, "failed", error_code="malformed_structured_evidence")
        except sqlite3.OperationalError:
            raise
        except Exception:
            raise
        active.execute("RELEASE SAVEPOINT assessment_map_scan_ingestion")

        ledger = _write_ledger(
            active,
            user_id,
            assessment_id,
            scan_id,
            digest,
            "complete",
            entity_count=len(counts.entities),
            assertion_count=len(counts.assertions),
            evidence_count=len(counts.evidence),
        )
        _replace_projection(
            active,
            user_id=user_id,
            assessment_id=assessment_id,
            scan_id=scan_id,
            digest=digest,
            evidence_ids=counts.evidence,
            previous_digest=head["source_digest"] if head is not None else None,
        )
        return ledger

    return run_locked_transaction(connection, operation)


def _require_owned_scan(
    connection: sqlite3.Connection, user_id: int, assessment_id: int, scan_id: int
) -> sqlite3.Row:
    assessment = connection.execute(
        "SELECT user_id FROM assessments WHERE id = ?", (int(assessment_id),)
    ).fetchone()
    if assessment is None or assessment["user_id"] is None or int(assessment["user_id"]) != int(user_id):
        raise AssessmentMapScopeError("Assessment scan is outside the owned assessment scope.")
    scan = connection.execute(
        "SELECT * FROM assessment_scans WHERE id = ? AND assessment_id = ?",
        (int(scan_id), int(assessment_id)),
    ).fetchone()
    if scan is None:
        raise AssessmentMapScopeError("Assessment scan is outside the owned assessment scope.")
    return scan


def _load_structured_sources(
    connection: sqlite3.Connection,
    user_id: int,
    assessment_id: int,
    scan: sqlite3.Row,
    tool: str,
) -> tuple[list[_Source], tuple[str, str] | None]:
    sources: list[_Source] = []
    source_error: tuple[str, str] | None = None
    finding_id = str(scan["finding_id"]) if scan["finding_id"] is not None else None
    if finding_id is not None:
        finding = connection.execute(
            "SELECT data_json FROM findings WHERE id = ? AND user_id = ?",
            (finding_id, int(user_id)),
        ).fetchone()
        if finding is None:
            source_error = ("skipped", "orphaned_finding_reference")
        else:
            try:
                data = json.loads(finding["data_json"])
            except (TypeError, json.JSONDecodeError):
                source_error = ("failed", "malformed_linked_finding")
            else:
                if isinstance(data, dict):
                    sources.append(_Source(data=data, root_path="finding", finding_id=finding_id))
                else:
                    source_error = ("failed", "malformed_linked_finding")

    artifacts = connection.execute(
        """SELECT id, artifact_type, content FROM assessment_artifacts
           WHERE assessment_id = ? AND scan_id = ? ORDER BY id""",
        (int(assessment_id), int(scan["id"])),
    ).fetchall()
    for artifact in artifacts:
        artifact_type = str(artifact["artifact_type"] or "").strip().lower()
        if artifact_type not in STRUCTURED_ARTIFACT_TYPES.get(tool, frozenset()):
            continue
        try:
            data = json.loads(artifact["content"] or "")
        except (TypeError, json.JSONDecodeError):
            source_error = source_error or ("failed", "malformed_structured_artifact")
            continue
        if isinstance(data, dict):
            sources.append(
                _Source(data=data, root_path=f"artifacts[{artifact['id']}]", artifact_id=int(artifact["id"]))
            )
        else:
            source_error = source_error or ("failed", "malformed_structured_artifact")
    return sources, source_error


def _canonical_digest_projection(
    scan: sqlite3.Row,
    tool: str,
    sources: list[_Source],
    source_error: tuple[str, str] | None,
) -> dict[str, Any]:
    projected_sources = []
    for source in sources:
        projection = _project_nmap_source(source.data) if tool == "nmap" else _project_httpx_source(source.data)
        projected_sources.append(
            {
                "finding_id": source.finding_id,
                "artifact_id": source.artifact_id,
                "root_path": source.root_path,
                "data": projection,
            }
        )
    return {
        "digest_version": DIGEST_VERSION,
        "ingestion_version": INGESTION_VERSION,
        "scan_id": scan["id"],
        "tool": tool,
        "source_error": list(source_error) if source_error is not None else None,
        "sources": projected_sources,
    }


def _project_nmap_source(data: dict[str, Any]) -> dict[str, Any]:
    ports = data.get("open_ports")
    if not isinstance(ports, list):
        ports = {"malformed_type": type(ports).__name__}
    else:
        ports = [
            {
                key: item.get(key)
                for key in ("ip", "host", "port", "protocol", "state", "service", "product", "version")
                if isinstance(item, dict) and key in item
            }
            if isinstance(item, dict)
            else {"malformed_type": type(item).__name__}
            for item in ports
        ]
    return {
        "source": data.get("source"),
        "target": data.get("target"),
        "host_status": data.get("host_status"),
        "open_ports": ports,
    }


def _project_httpx_source(data: dict[str, Any]) -> dict[str, Any]:
    observations = data.get("httpx_services")
    if not isinstance(observations, list):
        return {"source": data.get("source"), "httpx_services": {"malformed_type": type(observations).__name__}}
    projected = []
    for item in observations:
        if not isinstance(item, dict):
            projected.append({"malformed_type": type(item).__name__})
            continue
        if not _is_response_backed(item):
            continue
        projected.append(
            {
                "url": item.get("url"),
                "status_code": item.get("status_code"),
                "response_observed": item.get("response_observed"),
                "title": item.get("title"),
                "web_server": item.get("web_server"),
                "content_length": item.get("content_length"),
                "content_type": item.get("content_type"),
                "response_time": item.get("response_time"),
                "headers": _safe_headers(item.get("headers") or item.get("response_headers")),
                "ip": item.get("ip"),
                "cname": item.get("cname"),
                "technologies": item.get("technologies"),
                "redirect_location": item.get("redirect_location"),
                "final_url": item.get("final_url"),
            }
        )
    return {"source": data.get("source"), "httpx_services": projected}


def _ingest_nmap_source(
    connection: sqlite3.Connection,
    user_id: int,
    assessment_id: int,
    scan: sqlite3.Row,
    source: _Source,
    counts: _Counts,
) -> None:
    data = source.data
    source_tool = str(data.get("source") or "").strip().lower()
    if source_tool and source_tool not in {"nmap", "nmap_xml"}:
        raise AssessmentMapIngestionError("Linked finding does not match the Nmap scan.")
    ports = data.get("open_ports")
    if ports is None:
        ports = []
    if not isinstance(ports, list):
        raise AssessmentMapIngestionError("Malformed Nmap port observations.")
    default_host, default_identities = _network_identities(data.get("target"))
    planned: list[tuple[int, dict[str, Any], CanonicalIdentity, CanonicalIdentity]] = []
    for index, item in enumerate(ports):
        if not isinstance(item, dict):
            raise AssessmentMapIngestionError("Malformed Nmap service observation.")
        item_host, _ = _network_identities(item.get("ip") or item.get("host"))
        host_identity = item_host or default_host
        if host_identity is None:
            raise AssessmentMapIngestionError("Nmap service observation has no explicit host.")
        port = _valid_port(item.get("port"))
        protocol = str(item.get("protocol") or "").strip().lower()
        service_identity = canonical_service(_network_value(host_identity), protocol, port)
        planned.append((index, item, host_identity, service_identity))
    if default_host is None and not planned:
        raise AssessmentMapIngestionError("Nmap evidence has no canonical target.")

    if default_host is not None:
        target_rows = []
        for identity in default_identities:
            target_row = _entity(connection, user_id, assessment_id, identity)
            target_rows.append(target_row)
            counts.entities.add(target_row["id"])
            _evidence(
                connection, user_id, assessment_id, scan, source, target_row,
                "entity", "target", f"{source.root_path}.target", counts,
            )
        host = next(row for row in target_rows if row["identity_hash"] == default_host.identity_hash)
        hostname_row = next((row for row in target_rows if row["entity_type"] == "hostname"), None)
        ip_row = next((row for row in target_rows if row["entity_type"] == "ip"), None)
        if hostname_row is not None and ip_row is not None:
            address_relation = _assertion(
                connection, user_id, assessment_id, hostname_row["id"],
                "observed_address", object_entity_id=ip_row["id"],
            )
            counts.assertions.add(address_relation["id"])
            _evidence(
                connection, user_id, assessment_id, scan, source, address_relation,
                "assertion", "nmap_target_address", f"{source.root_path}.target", counts,
            )
        if data.get("host_status") not in (None, ""):
            assertion = _assertion(
                connection, user_id, assessment_id, host["id"], "has_host_state", value=str(data["host_status"])
            )
            counts.assertions.add(assertion["id"])
            _evidence(connection, user_id, assessment_id, scan, source, assertion, "assertion", "host_state", f"{source.root_path}.host_status", counts)

    for index, item, host_identity, service_identity in planned:
        path = f"{source.root_path}.open_ports[{index}]"
        host = _entity(connection, user_id, assessment_id, host_identity)
        service = _entity(connection, user_id, assessment_id, service_identity)
        counts.entities.update((host["id"], service["id"]))
        host_field = "ip" if item.get("ip") not in (None, "") else "host" if item.get("host") not in (None, "") else None
        host_path = f"{path}.{host_field}" if host_field is not None else f"{source.root_path}.target"
        _evidence(connection, user_id, assessment_id, scan, source, host, "entity", "service_host", host_path, counts)
        _evidence(connection, user_id, assessment_id, scan, source, service, "entity", "service_port", f"{path}.port", counts)
        _evidence(connection, user_id, assessment_id, scan, source, service, "entity", "service_transport", f"{path}.protocol", counts)
        exposes = _assertion(
            connection, user_id, assessment_id, host["id"], "exposes_service", object_entity_id=service["id"]
        )
        counts.assertions.add(exposes["id"])
        _evidence(connection, user_id, assessment_id, scan, source, exposes, "assertion", "open_service", path, counts)
        attributes = {
            "has_service_state": (item.get("state", "open"), "state" if item.get("state") not in (None, "") else None),
            "has_service_name": (item.get("service"), "service"),
            "has_product": (item.get("product"), "product"),
            "has_version": (item.get("version"), "version"),
        }
        for predicate, (value, field_name) in attributes.items():
            if value in (None, ""):
                continue
            assertion = _assertion(connection, user_id, assessment_id, service["id"], predicate, value=value)
            counts.assertions.add(assertion["id"])
            evidence_path = f"{path}.{field_name}" if field_name is not None else path
            _evidence(
                connection, user_id, assessment_id, scan, source, assertion,
                "assertion", predicate, evidence_path, counts,
            )


def _ingest_httpx_source(
    connection: sqlite3.Connection,
    user_id: int,
    assessment_id: int,
    scan: sqlite3.Row,
    source: _Source,
    counts: _Counts,
) -> None:
    source_tool = str(source.data.get("source") or "").strip().lower()
    if source_tool and source_tool != "httpx":
        raise AssessmentMapIngestionError("Linked finding does not match the httpx scan.")
    observations = source.data.get("httpx_services")
    if not isinstance(observations, list):
        raise AssessmentMapIngestionError("Missing normalized httpx observations.")
    response_observations: list[tuple[int, dict[str, Any], CanonicalIdentity, CanonicalIdentity]] = []
    for index, item in enumerate(observations):
        if not isinstance(item, dict):
            raise AssessmentMapIngestionError("Malformed httpx observation.")
        if not _is_response_backed(item):
            continue
        url = item.get("url")
        endpoint_identity = canonical_endpoint(str(url or ""))
        application_identity = canonical_application_origin(str(url or ""))
        response_observations.append((index, item, application_identity, endpoint_identity))
    if not response_observations:
        raise AssessmentMapIngestionError("No response-backed httpx observations.")

    observed_endpoints = {item[3].identity_hash: item[3] for item in response_observations}
    for index, item, application_identity, endpoint_identity in response_observations:
        path = f"{source.root_path}.httpx_services[{index}]"
        application = _entity(connection, user_id, assessment_id, application_identity)
        endpoint = _entity(connection, user_id, assessment_id, endpoint_identity)
        counts.entities.update((application["id"], endpoint["id"]))
        url_path = f"{path}.url"
        _evidence(connection, user_id, assessment_id, scan, source, application, "entity", "http_response", url_path, counts)
        _evidence(connection, user_id, assessment_id, scan, source, endpoint, "entity", "http_response", url_path, counts)
        exposed = _assertion(
            connection, user_id, assessment_id, application["id"], "exposes_endpoint", object_entity_id=endpoint["id"]
        )
        counts.assertions.add(exposed["id"])
        _evidence(connection, user_id, assessment_id, scan, source, exposed, "assertion", "http_response", url_path, counts)

        values = {
            "has_response_status": (item.get("status_code"), "status_code"),
            "has_title": (item.get("title"), "title"),
            "has_web_server": (item.get("web_server"), "web_server"),
            "has_content_length": (item.get("content_length"), "content_length"),
            "has_content_type": (item.get("content_type"), "content_type"),
            "has_response_time": (item.get("response_time"), "response_time"),
        }
        headers = _safe_headers(item.get("headers") or item.get("response_headers"))
        if headers:
            header_field = "headers" if isinstance(item.get("headers"), dict) else "response_headers"
            values["has_response_headers"] = (headers, header_field)
        for predicate, (value, field_name) in values.items():
            if value in (None, "", {}):
                continue
            assertion = _assertion(connection, user_id, assessment_id, endpoint["id"], predicate, value=value)
            counts.assertions.add(assertion["id"])
            _evidence(
                connection, user_id, assessment_id, scan, source, assertion,
                "assertion", predicate, f"{path}.{field_name}", counts,
            )

        if item.get("ip") not in (None, ""):
            ip_identity = canonical_ip(str(item["ip"]))
            ip_entity = _entity(connection, user_id, assessment_id, ip_identity)
            counts.entities.add(ip_entity["id"])
            observed_ip = _assertion(
                connection, user_id, assessment_id, application["id"], "observed_ip", object_entity_id=ip_entity["id"]
            )
            counts.assertions.add(observed_ip["id"])
            ip_path = f"{path}.ip"
            _evidence(connection, user_id, assessment_id, scan, source, ip_entity, "entity", "httpx_ip", ip_path, counts)
            _evidence(connection, user_id, assessment_id, scan, source, observed_ip, "assertion", "httpx_ip", ip_path, counts)

        if item.get("cname") is not None and not isinstance(item.get("cname"), list):
            raise AssessmentMapIngestionError("Malformed httpx CNAME observations.")
        for cname_index, cname in enumerate(_string_list(item.get("cname"))):
            cname_identity = canonical_hostname(cname)
            cname_entity = _entity(connection, user_id, assessment_id, cname_identity)
            counts.entities.add(cname_entity["id"])
            relation = _assertion(
                connection, user_id, assessment_id, application["id"], "observed_cname", object_entity_id=cname_entity["id"]
            )
            counts.assertions.add(relation["id"])
            cname_path = f"{path}.cname[{cname_index}]"
            _evidence(connection, user_id, assessment_id, scan, source, cname_entity, "entity", "httpx_cname", cname_path, counts)
            _evidence(connection, user_id, assessment_id, scan, source, relation, "assertion", "httpx_cname", cname_path, counts)

        technologies = item.get("technologies") or []
        if not isinstance(technologies, list):
            raise AssessmentMapIngestionError("Malformed httpx technology observations.")
        for technology_index, technology in enumerate(technologies):
            if isinstance(technology, dict):
                name = str(technology.get("name") or "").strip()
                version = technology.get("version")
            else:
                name, version = str(technology or "").strip(), None
            technology_identity = canonical_technology(name, version=str(version) if version is not None else None)
            technology_entity = _entity(connection, user_id, assessment_id, technology_identity)
            counts.entities.add(technology_entity["id"])
            relation = _assertion(
                connection, user_id, assessment_id, application["id"], "uses_technology", object_entity_id=technology_entity["id"]
            )
            counts.assertions.add(relation["id"])
            technology_path = f"{path}.technologies[{technology_index}]"
            _evidence(connection, user_id, assessment_id, scan, source, technology_entity, "entity", "httpx_technology", technology_path, counts)
            _evidence(connection, user_id, assessment_id, scan, source, relation, "assertion", "httpx_technology", technology_path, counts)
            if version not in (None, ""):
                version_assertion = _assertion(
                    connection, user_id, assessment_id, technology_entity["id"], "has_observed_version", value=version
                )
                counts.assertions.add(version_assertion["id"])
                _evidence(
                    connection, user_id, assessment_id, scan, source, version_assertion,
                    "assertion", "httpx_technology_version", f"{technology_path}.version", counts,
                )

        redirect = item.get("redirect_location") or item.get("final_url")
        if redirect not in (None, ""):
            redirect_identity = canonical_endpoint(str(redirect))
            redirect_entity = observed_endpoints.get(redirect_identity.identity_hash)
            if redirect_entity is not None:
                destination = _entity(connection, user_id, assessment_id, redirect_entity)
                relation = _assertion(
                    connection, user_id, assessment_id, endpoint["id"], "redirects_to", object_entity_id=destination["id"]
                )
            else:
                relation = _assertion(
                    connection,
                    user_id,
                    assessment_id,
                    endpoint["id"],
                    "redirects_to_reference",
                    value=redirect_identity.payload,
                )
            counts.assertions.add(relation["id"])
            redirect_field = "redirect_location" if item.get("redirect_location") not in (None, "") else "final_url"
            _evidence(
                connection, user_id, assessment_id, scan, source, relation,
                "assertion", "http_redirect", f"{path}.{redirect_field}", counts,
            )


def _network_identities(value: object) -> tuple[CanonicalIdentity | None, list[CanonicalIdentity]]:
    cleaned = str(value or "").strip()
    if not cleaned:
        return None, []
    combined = re.fullmatch(r"(.+?)\s+\(([^()]+)\)", cleaned)
    if combined is not None:
        try:
            hostname = canonical_hostname(combined.group(1).strip())
            address = canonical_ip(combined.group(2).strip())
        except ValueError:
            return None, []
        return address, [hostname, address]
    try:
        ipaddress.ip_address(cleaned)
    except ValueError:
        try:
            hostname = canonical_hostname(cleaned)
        except ValueError:
            return None, []
        return hostname, [hostname]
    address = canonical_ip(cleaned)
    return address, [address]


def _network_value(identity: CanonicalIdentity) -> str:
    return str(identity.payload.get("address") or identity.payload.get("hostname") or "")


def _valid_port(value: object) -> int:
    if isinstance(value, bool):
        raise AssessmentMapIngestionError("Invalid Nmap port observation.")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise AssessmentMapIngestionError("Invalid Nmap port observation.") from exc
    if not 1 <= port <= 65535:
        raise AssessmentMapIngestionError("Invalid Nmap port observation.")
    return port


def _is_response_backed(item: dict[str, Any]) -> bool:
    status = item.get("status_code")
    return (
        isinstance(status, int)
        and not isinstance(status, bool)
        and 100 <= status <= 599
    ) or item.get("response_observed") is True


def _safe_headers(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key).strip().lower(): item
        for key, item in value.items()
        if str(key).strip().lower() in _SAFE_RESPONSE_HEADER_NAMES
        and isinstance(item, (str, int, float, bool))
    }


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item or "").strip()]


def _entity(
    connection: sqlite3.Connection,
    user_id: int,
    assessment_id: int,
    identity: CanonicalIdentity,
) -> sqlite3.Row:
    row = connection.execute(
        """SELECT * FROM assessment_map_entities WHERE assessment_id = ? AND user_id = ?
           AND entity_type = ? AND identity_hash = ?""",
        (assessment_id, user_id, identity.entity_type, identity.identity_hash),
    ).fetchone()
    if row is not None:
        if row["canonical_key"] != identity.canonical_key or row["identity_version"] != identity.version:
            raise AssessmentMapIdentityCollisionError("Assessment-map entity hash collision detected.")
        return row
    now = _now()
    connection.execute(
        """INSERT INTO assessment_map_entities (
               assessment_id, user_id, entity_type, identity_version, identity_hash,
               canonical_key, attributes_json, first_seen_at, last_seen_at, created_at, updated_at
           ) VALUES (?, ?, ?, ?, ?, ?, '{}', ?, ?, ?, ?)""",
        (
            assessment_id, user_id, identity.entity_type, identity.version, identity.identity_hash,
            identity.canonical_key, now, now, now, now,
        ),
    )
    return connection.execute(
        """SELECT * FROM assessment_map_entities WHERE assessment_id = ? AND user_id = ?
           AND entity_type = ? AND identity_hash = ?""",
        (assessment_id, user_id, identity.entity_type, identity.identity_hash),
    ).fetchone()


def _assertion(
    connection: sqlite3.Connection,
    user_id: int,
    assessment_id: int,
    subject_entity_id: int,
    predicate: str,
    *,
    object_entity_id: int | None = None,
    value: Any = _MISSING,
) -> sqlite3.Row:
    subject = connection.execute(
        "SELECT identity_hash FROM assessment_map_entities WHERE id = ? AND assessment_id = ? AND user_id = ?",
        (subject_entity_id, assessment_id, user_id),
    ).fetchone()
    object_entity = connection.execute(
        "SELECT identity_hash FROM assessment_map_entities WHERE id = ? AND assessment_id = ? AND user_id = ?",
        (object_entity_id, assessment_id, user_id),
    ).fetchone() if object_entity_id is not None else None
    if subject is None or (object_entity_id is not None and object_entity is None):
        raise AssessmentMapScopeError("Assessment-map assertion entity is outside the owned scope.")
    canonical = {
        "object_hash": object_entity["identity_hash"] if object_entity is not None else None,
        "polarity": "observed",
        "predicate": predicate,
        "subject_hash": subject["identity_hash"],
        "value": None if value is _MISSING else value,
        "value_present": value is not _MISSING,
        "version": "assessment-map.assertion.v1",
    }
    key = _json(canonical)
    assertion_hash = hashlib.sha256(key.encode()).hexdigest()
    row = connection.execute(
        "SELECT * FROM assessment_map_assertions WHERE assessment_id = ? AND user_id = ? AND assertion_hash = ?",
        (assessment_id, user_id, assertion_hash),
    ).fetchone()
    if row is not None:
        if row["canonical_key"] != key:
            raise AssessmentMapIdentityCollisionError("Assessment-map assertion hash collision detected.")
        return row
    now = _now()
    connection.execute(
        """INSERT INTO assessment_map_assertions (
               assessment_id, user_id, subject_entity_id, predicate, object_entity_id,
               normalized_value_json, polarity, assertion_hash, canonical_key, attributes_json,
               first_seen_at, last_seen_at, created_at, updated_at
           ) VALUES (?, ?, ?, ?, ?, ?, 'observed', ?, ?, '{}', ?, ?, ?, ?)""",
        (
            assessment_id, user_id, subject_entity_id, predicate, object_entity_id,
            None if value is _MISSING else _json(value), assertion_hash, key, now, now, now, now,
        ),
    )
    return connection.execute(
        "SELECT * FROM assessment_map_assertions WHERE assessment_id = ? AND user_id = ? AND assertion_hash = ?",
        (assessment_id, user_id, assertion_hash),
    ).fetchone()


def _evidence(
    connection: sqlite3.Connection,
    user_id: int,
    assessment_id: int,
    scan: sqlite3.Row,
    source: _Source,
    destination: sqlite3.Row,
    destination_type: str,
    evidence_kind: str,
    path: str,
    counts: _Counts,
) -> None:
    destination_id = int(destination["id"])
    fingerprint = _digest(
        {
            "scan_id": scan["id"], "finding_id": source.finding_id, "artifact_id": source.artifact_id,
            "path": path, "destination_type": destination_type, "evidence_kind": evidence_kind,
            "destination_identity": destination["identity_hash"] if destination_type == "entity" else destination["assertion_hash"],
        }
    )
    row = connection.execute(
        """SELECT * FROM assessment_map_evidence_links WHERE assessment_id = ? AND user_id = ?
           AND destination_type = ? AND destination_id = ? AND evidence_fingerprint = ?""",
        (assessment_id, user_id, destination_type, destination_id, fingerprint),
    ).fetchone()
    expected = (scan["id"], source.finding_id, source.artifact_id, str(scan["tool"]).lower(), evidence_kind, path)
    if row is not None:
        actual = (
            row["scan_id"], row["finding_id"], row["artifact_id"], row["source_tool"],
            row["evidence_kind"], row["evidence_path"],
        )
        if actual != expected:
            raise AssessmentMapIdentityCollisionError("Assessment-map evidence fingerprint changed provenance.")
        counts.evidence.add(int(row["id"]))
        return
    now = _now()
    connection.execute(
        """INSERT INTO assessment_map_evidence_links (
               assessment_id, user_id, destination_type, destination_id, entity_id, assertion_id,
               scan_id, finding_id, artifact_id, source_tool, evidence_kind, evidence_path,
               evidence_fingerprint, metadata_json, created_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?)""",
        (
            assessment_id, user_id, destination_type, destination_id,
            destination_id if destination_type == "entity" else None,
            destination_id if destination_type == "assertion" else None,
            scan["id"], source.finding_id, source.artifact_id, str(scan["tool"]).lower(),
            evidence_kind, path, fingerprint, now,
        ),
    )
    evidence = connection.execute(
        """SELECT id FROM assessment_map_evidence_links WHERE assessment_id = ? AND user_id = ?
           AND destination_type = ? AND destination_id = ? AND evidence_fingerprint = ?""",
        (assessment_id, user_id, destination_type, destination_id, fingerprint),
    ).fetchone()
    counts.evidence.add(int(evidence["id"]))


def _ledger(
    connection: sqlite3.Connection, user_id: int, assessment_id: int, scan_id: int, digest: str
) -> sqlite3.Row | None:
    return connection.execute(
        """SELECT * FROM assessment_map_ingestions WHERE assessment_id = ? AND user_id = ?
           AND scan_id = ? AND ingestion_version = ? AND source_digest = ?""",
        (assessment_id, user_id, scan_id, INGESTION_VERSION, digest),
    ).fetchone()


def _projection_head(
    connection: sqlite3.Connection, user_id: int, assessment_id: int, scan_id: int
) -> sqlite3.Row | None:
    return connection.execute(
        """SELECT * FROM assessment_map_ingestion_heads
           WHERE assessment_id = ? AND user_id = ? AND scan_id = ? AND ingestion_version = ?""",
        (assessment_id, user_id, scan_id, INGESTION_VERSION),
    ).fetchone()


def _replace_projection(
    connection: sqlite3.Connection,
    *,
    user_id: int,
    assessment_id: int,
    scan_id: int,
    digest: str,
    evidence_ids: set[int],
    previous_digest: str | None,
) -> None:
    for evidence_id in sorted(evidence_ids):
        connection.execute(
            """INSERT OR IGNORE INTO assessment_map_ingestion_evidence (
                   assessment_id, user_id, scan_id, ingestion_version, source_digest, evidence_link_id
               ) VALUES (?, ?, ?, ?, ?, ?)""",
            (assessment_id, user_id, scan_id, INGESTION_VERSION, digest, evidence_id),
        )
    connection.execute(
        """INSERT INTO assessment_map_ingestion_heads (
               assessment_id, user_id, scan_id, ingestion_version, source_digest, updated_at
           ) VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(assessment_id, user_id, scan_id, ingestion_version)
           DO UPDATE SET source_digest = excluded.source_digest, updated_at = excluded.updated_at""",
        (assessment_id, user_id, scan_id, INGESTION_VERSION, digest, _now()),
    )
    if previous_digest is None or previous_digest == digest:
        return

    previous_evidence_rows = connection.execute(
            """SELECT membership.evidence_link_id, evidence.destination_type,
                      evidence.entity_id, evidence.assertion_id
               FROM assessment_map_ingestion_evidence AS membership
               JOIN assessment_map_evidence_links AS evidence
                 ON evidence.id = membership.evidence_link_id
                AND evidence.assessment_id = membership.assessment_id
                AND evidence.user_id = membership.user_id
               WHERE membership.assessment_id = ? AND membership.user_id = ?
                 AND membership.scan_id = ? AND membership.ingestion_version = ?
                 AND membership.source_digest = ?""",
            (assessment_id, user_id, scan_id, INGESTION_VERSION, previous_digest),
        ).fetchall()
    previous_evidence = {int(row["evidence_link_id"]) for row in previous_evidence_rows}
    candidate_assertions = {
        int(row["assertion_id"]) for row in previous_evidence_rows if row["assertion_id"] is not None
    }
    candidate_entities = {
        int(row["entity_id"]) for row in previous_evidence_rows if row["entity_id"] is not None
    }
    connection.execute(
        """DELETE FROM assessment_map_ingestion_evidence
           WHERE assessment_id = ? AND user_id = ? AND scan_id = ?
             AND ingestion_version = ? AND source_digest = ?""",
        (assessment_id, user_id, scan_id, INGESTION_VERSION, previous_digest),
    )
    for evidence_id in sorted(previous_evidence):
        still_owned = connection.execute(
            "SELECT 1 FROM assessment_map_ingestion_evidence WHERE evidence_link_id = ? LIMIT 1",
            (evidence_id,),
        ).fetchone()
        if still_owned is None:
            connection.execute(
                """DELETE FROM assessment_map_evidence_links
                   WHERE id = ? AND assessment_id = ? AND user_id = ?""",
                (evidence_id, assessment_id, user_id),
            )
    _remove_unreferenced_map_rows(
        connection,
        user_id,
        assessment_id,
        assertion_ids=candidate_assertions,
        entity_ids=candidate_entities,
    )


def _remove_unreferenced_map_rows(
    connection: sqlite3.Connection,
    user_id: int,
    assessment_id: int,
    *,
    assertion_ids: set[int],
    entity_ids: set[int],
) -> None:
    for assertion_id in sorted(assertion_ids):
        assertion = connection.execute(
            """SELECT subject_entity_id, object_entity_id FROM assessment_map_assertions
               WHERE id = ? AND assessment_id = ? AND user_id = ?""",
            (assertion_id, assessment_id, user_id),
        ).fetchone()
        if assertion is None:
            continue
        entity_ids.add(int(assertion["subject_entity_id"]))
        if assertion["object_entity_id"] is not None:
            entity_ids.add(int(assertion["object_entity_id"]))
        connection.execute(
            """DELETE FROM assessment_map_assertions
               WHERE id = ? AND assessment_id = ? AND user_id = ?
                 AND NOT EXISTS (
                     SELECT 1 FROM assessment_map_evidence_links AS evidence
                     WHERE evidence.assertion_id = assessment_map_assertions.id
                       AND evidence.assessment_id = assessment_map_assertions.assessment_id
                       AND evidence.user_id = assessment_map_assertions.user_id
                 )""",
            (assertion_id, assessment_id, user_id),
        )
    for entity_id in sorted(entity_ids):
        connection.execute(
            """DELETE FROM assessment_map_entities
           WHERE id = ? AND assessment_id = ? AND user_id = ?
             AND NOT EXISTS (
                 SELECT 1 FROM assessment_map_evidence_links AS evidence
                 WHERE evidence.entity_id = assessment_map_entities.id
                   AND evidence.assessment_id = assessment_map_entities.assessment_id
                   AND evidence.user_id = assessment_map_entities.user_id
             )
             AND NOT EXISTS (
                 SELECT 1 FROM assessment_map_assertions AS assertion
                 WHERE assertion.assessment_id = assessment_map_entities.assessment_id
                   AND assertion.user_id = assessment_map_entities.user_id
                   AND (assertion.subject_entity_id = assessment_map_entities.id
                        OR assertion.object_entity_id = assessment_map_entities.id)
             )
             AND NOT EXISTS (
                 SELECT 1 FROM assessment_validation_attempts AS validation
                 WHERE validation.assessment_id = assessment_map_entities.assessment_id
                   AND validation.user_id = assessment_map_entities.user_id
                   AND (validation.target_entity_id = assessment_map_entities.id
                        OR validation.service_entity_id = assessment_map_entities.id
                        OR validation.finding_entity_id = assessment_map_entities.id)
             )""",
            (entity_id, assessment_id, user_id),
        )


def _write_ledger(
    connection: sqlite3.Connection,
    user_id: int,
    assessment_id: int,
    scan_id: int,
    digest: str,
    status: str,
    *,
    entity_count: int = 0,
    assertion_count: int = 0,
    evidence_count: int = 0,
    error_code: str | None = None,
) -> dict:
    now = _now()
    connection.execute(
        """INSERT INTO assessment_map_ingestions (
               assessment_id, user_id, scan_id, ingestion_version, source_digest, status,
               entity_count, assertion_count, evidence_count, error_code, ingested_at, updated_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(assessment_id, user_id, scan_id, ingestion_version, source_digest)
           DO UPDATE SET status = excluded.status, entity_count = excluded.entity_count,
               assertion_count = excluded.assertion_count, evidence_count = excluded.evidence_count,
               error_code = excluded.error_code, updated_at = excluded.updated_at""",
        (
            assessment_id, user_id, scan_id, INGESTION_VERSION, digest, status,
            entity_count, assertion_count, evidence_count, error_code, now, now,
        ),
    )
    return _row(_ledger(connection, user_id, assessment_id, scan_id, digest))


def _digest(value: object) -> str:
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True, default=str)


def _now() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()


def _row(row: sqlite3.Row | None) -> dict:
    if row is None:
        raise RuntimeError("Assessment-map ingestion ledger was not written.")
    return {key: row[key] for key in row.keys()}
