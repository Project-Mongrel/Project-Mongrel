"""Bounded assessment-map retrieval for assessment-scoped Ask Mongrel."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.services.assessment_map_store import AssessmentMapScopeError, initialize_assessment_map_schema
from app.services.assessment_map_store import list_assertions as _list_assertions
from app.services.assessment_map_store import list_entities as _list_entities
from app.services.findings_store import _get_connection

MAP_RETRIEVAL_VERSION = "assessment-map.retrieval.v1"
MAP_EVIDENCE_TOOLS = (
    "nmap", "bbot", "httpx", "katana", "playwright", "ffuf", "nuclei", "testssl", "gitleaks",
)
MAX_ENTITY_CANDIDATES = 40
MAX_ASSERTION_CANDIDATES = 80
MAX_CONTEXT_ENTITIES = 12
MAX_CONTEXT_RELATIONSHIPS = 18
MAX_PROVENANCE_PER_ITEM = 3
MAX_CONTEXT_CHARS = 4500
_WORD_PATTERN = re.compile(r"[a-z0-9][a-z0-9_.:-]{2,}")
_STOPWORDS = {
    "about",
    "assessment",
    "associated",
    "between",
    "different",
    "discovered",
    "does",
    "endpoint",
    "endpoints",
    "evidence",
    "finding",
    "findings",
    "have",
    "investigate",
    "mongrel",
    "relationship",
    "relationships",
    "remain",
    "server",
    "service",
    "services",
    "should",
    "support",
    "supports",
    "that",
    "this",
    "tool",
    "tools",
    "unknown",
    "what",
    "which",
}


def build_assessment_map_context(
    *,
    user_id: int,
    assessment_id: int,
    question: str | None = None,
    entity_limit: int = MAX_CONTEXT_ENTITIES,
    relationship_limit: int = MAX_CONTEXT_RELATIONSHIPS,
    max_chars: int = MAX_CONTEXT_CHARS,
) -> dict:
    """Return a deterministic, owner-scoped map slice safe for Ask prompts.

    The function intentionally reads a bounded candidate set rather than the
    entire map. Missing map rows are treated as lack of map evidence, not proof
    that an asset, endpoint, relationship, or finding is absent.
    """

    try:
        initialize_assessment_map_schema()
        entities = _list_entities(
            user_id=user_id,
            assessment_id=assessment_id,
            limit=max(entity_limit * 3, MAX_ENTITY_CANDIDATES),
        )
        assertions = _list_assertions(
            user_id=user_id,
            assessment_id=assessment_id,
            limit=max(relationship_limit * 3, MAX_ASSERTION_CANDIDATES),
        )
        total_entities, total_assertions = _map_counts(user_id=user_id, assessment_id=assessment_id)
    except AssessmentMapScopeError:
        raise
    except Exception:
        return _unavailable("retrieval_error")

    if not entities and not assertions:
        return {
            "version": MAP_RETRIEVAL_VERSION,
            "available": False,
            "reason": "no_mapped_evidence",
            "coverage": _coverage_note(),
            "entities": [],
            "relationships": [],
            "truncated": False,
        }

    entities = _include_assertion_entities(
        user_id=user_id,
        assessment_id=assessment_id,
        entities=entities,
        assertions=assertions,
    )
    entity_by_id = {int(entity["id"]): _summarize_entity(entity) for entity in entities}
    terms = _question_terms(question or "")
    ranked_entities = _rank_entities(entity_by_id.values(), terms)
    selected_entities = ranked_entities[: max(0, int(entity_limit))]
    selected_ids = {int(entity["id"]) for entity in selected_entities}

    summarized_assertions = [_summarize_assertion(row, entity_by_id) for row in assertions]
    ranked_relationships = _rank_relationships(summarized_assertions, selected_ids, terms)
    selected_relationships = ranked_relationships[: max(0, int(relationship_limit))]

    related_ids = {
        entity_id
        for relationship in selected_relationships
        for entity_id in (relationship.get("subject_id"), relationship.get("object_id"))
        if entity_id is not None
    }
    for entity_id in related_ids:
        if entity_id not in selected_ids and entity_id in entity_by_id and len(selected_entities) < int(entity_limit):
            selected_entities.append(entity_by_id[entity_id])
            selected_ids.add(entity_id)

    try:
        represented_tools = _attach_provenance(
            user_id=user_id,
            assessment_id=assessment_id,
            entities=selected_entities,
            relationships=selected_relationships,
        )
    except Exception:
        return _unavailable("provenance_retrieval_error")
    selected_relationships = [item for item in selected_relationships if item.get("provenance")]
    supported_entity_ids = {
        int(entity["id"])
        for entity in selected_entities
        if entity.get("provenance")
    }
    supported_entity_ids.update(
        int(entity_id)
        for relationship in selected_relationships
        for entity_id in (relationship.get("subject_id"), relationship.get("object_id"))
        if entity_id is not None
    )
    selected_entities = [
        entity for entity in selected_entities if int(entity["id"]) in supported_entity_ids
    ]
    if not selected_entities and not selected_relationships:
        return _unavailable("no_provenanced_map_evidence")
    context = {
        "version": MAP_RETRIEVAL_VERSION,
        "available": bool(selected_entities or selected_relationships),
        "coverage": _coverage_note(represented_tools=represented_tools),
        "entity_count": total_entities,
        "relationship_count": total_assertions,
        "entities": selected_entities,
        "relationships": selected_relationships,
        "truncated": len(selected_entities) < total_entities or len(selected_relationships) < total_assertions,
    }
    return _fit_context(context, max_chars=max_chars)


def _unavailable(reason: str) -> dict:
    return {
        "version": MAP_RETRIEVAL_VERSION,
        "available": False,
        "reason": reason,
        "coverage": _coverage_note(),
        "entities": [],
        "relationships": [],
        "truncated": False,
    }


def _coverage_note(*, represented_tools: set[str] | None = None) -> dict:
    represented = sorted(represented_tools or set())
    return {
        "supported_tools": list(MAP_EVIDENCE_TOOLS),
        "represented_tools": represented,
        "limitation": (
            "This map slice contains only stored mapped evidence and may represent only a subset of supported tools. "
            "Missing map evidence is not proof of absence or target safety."
        ),
    }


def _summarize_entity(entity: dict) -> dict:
    canonical = _json_object(entity.get("canonical_key"))
    payload = canonical.get("payload") if isinstance(canonical.get("payload"), dict) else {}
    summary = {
        "id": int(entity["id"]),
        "type": str(entity.get("entity_type") or ""),
        "label": _entity_label(entity, payload),
        "identity": _safe_payload(payload),
    }
    attributes = _json_object(entity.get("attributes_json"))
    if attributes:
        summary["attributes"] = _safe_payload(attributes, max_items=6)
    return summary


def _entity_label(entity: dict, payload: dict) -> str:
    display = str(entity.get("display_value") or "").strip()
    if display:
        return _safe_display_label(display)
    entity_type = str(entity.get("entity_type") or "entity")
    if entity_type == "hostname":
        return str(payload.get("hostname") or "hostname")
    if entity_type == "ip":
        return str(payload.get("address") or "IP address")
    if entity_type == "technology":
        return str(payload.get("product") or "technology")
    if entity_type == "service":
        return f"{payload.get('transport', 'service')}/{payload.get('port', 'unknown-port')}"
    if entity_type == "endpoint":
        origin = payload.get("origin") if isinstance(payload.get("origin"), dict) else {}
        return f"{origin.get('scheme', 'http')} endpoint {payload.get('path', '/')}"
    if entity_type == "application":
        origin = payload if isinstance(payload, dict) else {}
        return f"{origin.get('scheme', 'web')} application"
    if entity_type == "finding":
        return f"{payload.get('tool', 'tool')} finding {payload.get('stable_id', '')}".strip()
    return entity_type


def _summarize_assertion(row: dict, entity_by_id: dict[int, dict]) -> dict:
    subject_id = int(row["subject_entity_id"])
    object_id = int(row["object_entity_id"]) if row.get("object_entity_id") is not None else None
    value = _json_value(row.get("normalized_value_json"))
    summary = {
        "id": int(row["id"]),
        "subject_id": subject_id,
        "subject": (entity_by_id.get(subject_id) or {}).get("label", f"entity {subject_id}"),
        "predicate": str(row.get("predicate") or ""),
        "polarity": str(row.get("polarity") or "observed"),
    }
    if object_id is not None:
        summary["object_id"] = object_id
        summary["object"] = (entity_by_id.get(object_id) or {}).get("label", f"entity {object_id}")
    if value is not None:
        summary["value"] = _safe_payload(value, max_items=6)
    attributes = _json_object(row.get("attributes_json"))
    if attributes:
        summary["attributes"] = _safe_payload(attributes, max_items=6)
    return summary


def _attach_provenance(
    *, user_id: int, assessment_id: int, entities: list[dict], relationships: list[dict]
) -> set[str]:
    entity_ids = [int(entity["id"]) for entity in entities]
    assertion_ids = [int(item["id"]) for item in relationships]
    if not entity_ids and not assertion_ids:
        return set()
    rows = _load_evidence_links(
        user_id=user_id,
        assessment_id=assessment_id,
        entity_ids=entity_ids,
        assertion_ids=assertion_ids,
    )
    grouped: dict[tuple[str, int], list[dict]] = {}
    represented_tools: set[str] = set()
    for row in rows:
        destination_type = str(row.get("destination_type") or "")
        destination_id = int(row.get("destination_id"))
        grouped.setdefault((destination_type, destination_id), []).append(_provenance(row))
        tool = str(row.get("source_tool") or "").strip().lower().removesuffix(".sh")
        if tool:
            represented_tools.add(tool)
    for entity in entities:
        entity["provenance"] = grouped.get(("entity", int(entity["id"])), [])[:MAX_PROVENANCE_PER_ITEM]
    for relationship in relationships:
        relationship["provenance"] = grouped.get(("assertion", int(relationship["id"])), [])[:MAX_PROVENANCE_PER_ITEM]
    return represented_tools


def _load_evidence_links(
    *,
    user_id: int,
    assessment_id: int,
    entity_ids: list[int],
    assertion_ids: list[int],
) -> list[dict]:
    rows: list[dict] = []
    connection = _get_connection()
    query = """
        SELECT destination_type, destination_id, scan_id, finding_id, artifact_id,
               source_tool, evidence_kind, evidence_path, confidence
        FROM assessment_map_evidence_links
        WHERE assessment_id = ? AND user_id = ? AND destination_type = ? AND destination_id = ?
        ORDER BY source_tool, scan_id, finding_id, artifact_id, id
        LIMIT ?
    """
    for destination_type, destination_ids in (("entity", entity_ids), ("assertion", assertion_ids)):
        for destination_id in destination_ids:
            rows.extend(
                dict(row)
                for row in connection.execute(
                    query,
                    (
                        assessment_id,
                        user_id,
                        destination_type,
                        int(destination_id),
                        MAX_PROVENANCE_PER_ITEM,
                    ),
                ).fetchall()
            )
    return rows


def _map_counts(*, user_id: int, assessment_id: int) -> tuple[int, int]:
    """Return scope-qualified totals without loading unbounded map rows."""

    connection = _get_connection()
    entity_count = connection.execute(
        "SELECT COUNT(*) FROM assessment_map_entities WHERE assessment_id = ? AND user_id = ?",
        (assessment_id, user_id),
    ).fetchone()[0]
    assertion_count = connection.execute(
        "SELECT COUNT(*) FROM assessment_map_assertions WHERE assessment_id = ? AND user_id = ?",
        (assessment_id, user_id),
    ).fetchone()[0]
    return int(entity_count), int(assertion_count)


def _include_assertion_entities(
    *, user_id: int, assessment_id: int, entities: list[dict], assertions: list[dict]
) -> list[dict]:
    """Hydrate endpoints of the bounded assertion candidate set in the same owner scope."""

    existing_ids = {int(entity["id"]) for entity in entities}
    related_ids = {
        int(entity_id)
        for assertion in assertions
        for entity_id in (assertion.get("subject_entity_id"), assertion.get("object_entity_id"))
        if entity_id is not None and int(entity_id) not in existing_ids
    }
    if not related_ids:
        return entities
    connection = _get_connection()
    rows = []
    for entity_id in sorted(related_ids):
        row = connection.execute(
            """SELECT * FROM assessment_map_entities
               WHERE assessment_id = ? AND user_id = ? AND id = ?""",
            (assessment_id, user_id, entity_id),
        ).fetchone()
        if row is not None:
            rows.append(dict(row))
    rows.sort(key=lambda row: (str(row.get("entity_type") or ""), int(row.get("id") or 0)))
    return [*entities, *rows]


def _provenance(row: dict) -> dict:
    item = {
        "tool": str(row.get("source_tool") or ""),
        "kind": str(row.get("evidence_kind") or ""),
        "scan_id": row.get("scan_id"),
        "finding_id": row.get("finding_id"),
        "artifact_id": row.get("artifact_id"),
    }
    if row.get("evidence_path"):
        item["path"] = str(row.get("evidence_path"))
    if row.get("confidence"):
        item["confidence"] = str(row.get("confidence"))
    return {key: value for key, value in item.items() if value not in (None, "")}


def _safe_display_label(value: str) -> str:
    """Bound labels and remove URL credentials, fragments, and query values."""

    text = str(value or "").strip()
    try:
        parsed = urlsplit(text)
    except ValueError:
        parsed = None
    if parsed is not None and parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        try:
            port = parsed.port
        except ValueError:
            port = None
        netloc = host + (f":{port}" if port is not None else "")
        parameter_names = sorted({name for name, _value in parse_qsl(parsed.query, keep_blank_values=True) if name})
        query = urlencode([(name, "[redacted]") for name in parameter_names])
        text = urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", query, ""))
    return text[:300] + "... [truncated]" if len(text) > 320 else text


def _question_terms(question: str) -> set[str]:
    return {
        term
        for term in _WORD_PATTERN.findall(str(question or "").lower())
        if term not in _STOPWORDS
    }


def _rank_entities(entities: list[dict], terms: set[str]) -> list[dict]:
    return sorted(
        entities,
        key=lambda entity: (
            -_term_score(entity, terms),
            _entity_type_rank(str(entity.get("type") or "")),
            str(entity.get("label") or ""),
            int(entity.get("id") or 0),
        ),
    )


def _rank_relationships(relationships: list[dict], selected_ids: set[int], terms: set[str]) -> list[dict]:
    return sorted(
        relationships,
        key=lambda item: (
            -int(item.get("subject_id") in selected_ids or item.get("object_id") in selected_ids),
            -_term_score(item, terms),
            str(item.get("predicate") or ""),
            int(item.get("id") or 0),
        ),
    )


def _term_score(value: object, terms: set[str]) -> int:
    if not terms:
        return 0
    serialized = json.dumps(value, sort_keys=True, default=str).lower()
    return sum(term in serialized for term in terms)


def _entity_type_rank(entity_type: str) -> int:
    return {
        "hostname": 0,
        "ip": 1,
        "service": 2,
        "application": 3,
        "endpoint": 4,
        "technology": 5,
        "finding": 6,
    }.get(entity_type, 99)


def _fit_context(context: dict, *, max_chars: int) -> dict:
    budget = max(256, int(max_chars))
    if len(json.dumps(context, sort_keys=True, default=str)) <= budget:
        return context
    reduced = dict(context)
    reduced["truncated"] = True
    reduced["relationships"] = list(reduced.get("relationships") or [])
    reduced["entities"] = list(reduced.get("entities") or [])
    while len(json.dumps(reduced, sort_keys=True, default=str)) > budget and (
        len(reduced["relationships"]) > 4 or len(reduced["entities"]) > 4
    ):
        if len(reduced["relationships"]) >= len(reduced["entities"]) and len(reduced["relationships"]) > 4:
            reduced["relationships"] = reduced["relationships"][:-1]
        elif len(reduced["entities"]) > 4:
            reduced["entities"] = reduced["entities"][:-1]
    for item in list(reduced.get("entities") or []) + list(reduced.get("relationships") or []):
        if isinstance(item, dict):
            item["provenance"] = list(item.get("provenance") or [])[:1]
            item.pop("attributes", None)
            item.pop("identity", None)
    if len(json.dumps(reduced, sort_keys=True, default=str)) > budget:
        reduced["relationships"] = []
        reduced["entities"] = list(reduced.get("entities") or [])[:3]
    while len(json.dumps(reduced, sort_keys=True, default=str)) > budget and reduced["entities"]:
        reduced["entities"] = reduced["entities"][:-1]
    if len(json.dumps(reduced, sort_keys=True, default=str)) > budget:
        reduced["coverage"] = {
            "represented_tools": list((reduced.get("coverage") or {}).get("represented_tools") or []),
            "limitation": "Bounded map slice; omitted entries are not proof of absence.",
        }
    return reduced


def _json_object(value: object) -> dict:
    parsed = _json_value(value)
    return parsed if isinstance(parsed, dict) else {}


def _json_value(value: object) -> Any:
    if value in (None, ""):
        return None
    if isinstance(value, (dict, list, int, float, bool)):
        return value
    try:
        return json.loads(str(value))
    except (TypeError, json.JSONDecodeError):
        return None


def _safe_payload(value: Any, *, max_items: int = 8) -> Any:
    if isinstance(value, dict):
        safe = {}
        for key, item in list(value.items())[:max_items]:
            key_text = str(key)
            if _sensitive_key(key_text):
                continue
            safe[key_text] = _safe_payload(item, max_items=max_items)
        return safe
    if isinstance(value, list):
        return [_safe_payload(item, max_items=max_items) for item in value[:max_items]]
    if isinstance(value, str):
        return value[:300] + "... [truncated]" if len(value) > 320 else value
    return value


def _sensitive_key(key: str) -> bool:
    normalized = key.lower()
    return any(term in normalized for term in ("password", "passwd", "secret", "token", "credential", "authorization"))
