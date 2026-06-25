import ipaddress
import json
import re
from collections.abc import Iterable
from typing import Any

from app.services.target_normalizer import normalize_target_key

SUBDOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TECH_KEYS = {"technology", "technologies", "tech", "wappalyzer", "product"}
CERT_KEYS = {"certificate", "cert", "ssl", "tls"}
DNS_KEYS = {"dns", "dns_record", "record", "resolved_hosts"}
TYPE_MAP = {
    "dns_name": "subdomain",
    "subdomain": "subdomain",
    "url": "url",
    "ip": "ip_address",
    "ip_address": "ip_address",
    "email": "email",
    "technology": "technology",
    "certificate": "certificate",
    "dns_record": "dns_record",
}


def normalize_bbot_output(
    raw_output: str | dict | list | None,
    target: str,
    user_id: int,
    investigation_id: str | None = None,
) -> list[dict]:
    target_key = normalize_target_key(target)
    observations: list[dict] = []
    seen: set[tuple[str, str, str, str | None]] = set()

    for item in _iter_payload_items(raw_output):
        if isinstance(item, dict):
            _extract_from_mapping(item, observations, seen, target, target_key, user_id, investigation_id)
        elif isinstance(item, str):
            _extract_from_text(item, observations, seen, target, target_key, user_id, investigation_id)

    return observations


def summarize_observations(observations: list[dict]) -> dict[str, int]:
    summary = {
        "subdomain": 0,
        "url": 0,
        "ip_address": 0,
        "email": 0,
        "dns_record": 0,
        "technology": 0,
        "certificate": 0,
        "raw_event": 0,
    }
    for observation in observations:
        observation_type = str(observation.get("observation_type") or "")
        if observation_type in summary:
            summary[observation_type] += 1

    return summary


def _iter_payload_items(raw_output: str | dict | list | None) -> Iterable[str | dict]:
    if raw_output is None:
        return []
    if isinstance(raw_output, dict):
        return [raw_output]
    if isinstance(raw_output, list):
        return _flatten_payload(raw_output)
    if not isinstance(raw_output, str):
        return [str(raw_output)]

    items: list[str | dict] = []
    for line in raw_output.splitlines():
        stripped_line = line.strip()
        if not stripped_line:
            continue
        try:
            decoded = json.loads(stripped_line)
        except json.JSONDecodeError:
            items.append(stripped_line)
            continue
        if isinstance(decoded, dict):
            items.append(decoded)
        elif isinstance(decoded, list):
            items.extend(_flatten_payload(decoded))
        else:
            items.append(str(decoded))

    return items


def _flatten_payload(payload: list) -> list[str | dict]:
    items: list[str | dict] = []
    for item in payload:
        if isinstance(item, dict):
            items.append(item)
        elif isinstance(item, list):
            items.extend(_flatten_payload(item))
        elif item is not None:
            items.append(str(item))
    return items


def _extract_from_mapping(
    event: dict,
    observations: list[dict],
    seen: set[tuple[str, str, str, str | None]],
    target: str,
    target_key: str | None,
    user_id: int,
    investigation_id: str | None,
) -> None:
    event_type = _normalize_event_type(event)
    value = _extract_event_value(event)
    if event_type and value:
        _add_observation(observations, seen, event_type, value, target, target_key, user_id, investigation_id, event)

    for key, item in event.items():
        normalized_key = str(key).lower()
        if normalized_key in TECH_KEYS:
            for value in _iter_values(item):
                _add_observation(observations, seen, "technology", value, target, target_key, user_id, investigation_id, event)
        elif normalized_key in CERT_KEYS:
            for value in _iter_values(item):
                _add_observation(observations, seen, "certificate", value, target, target_key, user_id, investigation_id, event)
        elif normalized_key in DNS_KEYS:
            for value in _iter_values(item):
                _add_observation(observations, seen, "dns_record", value, target, target_key, user_id, investigation_id, event)
        elif isinstance(item, str):
            _extract_from_text(item, observations, seen, target, target_key, user_id, investigation_id)

    if not any(observation.get("metadata", {}).get("raw_event") == event for observation in observations):
        if event_type is None and value is not None:
            _add_observation(observations, seen, "raw_event", str(value), target, target_key, user_id, investigation_id, event)
        elif event_type is None and value is None and event:
            _add_observation(observations, seen, "raw_event", json.dumps(event, sort_keys=True), target, target_key, user_id, investigation_id, event)


def _extract_from_text(
    text: str,
    observations: list[dict],
    seen: set[tuple[str, str, str, str | None]],
    target: str,
    target_key: str | None,
    user_id: int,
    investigation_id: str | None,
) -> None:
    for value in URL_RE.findall(text):
        _add_observation(observations, seen, "url", value.rstrip(".,;)"), target, target_key, user_id, investigation_id)
    for value in EMAIL_RE.findall(text):
        _add_observation(observations, seen, "email", value.rstrip(".,;)"), target, target_key, user_id, investigation_id)
    for value in IP_RE.findall(text):
        if _is_ip_address(value):
            _add_observation(observations, seen, "ip_address", value, target, target_key, user_id, investigation_id)
    for value in SUBDOMAIN_RE.findall(text):
        cleaned_value = value.rstrip(".,;)")
        if "@" in cleaned_value or cleaned_value.startswith(("http.", "https.")) or _is_ip_address(cleaned_value):
            continue
        _add_observation(observations, seen, "subdomain", cleaned_value, target, target_key, user_id, investigation_id)


def _normalize_event_type(event: dict) -> str | None:
    raw_type = event.get("type") or event.get("event_type") or event.get("module")
    if raw_type is None:
        return None
    normalized_type = str(raw_type).lower().replace("-", "_")
    return TYPE_MAP.get(normalized_type)


def _extract_event_value(event: dict) -> str | None:
    for key in ("data", "value", "host", "url", "email", "ip", "name"):
        value = event.get(key)
        if isinstance(value, (str, int, float)):
            return str(value)
    return None


def _iter_values(value: Any) -> Iterable[str]:
    if value is None:
        return []
    if isinstance(value, (str, int, float)):
        return [str(value)]
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            values.extend(_iter_values(item))
        return values
    if isinstance(value, dict):
        return [str(item) for item in value.values() if isinstance(item, (str, int, float))]
    return [str(value)]


def _add_observation(
    observations: list[dict],
    seen: set[tuple[str, str, str, str | None]],
    observation_type: str,
    value: str,
    target: str,
    target_key: str | None,
    user_id: int,
    investigation_id: str | None,
    raw_event: dict | None = None,
) -> None:
    cleaned_value = value.strip()
    if not cleaned_value:
        return

    key = ("bbot", observation_type, cleaned_value.lower(), target_key)
    if key in seen:
        return

    seen.add(key)
    observations.append(
        {
            "user_id": user_id,
            "investigation_id": investigation_id,
            "source": "bbot",
            "observation_type": observation_type,
            "value": cleaned_value,
            "target": target,
            "target_key": target_key,
            "confidence": "medium",
            "risk_level": "info",
            "summary": _summary_for_observation(observation_type, cleaned_value),
            "metadata": {"raw_event": raw_event} if raw_event is not None else {},
        }
    )


def _summary_for_observation(observation_type: str, value: str) -> str:
    labels = {
        "subdomain": "BBOT identified subdomain",
        "url": "BBOT identified URL",
        "ip_address": "BBOT identified IP address",
        "email": "BBOT identified email address",
        "dns_record": "BBOT identified DNS record",
        "technology": "BBOT identified technology",
        "certificate": "BBOT identified certificate data",
        "raw_event": "BBOT produced raw event",
    }
    return f"{labels.get(observation_type, 'BBOT observation')}: {value}"


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
