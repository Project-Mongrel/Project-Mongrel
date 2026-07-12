from urllib.parse import urlparse


def normalize_playwright_observation(observation: dict) -> dict:
    requested_url = _clean(observation.get("requested_url"))
    final_url = _clean(observation.get("final_url")) or requested_url
    parsed = urlparse(final_url or requested_url or "")
    normalized = {
        "requested_url": requested_url,
        "final_url": final_url,
        "host": _clean(observation.get("host")) or parsed.netloc or None,
        "title": _clean(observation.get("title")),
        "load_status": _clean(observation.get("load_status")) or "unknown",
        "status_code": _as_int(observation.get("status_code")),
        "redirects": _as_string_list(observation.get("redirects")),
        "redirected_out_of_scope": bool(observation.get("redirected_out_of_scope")),
        "forms_count": _as_int(observation.get("forms_count")) or 0,
        "inputs_count": _as_int(observation.get("inputs_count")) or 0,
        "links_count": _as_int(observation.get("links_count")) or 0,
        "link_samples": _as_string_list(observation.get("link_samples"))[:10],
        "form_samples": _as_dict_list(observation.get("form_samples"), limit=10),
        "input_samples": _as_dict_list(observation.get("input_samples"), limit=25),
        "console_issue_count": _as_int(observation.get("console_issue_count")) or 0,
        "console_messages": _as_dict_list(observation.get("console_messages"), limit=10),
        "network_issue_count": _as_int(observation.get("network_issue_count")) or 0,
        "network_events": _as_dict_list(observation.get("network_events"), limit=25),
        "page_error_count": _as_int(observation.get("page_error_count")) or 0,
        "screenshot": observation.get("screenshot") if isinstance(observation.get("screenshot"), dict) else {},
        "limits": observation.get("limits") if isinstance(observation.get("limits"), dict) else {},
        "limitations": _as_string_list(observation.get("limitations")),
    }
    return {key: value for key, value in normalized.items() if value not in (None, "", [], {})}


def summarize_playwright_observation(observation: dict) -> dict[str, object]:
    normalized = normalize_playwright_observation(observation)
    return {
        "requested_url": normalized.get("requested_url"),
        "final_url": normalized.get("final_url"),
        "title": normalized.get("title"),
        "load_status": normalized.get("load_status", "unknown"),
        "status_code": normalized.get("status_code"),
        "forms_count": int(normalized.get("forms_count") or 0),
        "inputs_count": int(normalized.get("inputs_count") or 0),
        "links_count": int(normalized.get("links_count") or 0),
        "console_issue_count": int(normalized.get("console_issue_count") or 0),
        "network_issue_count": int(normalized.get("network_issue_count") or 0),
        "page_error_count": int(normalized.get("page_error_count") or 0),
        "screenshot_present": bool(normalized.get("screenshot")),
        "redirected_out_of_scope": bool(normalized.get("redirected_out_of_scope")),
        "form_samples_count": len(normalized.get("form_samples") or []),
        "input_samples_count": len(normalized.get("input_samples") or []),
        "network_events_count": len(normalized.get("network_events") or []),
    }


def _clean(value: object) -> str | None:
    cleaned = str(value or "").replace("\n", " ").strip()
    return cleaned[:700] if cleaned else None


def _as_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_string_list(value: object) -> list[str]:
    if value is None:
        return []
    candidates = value if isinstance(value, list) else [value]
    return [str(candidate).strip() for candidate in candidates if str(candidate).strip()]


def _as_dict_list(value: object, *, limit: int) -> list[dict]:
    if not isinstance(value, list):
        return []
    normalized = []
    for item in value[:limit]:
        if not isinstance(item, dict):
            continue
        cleaned = {
            str(key): _clean(raw_value) if not isinstance(raw_value, bool) else raw_value
            for key, raw_value in item.items()
            if raw_value not in (None, "", [], {})
        }
        if cleaned:
            normalized.append(cleaned)
    return normalized
