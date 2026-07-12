import json

SENSITIVE_RAW_KEYS = {
    "body",
    "response",
    "request",
    "raw",
    "raw_header",
    "raw_headers",
    "header",
    "headers",
    "request_header",
    "request_headers",
    "response_header",
    "response_headers",
    "cookie",
    "cookies",
    "set-cookie",
    "authorization",
    "proxy-authorization",
    "www-authenticate",
    "screenshot_bytes",
    "stored_response_path",
}


def parse_httpx_output(text: str) -> list[dict]:
    observations: list[dict] = []
    for line in str(text or "").splitlines():
        cleaned = line.strip()
        if not cleaned:
            continue
        try:
            decoded = json.loads(cleaned)
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict):
            observations.append(normalize_httpx_observation(decoded))
    return observations


def normalize_httpx_observation(item: dict) -> dict:
    url = _first_string(item, "url", "input", "host", "scheme")
    final_url = _first_string(item, "final_url", "location", "redirect-location", "redirect_location")
    status_code = _as_int(item.get("status_code") or item.get("status-code") or item.get("status"))
    technologies = _as_string_list(item.get("tech") or item.get("technologies") or item.get("technology"))
    headers = item.get("header") or item.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}

    tls = _safe_metadata_dict(item.get("tls") or item.get("tls_grab") or item.get("tls_probe") or item.get("certificate"))
    cname = _as_string_list(item.get("cname") or item.get("cnames"))
    cdn = item.get("cdn")
    cdn_name = _first_string(item, "cdn_name", "cdn-name", "cdn")

    normalized = {
        "url": url,
        "host": _first_string(item, "host", "hostname", "input") or url,
        "status_code": status_code,
        "title": _first_string(item, "title"),
        "web_server": _first_string(item, "webserver", "web_server", "server") or _header_value(headers, "server"),
        "technologies": technologies,
        "content_length": _as_int(item.get("content_length") or item.get("content-length") or item.get("cl")),
        "content_type": _first_string(item, "content_type", "content-type", "ct"),
        "response_time": _first_string(item, "response_time", "response-time", "rt"),
        "method": _first_string(item, "method"),
        "ip": _first_string(item, "ip", "host_ip", "a"),
        "cdn": bool(cdn) if isinstance(cdn, bool) else cdn_name,
        "cname": cname,
        "asn": _safe_metadata_dict(item.get("asn")) or _first_string(item, "asn"),
        "probe": item.get("probe") if isinstance(item.get("probe"), bool) else _first_string(item, "probe"),
        "redirect_location": final_url,
        "final_url": final_url,
        "tls": tls,
        "raw": _normalize_raw(item),
    }
    return {key: value for key, value in normalized.items() if value not in (None, "", [], {})}


def summarize_httpx_services(services: list[dict]) -> dict[str, object]:
    status_codes: dict[str, int] = {}
    technologies: list[str] = []
    redirects = 0
    titles = 0
    tls_count = 0
    ip_count = 0
    cdn_count = 0
    cname_count = 0
    content_types: list[str] = []
    for service in services:
        status_code = service.get("status_code")
        if status_code is not None:
            key = str(status_code)
            status_codes[key] = status_codes.get(key, 0) + 1
        if service.get("title"):
            titles += 1
        if service.get("redirect_location") or service.get("final_url"):
            redirects += 1
        if service.get("tls"):
            tls_count += 1
        if service.get("ip"):
            ip_count += 1
        if service.get("cdn"):
            cdn_count += 1
        if service.get("cname"):
            cname_count += 1
        content_type = str(service.get("content_type") or "").strip()
        if content_type and content_type.lower() not in {value.lower() for value in content_types}:
            content_types.append(content_type)
        for technology in service.get("technologies") or []:
            cleaned = str(technology or "").strip()
            if cleaned and cleaned.lower() not in {value.lower() for value in technologies}:
                technologies.append(cleaned)
    return {
        "service_count": len(services),
        "status_codes": status_codes,
        "title_count": titles,
        "technologies": technologies,
        "redirect_count": redirects,
        "tls_count": tls_count,
        "ip_count": ip_count,
        "cdn_count": cdn_count,
        "cname_count": cname_count,
        "content_types": content_types,
    }


def _first_string(item: dict, *keys: str) -> str | None:
    for key in keys:
        value = item.get(key)
        if value is None:
            continue
        cleaned = str(value).strip()
        if cleaned:
            return cleaned
    return None


def _header_value(headers: dict, wanted_key: str) -> str | None:
    for key, value in headers.items():
        if str(key).lower() == wanted_key.lower():
            return str(value).strip() or None
    return None


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
    if isinstance(value, list):
        candidates = value
    elif isinstance(value, str):
        candidates = [part.strip() for part in value.split(",")]
    else:
        candidates = [value]
    return [str(candidate).strip() for candidate in candidates if str(candidate).strip()]


def _safe_metadata_dict(value: object) -> dict:
    if not isinstance(value, dict):
        return {}
    cleaned: dict[str, object] = {}
    for key, nested_value in value.items():
        normalized_key = str(key).strip()
        if not normalized_key or normalized_key.lower() in SENSITIVE_RAW_KEYS:
            continue
        if nested_value in (None, "", [], {}):
            continue
        if isinstance(nested_value, dict):
            nested = _safe_metadata_dict(nested_value)
            if nested:
                cleaned[normalized_key] = nested
        elif isinstance(nested_value, list):
            bounded = [str(item).strip() for item in nested_value[:20] if str(item).strip()]
            if bounded:
                cleaned[normalized_key] = bounded
        else:
            cleaned[normalized_key] = nested_value
    return cleaned


def _normalize_raw(item: dict) -> dict:
    return {
        str(key): value
        for key, value in item.items()
        if str(key).lower() not in SENSITIVE_RAW_KEYS and value not in (None, "", [], {})
    }
