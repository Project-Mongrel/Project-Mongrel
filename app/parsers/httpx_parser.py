import json


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

    tls = item.get("tls") or item.get("tls_grab") or item.get("tls_probe")
    if not isinstance(tls, dict):
        tls = {}

    normalized = {
        "url": url,
        "host": _first_string(item, "host", "hostname", "input") or url,
        "status_code": status_code,
        "title": _first_string(item, "title"),
        "web_server": _first_string(item, "webserver", "web_server", "server") or _header_value(headers, "server"),
        "technologies": technologies,
        "content_length": _as_int(item.get("content_length") or item.get("content-length") or item.get("cl")),
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
    for service in services:
        status_code = service.get("status_code")
        if status_code is not None:
            key = str(status_code)
            status_codes[key] = status_codes.get(key, 0) + 1
        if service.get("title"):
            titles += 1
        if service.get("redirect_location") or service.get("final_url"):
            redirects += 1
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


def _normalize_raw(item: dict) -> dict:
    return {
        str(key): value
        for key, value in item.items()
        if key not in {"body", "response", "screenshot_bytes"} and value not in (None, "", [], {})
    }
