import json
from urllib.parse import parse_qs, urlparse


def parse_katana_output(text: str) -> list[dict]:
    observations: list[dict] = []
    for item in _decode_json_records(text):
        if isinstance(item, dict):
            observations.append(normalize_katana_observation(item))
    return observations


def normalize_katana_observation(item: dict) -> dict:
    request = item.get("request") if isinstance(item.get("request"), dict) else {}
    response = item.get("response") if isinstance(item.get("response"), dict) else {}
    url = _first_string(item, "url", "endpoint", "matched", "href") or _first_string(request, "url", "endpoint")
    source = _first_string(item, "source", "referrer", "parent") or _first_string(request, "source", "referrer")
    parsed = urlparse(url or "")
    path = _first_string(item, "path") or parsed.path or None
    method = _first_string(item, "method") or _first_string(request, "method")
    status_code = _as_int(item.get("status_code") or item.get("status-code") or response.get("status_code") or response.get("status"))
    endpoint_type = _infer_endpoint_type(item, url, path)
    query_parameters = _query_parameters(item, parsed)
    form_action = _first_string(item, "form_action", "action")
    raw_forms = item.get("forms") if isinstance(item.get("forms"), list) else []
    forms = [_normalize_form(form) for form in raw_forms if isinstance(form, dict)]
    if form_action and not forms:
        forms = [{"action": form_action}]

    normalized = {
        "url": url,
        "host": _first_string(item, "host", "fqdn") or parsed.netloc or None,
        "path": path,
        "method": method,
        "status_code": status_code,
        "source": source,
        "depth": _as_int(item.get("depth") or item.get("crawl_depth")),
        "endpoint_type": endpoint_type,
        "query_parameters": query_parameters,
        "javascript": endpoint_type == "javascript",
        "forms": forms,
        "raw": _normalize_raw(item),
    }
    return {key: value for key, value in normalized.items() if value not in (None, "", [], {})}


def summarize_katana_observations(observations: list[dict]) -> dict[str, object]:
    hosts: list[str] = []
    js_files: list[str] = []
    query_parameters: list[str] = []
    forms = 0
    max_depth = 0
    for observation in observations:
        host = str(observation.get("host") or "").strip()
        if host and host.lower() not in {value.lower() for value in hosts}:
            hosts.append(host)
        if observation.get("endpoint_type") == "javascript":
            url = str(observation.get("url") or "").strip()
            if url and url.lower() not in {value.lower() for value in js_files}:
                js_files.append(url)
        for parameter in observation.get("query_parameters") or []:
            cleaned = str(parameter or "").strip()
            if cleaned and cleaned.lower() not in {value.lower() for value in query_parameters}:
                query_parameters.append(cleaned)
        forms += len(observation.get("forms") or [])
        depth = _as_int(observation.get("depth")) or 0
        max_depth = max(max_depth, depth)
    return {
        "url_count": len(observations),
        "unique_hosts": hosts,
        "host_count": len(hosts),
        "javascript_files": js_files,
        "javascript_count": len(js_files),
        "query_parameters": query_parameters,
        "query_parameter_count": len(query_parameters),
        "form_count": forms,
        "max_depth": max_depth,
    }


def _decode_json_records(text: str) -> list[object]:
    cleaned = str(text or "").strip()
    if not cleaned:
        return []
    try:
        decoded = json.loads(cleaned)
    except json.JSONDecodeError:
        decoded = None
    if isinstance(decoded, list):
        return decoded
    if isinstance(decoded, dict):
        return [decoded]

    records = []
    for line in cleaned.splitlines():
        try:
            decoded_line = json.loads(line.strip())
        except json.JSONDecodeError:
            continue
        records.append(decoded_line)
    return records


def _infer_endpoint_type(item: dict, url: str | None, path: str | None) -> str:
    explicit = _first_string(item, "endpoint_type", "type", "tag")
    candidate = (path or url or "").lower()
    if candidate.endswith(".js"):
        return "javascript"
    if explicit:
        normalized = explicit.lower()
        if normalized in {"form", "input"} or item.get("form_action") or item.get("forms"):
            return "form"
        return normalized
    if item.get("form_action") or item.get("forms"):
        return "form"
    if urlparse(url or "").query:
        return "parameterized_url"
    return "url"


def _query_parameters(item: dict, parsed_url: object) -> list[str]:
    raw_parameters = item.get("query_parameters") or item.get("params") or item.get("parameters")
    values: list[str] = []
    if isinstance(raw_parameters, dict):
        values.extend(str(key) for key in raw_parameters)
    elif isinstance(raw_parameters, list):
        values.extend(_explicit_parameter_name(value) for value in raw_parameters)
    elif isinstance(raw_parameters, str):
        values.extend(part.strip() for part in raw_parameters.split(","))
    values.extend(parse_qs(parsed_url.query).keys())
    unique_values = []
    for value in values:
        cleaned = _explicit_parameter_name(value)
        if cleaned and cleaned.lower() not in {item.lower() for item in unique_values}:
            unique_values.append(cleaned)
    return unique_values


def _normalize_form(form: dict) -> dict:
    normalized = {
        "action": _first_string(form, "action", "url"),
        "method": _first_string(form, "method"),
    }
    inputs = form.get("inputs") if isinstance(form.get("inputs"), list) else []
    if inputs:
        normalized["inputs"] = [name for value in inputs if (name := _explicit_parameter_name(value))]
    return {key: value for key, value in normalized.items() if value not in (None, "", [], {})}


def _explicit_parameter_name(value: object) -> str:
    if isinstance(value, dict):
        value = value.get("name") if value.get("name") not in (None, "") else value.get("key")
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return ""
    cleaned = str(value).strip()
    if not cleaned or cleaned.startswith(("{", "[")):
        return ""
    for separator in ("=", ":"):
        cleaned = cleaned.split(separator, 1)[0].strip()
    if not cleaned or len(cleaned) > 128:
        return ""
    return cleaned if all(character.isalnum() or character in "_.-[]" for character in cleaned) else ""


def _first_string(item: dict, *keys: str) -> str | None:
    for key in keys:
        value = item.get(key)
        if value is None:
            continue
        cleaned = str(value).strip()
        if cleaned:
            return cleaned
    return None


def _as_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_raw(item: dict) -> dict:
    return {
        str(key): value
        for key, value in item.items()
        if key not in {"body", "response_body", "screenshot_bytes"} and value not in (None, "", [], {})
    }
