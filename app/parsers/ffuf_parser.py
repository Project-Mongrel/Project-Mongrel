import json
from urllib.parse import urlparse


def parse_ffuf_output(text: str) -> list[dict]:
    results: list[dict] = []
    for item in _decode_records(text):
        if isinstance(item, dict) and isinstance(item.get("results"), list):
            for result in item["results"]:
                if isinstance(result, dict):
                    results.append(normalize_ffuf_result(result))
        elif isinstance(item, dict):
            results.append(normalize_ffuf_result(item))
    return results


def normalize_ffuf_result(item: dict) -> dict:
    url = _first_string(item, "url", "input_url", "matched")
    parsed = urlparse(url or "")
    status_code = _as_int(item.get("status") or item.get("status_code"))
    normalized = {
        "url": url,
        "host": parsed.netloc or _first_string(item, "host"),
        "path": _first_string(item, "path") or parsed.path or None,
        "status_code": status_code,
        "content_length": _as_int(item.get("length") or item.get("content_length")),
        "words": _as_int(item.get("words")),
        "lines": _as_int(item.get("lines")),
        "redirect_location": _first_string(item, "redirectlocation", "redirect_location", "location"),
        "input_word": _input_word(item.get("input")),
        "classification": _classification(status_code),
        "raw": _normalize_raw(item),
    }
    return {key: value for key, value in normalized.items() if value not in (None, "", [], {})}


def summarize_ffuf_results(results: list[dict]) -> dict[str, object]:
    status_codes: dict[str, int] = {}
    interesting_paths: list[str] = []
    redirect_count = 0
    forbidden_count = 0
    server_error_count = 0
    for result in results:
        status = result.get("status_code")
        if status is not None:
            key = str(status)
            status_codes[key] = status_codes.get(key, 0) + 1
        classification = str(result.get("classification") or "")
        if classification == "redirect":
            redirect_count += 1
        if classification == "forbidden":
            forbidden_count += 1
        if classification == "server-error":
            server_error_count += 1
        path = str(result.get("path") or result.get("url") or "").strip()
        if path and path.lower() not in {value.lower() for value in interesting_paths}:
            interesting_paths.append(path)
    return {
        "result_count": len(results),
        "status_codes": status_codes,
        "interesting_paths": interesting_paths,
        "redirect_count": redirect_count,
        "forbidden_count": forbidden_count,
        "server_error_count": server_error_count,
    }


def _decode_records(text: str) -> list[object]:
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


def _input_word(value: object) -> str | None:
    if isinstance(value, dict):
        for key in ("FUZZ", "word"):
            cleaned = str(value.get(key) or "").strip()
            if cleaned:
                return cleaned
        for candidate in value.values():
            cleaned = str(candidate or "").strip()
            if cleaned:
                return cleaned
    cleaned = str(value or "").strip()
    return cleaned or None


def _classification(status_code: int | None) -> str:
    if status_code is None:
        return "observed"
    if 200 <= status_code <= 299:
        return "public"
    if 300 <= status_code <= 399:
        return "redirect"
    if status_code in {401, 403}:
        return "forbidden"
    if status_code >= 500:
        return "server-error"
    return "observed"


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
        if key not in {"body", "response_body", "content"} and value not in (None, "", [], {})
    }
