import re
from ipaddress import ip_address
from urllib.parse import urlparse, urlunparse

_IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PARENTHESIZED_IPV4_PATTERN = re.compile(r"\((?P<ip>(?:\d{1,3}\.){3}\d{1,3})\)")
_WHITESPACE_PATTERN = re.compile(r"\s")


def normalize_target_key(target: str | None) -> str | None:
    if target is None:
        return None

    normalized_target = target.strip()
    if not normalized_target:
        return None

    parenthesized_ip_match = _PARENTHESIZED_IPV4_PATTERN.search(normalized_target)
    if parenthesized_ip_match is not None:
        return parenthesized_ip_match.group("ip")

    if _IPV4_PATTERN.fullmatch(normalized_target):
        return normalized_target

    return normalized_target.lower()


def normalize_for_nmap(raw_target: str) -> str:
    return _normalize_hostname_target(raw_target, tool_name="Nmap")


def normalize_for_bbot(raw_target: str) -> str:
    return _normalize_hostname_target(raw_target, tool_name="BBOT")


def normalize_for_nuclei(raw_target: str) -> str:
    return _normalize_http_url_target(raw_target, tool_name="Nuclei")


def normalize_for_httpx(raw_target: str) -> str:
    return _normalize_http_url_target(raw_target, tool_name="httpx")


def normalize_for_katana(raw_target: str) -> str:
    return _normalize_http_url_target(raw_target, tool_name="Katana")


def normalize_for_playwright(raw_target: str) -> str:
    return _normalize_http_url_target(raw_target, tool_name="Playwright")


def normalize_for_ffuf(raw_target: str) -> str:
    return _normalize_http_url_target(raw_target, tool_name="ffuf")


def _normalize_http_url_target(raw_target: str, *, tool_name: str) -> str:
    stripped_target = _strip_and_validate(raw_target, tool_name=tool_name)
    parsed_target = urlparse(stripped_target)
    if parsed_target.scheme:
        if parsed_target.scheme.lower() not in {"http", "https"} or not parsed_target.hostname:
            raise ValueError(f"{tool_name} target must be a valid http or https URL or hostname.")

        netloc = _normalize_netloc(parsed_target, tool_name=tool_name)
        return urlunparse(
            (
                parsed_target.scheme.lower(),
                netloc,
                parsed_target.path,
                "",
                parsed_target.query,
                parsed_target.fragment,
            )
        )

    if "://" in stripped_target:
        raise ValueError(f"{tool_name} target must be a valid http or https URL or hostname.")

    _validate_bare_host_or_ip(stripped_target, tool_name=tool_name)
    return f"https://{stripped_target.lower()}"


def _normalize_hostname_target(raw_target: str, *, tool_name: str) -> str:
    stripped_target = _strip_and_validate(raw_target, tool_name=tool_name)
    parsed_target = urlparse(stripped_target)
    if parsed_target.scheme:
        if parsed_target.scheme.lower() not in {"http", "https"} or not parsed_target.hostname:
            raise ValueError(f"{tool_name} target must be a valid http or https URL or hostname.")

        return parsed_target.hostname.lower()

    if "://" in stripped_target:
        raise ValueError(f"{tool_name} target must be a valid http or https URL or hostname.")

    _validate_bare_host_or_ip(stripped_target, tool_name=tool_name)
    return stripped_target.lower()


def _strip_and_validate(raw_target: str, *, tool_name: str) -> str:
    stripped_target = str(raw_target or "").strip()
    if not stripped_target:
        raise ValueError(f"{tool_name} target cannot be empty.")

    if _WHITESPACE_PATTERN.search(stripped_target):
        raise ValueError(f"{tool_name} target is malformed.")

    return stripped_target


def _validate_bare_host_or_ip(target: str, *, tool_name: str) -> None:
    try:
        ip_address(target)
        return
    except ValueError:
        pass

    if target.startswith((".", "-")) or target.endswith((".", "-")) or ".." in target:
        raise ValueError(f"{tool_name} target is malformed.")

    labels = target.split(".")
    if not all(label and re.fullmatch(r"[A-Za-z0-9-]+", label) for label in labels):
        raise ValueError(f"{tool_name} target is malformed.")


def _normalize_netloc(parsed_target: object, *, tool_name: str) -> str:
    hostname = str(parsed_target.hostname or "").lower()
    try:
        port = parsed_target.port
    except ValueError as exc:
        raise ValueError(f"{tool_name} target is malformed.") from exc

    if port is not None:
        hostname = f"{hostname}:{port}"

    return hostname
