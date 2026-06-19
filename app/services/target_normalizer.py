import re

_IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PARENTHESIZED_IPV4_PATTERN = re.compile(r"\((?P<ip>(?:\d{1,3}\.){3}\d{1,3})\)")


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
