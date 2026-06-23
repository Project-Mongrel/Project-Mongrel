from urllib.parse import urlparse


def normalize_target(target: str) -> str:
    stripped_target = target.strip()
    if not stripped_target:
        return stripped_target

    parsed_target = urlparse(stripped_target)
    if parsed_target.scheme in {"http", "https"} and parsed_target.hostname:
        return parsed_target.hostname

    return stripped_target
