from app.services.target_normalizer import normalize_for_nmap


def normalize_target(target: str) -> str:
    return normalize_for_nmap(target)
