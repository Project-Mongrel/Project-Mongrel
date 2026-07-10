import hashlib
import json
import re

from app.core.config import get_settings
from app.tools.nmap_runner import DANGEROUS_SHELL_CHARACTERS

SAFE_TSHARK_INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def build_tshark_capture_request(
    *,
    interface: str,
    duration_seconds: int,
    packet_count: int,
    file_size_kb: int | None = None,
) -> dict:
    settings = get_settings()
    normalized_interface = _normalize_interface(interface)
    allowed_interfaces = _allowed_interfaces(settings.tshark_live_interface_allowlist)
    if normalized_interface not in allowed_interfaces:
        raise ValueError("TShark interface is not allowlisted.")

    normalized_duration = _bounded_int(
        duration_seconds,
        minimum=1,
        maximum=int(settings.tshark_live_max_duration_seconds),
        name="TShark capture duration",
    )
    normalized_packet_count = _bounded_int(
        packet_count,
        minimum=1,
        maximum=int(settings.tshark_live_max_packet_count),
        name="TShark packet count",
    )
    normalized_file_size = _bounded_int(
        file_size_kb if file_size_kb is not None else int(settings.tshark_live_max_file_size_kb),
        minimum=64,
        maximum=int(settings.tshark_live_max_file_size_kb),
        name="TShark capture file size",
    )
    request = {
        "interface": normalized_interface,
        "duration_seconds": normalized_duration,
        "packet_count": normalized_packet_count,
        "file_size_kb": normalized_file_size,
        "expected_effect": "Capture bounded packet metadata from an allowlisted local interface for offline TShark analysis.",
        "risk_tier": "medium",
    }
    request["fingerprint"] = tshark_capture_request_fingerprint(request)
    return request


def tshark_capture_request_fingerprint(request: dict) -> str:
    canonical = {
        "interface": request.get("interface"),
        "duration_seconds": int(request.get("duration_seconds") or 0),
        "packet_count": int(request.get("packet_count") or 0),
        "file_size_kb": int(request.get("file_size_kb") or 0),
        "expected_effect": request.get("expected_effect"),
        "risk_tier": request.get("risk_tier"),
    }
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _allowed_interfaces(raw_allowlist: str) -> set[str]:
    return {item.strip() for item in str(raw_allowlist or "").split(",") if item.strip()}


def _normalize_interface(interface: str) -> str:
    normalized = str(interface or "").strip()
    if (
        not SAFE_TSHARK_INTERFACE_PATTERN.fullmatch(normalized)
        or ".." in normalized
        or any(character in normalized for character in DANGEROUS_SHELL_CHARACTERS)
    ):
        raise ValueError("Malformed TShark interface.")
    return normalized


def _bounded_int(value: object, *, minimum: int, maximum: int, name: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer.") from exc
    if parsed < minimum or parsed > maximum:
        raise ValueError(f"{name} is outside the allowed range.")
    return parsed
