import hashlib
import json
import re
from dataclasses import dataclass

from app.tools.nmap_runner import DANGEROUS_SHELL_CHARACTERS

SUPPORTED_ACTION_TYPES = frozenset({"check", "auxiliary_validation", "exploit_validation"})
SAFE_OPTION_VALUE_PATTERN = re.compile(r"^[A-Za-z0-9._:/@%+=,\-\s]{0,200}$")
SAFE_TARGET_PATTERN = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
SAFE_MODULE_PATTERN = re.compile(r"^(auxiliary|exploit)/[A-Za-z0-9_/-]{3,160}$")


@dataclass(frozen=True)
class MetasploitModulePolicy:
    module: str
    supported_actions: frozenset[str]
    approved_options: frozenset[str]
    risk_tier: str
    expected_effect: str
    default_timeout_seconds: int = 300


MODULE_POLICIES: dict[str, MetasploitModulePolicy] = {
    "auxiliary/scanner/http/http_version": MetasploitModulePolicy(
        module="auxiliary/scanner/http/http_version",
        supported_actions=frozenset({"auxiliary_validation"}),
        approved_options=frozenset({"SSL", "TARGETURI", "VHOST"}),
        risk_tier="low",
        expected_effect="Collect HTTP service banner/version metadata from the authorized target.",
        default_timeout_seconds=120,
    ),
    "auxiliary/scanner/ssh/ssh_version": MetasploitModulePolicy(
        module="auxiliary/scanner/ssh/ssh_version",
        supported_actions=frozenset({"auxiliary_validation"}),
        approved_options=frozenset({"RHOSTS"}),
        risk_tier="low",
        expected_effect="Collect SSH service banner/version metadata from the authorized target.",
        default_timeout_seconds=120,
    ),
    "exploit/multi/http/struts2_content_type_ognl": MetasploitModulePolicy(
        module="exploit/multi/http/struts2_content_type_ognl",
        supported_actions=frozenset({"check", "exploit_validation"}),
        approved_options=frozenset({"SSL", "TARGETURI", "VHOST"}),
        risk_tier="high",
        expected_effect="Validate whether the authorized target appears affected by the selected module. Exploit validation must not request sessions or post-exploitation.",
        default_timeout_seconds=180,
    ),
}


def build_metasploit_action_request(
    *,
    module: str,
    action_type: str,
    target: str,
    port: int,
    options: dict[str, object] | None = None,
    timeout_seconds: int | None = None,
) -> dict:
    normalized_module = _normalize_module(module)
    policy = MODULE_POLICIES.get(normalized_module)
    if policy is None:
        raise ValueError("Unsupported Metasploit module.")

    normalized_action = str(action_type or "").strip().lower()
    if normalized_action not in SUPPORTED_ACTION_TYPES or normalized_action not in policy.supported_actions:
        raise ValueError("Unsupported Metasploit action for module.")

    normalized_target = _normalize_target(target)
    normalized_port = _normalize_port(port)
    normalized_options = _normalize_options(options or {}, policy)
    normalized_timeout = _normalize_timeout(timeout_seconds, policy)
    request = {
        "module": normalized_module,
        "action_type": normalized_action,
        "target": normalized_target,
        "port": normalized_port,
        "options": normalized_options,
        "risk_tier": policy.risk_tier,
        "expected_effect": policy.expected_effect,
        "timeout_seconds": normalized_timeout,
    }
    request["fingerprint"] = metasploit_request_fingerprint(request)
    return request


def metasploit_request_fingerprint(request: dict) -> str:
    canonical = {
        "module": request.get("module"),
        "action_type": request.get("action_type"),
        "target": request.get("target"),
        "port": int(request.get("port") or 0),
        "options": dict(sorted((request.get("options") or {}).items())),
        "risk_tier": request.get("risk_tier"),
        "expected_effect": request.get("expected_effect"),
        "timeout_seconds": int(request.get("timeout_seconds") or 0),
    }
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _normalize_module(module: str) -> str:
    normalized = str(module or "").strip()
    if not SAFE_MODULE_PATTERN.fullmatch(normalized) or ".." in normalized or any(character in normalized for character in DANGEROUS_SHELL_CHARACTERS):
        raise ValueError("Malformed Metasploit module.")
    return normalized


def _normalize_target(target: str) -> str:
    normalized = str(target or "").strip()
    if not SAFE_TARGET_PATTERN.fullmatch(normalized) or any(character in normalized for character in DANGEROUS_SHELL_CHARACTERS):
        raise ValueError("Malformed Metasploit target.")
    return normalized


def _normalize_port(port: int) -> int:
    try:
        value = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError("Metasploit port must be an integer.") from exc
    if value < 1 or value > 65535:
        raise ValueError("Metasploit port is outside the valid range.")
    return value


def _normalize_options(options: dict[str, object], policy: MetasploitModulePolicy) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in sorted(options.items()):
        option_name = str(key or "").strip().upper()
        if option_name not in policy.approved_options:
            raise ValueError("Unsupported Metasploit option for module.")
        option_value = str(value or "").strip()
        if "\n" in option_value or "\r" in option_value or any(character in option_value for character in DANGEROUS_SHELL_CHARACTERS):
            raise ValueError("Malformed Metasploit option value.")
        if not SAFE_OPTION_VALUE_PATTERN.fullmatch(option_value):
            raise ValueError("Malformed Metasploit option value.")
        normalized[option_name] = option_value
    return normalized


def _normalize_timeout(timeout_seconds: int | None, policy: MetasploitModulePolicy) -> int:
    value = policy.default_timeout_seconds if timeout_seconds is None else int(timeout_seconds)
    if value < 10 or value > 900:
        raise ValueError("Metasploit timeout is outside the allowed range.")
    return value
