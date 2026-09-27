from collections import Counter

from app.services.icon_helper import icon_label, section_label
from app.services.observation_store import get_investigation_observations, get_user_observations
from app.services.target_normalizer import normalize_target_key

ASSET_TYPES = (
    "subdomain",
    "url",
    "ip_address",
    "open_port",
    "dns_record",
    "technology",
    "certificate",
    "email",
)
ASSET_LABELS = {
    "subdomain": "subdomains",
    "url": "URLs",
    "ip_address": "IP addresses",
    "open_port": "open ports",
    "dns_record": "DNS records",
    "technology": "technologies",
    "certificate": "certificates",
    "email": "email addresses",
}
DISCOVERY_TYPES = ("subdomain", "url", "ip_address", "open_port", "technology", "certificate", "email", "dns_record")
ADMIN_HOST_TOKENS = {"admin", "auth", "login", "manage", "management", "portal", "vpn", "staging"}
MAX_DISCOVERIES = 8


def build_bbot_recon_summary(
    user_id,
    investigation_id=None,
    target=None,
    completed_tools: set[str] | None = None,
):
    observations = _load_bbot_observations(user_id, investigation_id=investigation_id, target=target)
    return build_bbot_recon_summary_from_observations(observations, target=target, completed_tools=completed_tools)


def build_bbot_recon_summary_from_observations(
    observations: list[dict],
    target=None,
    completed_tools: set[str] | None = None,
) -> str:
    target_label = _summary_target(target, observations)
    counts = Counter(str(observation.get("observation_type") or "") for observation in observations)
    discoveries = _interesting_discoveries(observations)
    recommendations = _recommended_actions(observations, completed_tools=completed_tools)

    lines = [
        section_label("bbot", "BBOT Recon Summary"),
        "",
        icon_label("target", "Target:"),
        target_label,
        "",
        "Recon Overview",
        "",
        f"Observations Collected: {len(observations)}",
        "",
        icon_label("statistics", "Assets"),
        "",
    ]
    lines.extend(f"{counts.get(asset_type, 0)} {ASSET_LABELS[asset_type]}" for asset_type in ASSET_TYPES)
    lines.extend(["", icon_label("observation", "Interesting Discoveries"), ""])
    if discoveries:
        lines.extend(discoveries)
    else:
        lines.append("No significant BBOT discoveries stored yet.")

    lines.extend(["", icon_label("risk", "Recommended Next Actions"), ""])
    lines.extend(recommendations)
    return "\n".join(lines)


def _load_bbot_observations(user_id: int, investigation_id: str | None, target: str | None) -> list[dict]:
    if investigation_id:
        observations = get_investigation_observations(str(investigation_id), int(user_id))
    else:
        observations = get_user_observations(int(user_id))

    target_key = normalize_target_key(target)
    filtered = [observation for observation in observations if observation.get("source") == "bbot"]
    if target_key is not None:
        filtered = [
            observation
            for observation in filtered
            if (observation.get("target_key") or normalize_target_key(observation.get("target"))) == target_key
        ]

    return filtered


def _summary_target(target: str | None, observations: list[dict]) -> str:
    if target:
        return str(target)
    for observation in observations:
        if observation.get("target"):
            return str(observation["target"])
    return "unknown"


def _interesting_discoveries(observations: list[dict]) -> list[str]:
    values = []
    seen = set()
    priority_observations = sorted(
        observations,
        key=lambda observation: DISCOVERY_TYPES.index(str(observation.get("observation_type")))
        if str(observation.get("observation_type")) in DISCOVERY_TYPES
        else len(DISCOVERY_TYPES),
    )
    for observation in priority_observations:
        observation_type = str(observation.get("observation_type") or "")
        value = str(observation.get("value") or "").strip()
        key = (observation_type, value.lower())
        if observation_type not in DISCOVERY_TYPES or not value or key in seen:
            continue
        seen.add(key)
        values.append(value)
        if len(values) >= MAX_DISCOVERIES:
            break
    return values


def _recommended_actions(observations: list[dict], completed_tools: set[str] | None = None) -> list[str]:
    types = {str(observation.get("observation_type") or "") for observation in observations}
    values = [str(observation.get("value") or "") for observation in observations]
    completed = {str(tool or "").strip().lower().removesuffix(".sh") for tool in (completed_tools or set())}
    recommendations = []
    if ("subdomain" in types or "url" in types) and "nuclei" not in completed:
        recommendations.append("Run Nuclei against discovered domains or URLs where authorized.")
    if "technology" in types:
        recommendations.append("Review observed technologies and versions against current advisories where version evidence exists.")
    if "certificate" in types:
        recommendations.append("Review certificate validity and intended exposure.")
    if any(_is_admin_like_host(value) for value in values):
        recommendations.append("Review authentication requirements and intended exposure for admin-like hostnames.")
    if not recommendations:
        if completed_tools is None:
            recommendations.append("Continue reconnaissance using additional observation sources.")
        else:
            recommendations.append("Review the discovered reconnaissance evidence and ask Mongrel for assessment-aware next steps if needed.")
    return recommendations


def _is_admin_like_host(value: str) -> bool:
    labels = value.lower().replace("://", ".").replace("/", ".").split(".")
    return any(label in ADMIN_HOST_TOKENS for label in labels)
