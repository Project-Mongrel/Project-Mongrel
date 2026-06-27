import json

from app.services.ai_client import ask_ai
from app.services.bbot_summary import build_bbot_recon_summary
from app.services.investigation_store import get_investigation
from app.services.observation_store import get_investigation_observations, get_user_observations
from app.services.target_normalizer import normalize_target_key

AI_UNAVAILABLE_MESSAGES = (
    "AI integration is not configured yet.",
    "Unsupported AI provider.",
    "Ollama base URL is not configured.",
    "AI request timed out.",
    "Unable to connect to Ollama server.",
    "AI request failed.",
    "Malformed Ollama response.",
    "Empty AI response.",
    "Mongrel generated internal reasoning but no final answer.",
)
FALLBACK_LINES = [
    "AI recon assessment unavailable.",
    "Use the deterministic BBOT Recon Summary for next actions.",
]


def generate_bbot_ai_assessment(
    user_id,
    investigation_id=None,
    target=None,
) -> list[str]:
    observations = _load_bbot_observations(int(user_id), investigation_id=investigation_id, target=target)
    summary = build_bbot_recon_summary(user_id=user_id, investigation_id=investigation_id, target=target)
    investigation = get_investigation(str(investigation_id), int(user_id)) if investigation_id else None

    if not observations:
        return [
            "AI Recon Assessment",
            "",
            "Overall Recon Posture:",
            "UNKNOWN",
            "",
            "Key Observations:",
            "- No stored BBOT observations are available for this scope.",
            "",
            "Why It Matters:",
            "- Evidence is limited, so no meaningful reconnaissance posture can be assessed.",
            "",
            "Priority Follow-Up:",
            "- Use the deterministic BBOT Recon Summary and consider collecting additional observations.",
            "",
            "Confidence:",
            "LOW",
            "",
            "Evidence Limitations:",
            "- Assessment is limited because the Observation Store contains no BBOT observations for this scope.",
        ]

    prompt = build_bbot_ai_assessment_prompt(
        observations=observations,
        recon_summary=summary,
        investigation=investigation,
        target=target,
    )
    try:
        response = ask_ai(prompt)
    except Exception:
        return list(FALLBACK_LINES)

    if _is_unavailable_response(response):
        return list(FALLBACK_LINES)

    cleaned_response = str(response or "").strip()
    if not cleaned_response:
        return list(FALLBACK_LINES)

    return cleaned_response.splitlines()


def build_bbot_ai_assessment_prompt(
    observations: list[dict],
    recon_summary: str,
    investigation: dict | None = None,
    target: str | None = None,
) -> str:
    return "\n".join(
        [
            "Create a grounded AI Recon Assessment for BBOT reconnaissance.",
            "",
            "Rules:",
            "- Only use the supplied observations and recon summary.",
            "- Do not invent vulnerabilities.",
            "- Do not claim compromise.",
            "- Do not recommend exploitation.",
            "- Do not say a service is vulnerable unless evidence supports it.",
            "- Use cautious language such as review, verify, consider, prioritize, and may indicate.",
            "- If evidence is limited, say so.",
            "- Include confidence level.",
            "- Return final answer only.",
            "",
            "Required sections:",
            "AI Recon Assessment",
            "Overall Recon Posture:",
            "Key Observations:",
            "Why It Matters:",
            "Priority Follow-Up:",
            "Confidence:",
            "Evidence Limitations:",
            "",
            "Target:",
            str(target or _target_from_observations(observations) or "unknown"),
            "",
            "Investigation Context:",
            _format_investigation_context(investigation),
            "",
            "Deterministic BBOT Recon Summary:",
            recon_summary,
            "",
            "Stored Observations:",
            _format_observations(observations),
        ]
    )


def _load_bbot_observations(user_id: int, investigation_id: str | None, target: str | None) -> list[dict]:
    if investigation_id:
        observations = get_investigation_observations(str(investigation_id), user_id)
    else:
        observations = get_user_observations(user_id)

    target_key = normalize_target_key(target)
    filtered = [observation for observation in observations if observation.get("source") == "bbot"]
    if target_key is not None:
        filtered = [
            observation
            for observation in filtered
            if (observation.get("target_key") or normalize_target_key(observation.get("target"))) == target_key
        ]
    return filtered


def _format_investigation_context(investigation: dict | None) -> str:
    if investigation is None:
        return "No investigation metadata supplied."

    context = {
        "id": investigation.get("id"),
        "name": investigation.get("name"),
        "target": investigation.get("target"),
        "status": investigation.get("status"),
        "overall_risk": investigation.get("overall_risk"),
        "summary": investigation.get("summary"),
    }
    return json.dumps(context, sort_keys=True, default=str)


def _format_observations(observations: list[dict]) -> str:
    formatted = []
    for observation in observations:
        formatted.append(
            {
                "source": observation.get("source"),
                "type": observation.get("observation_type"),
                "value": observation.get("value"),
                "target": observation.get("target"),
                "confidence": observation.get("confidence"),
                "risk_level": observation.get("risk_level"),
                "summary": observation.get("summary"),
            }
        )
    return json.dumps(formatted, sort_keys=True, default=str)


def _target_from_observations(observations: list[dict]) -> str | None:
    for observation in observations:
        if observation.get("target"):
            return str(observation["target"])
    return None


def _is_unavailable_response(response: str) -> bool:
    normalized = str(response or "").strip()
    return any(normalized.startswith(message) for message in AI_UNAVAILABLE_MESSAGES)
