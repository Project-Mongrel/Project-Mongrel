from app.ui.icons import icon
from app.ui.result_cards import render_section

AI_SUMMARY_SECTIONS = (
    "Executive Summary",
    "Observed Facts",
    "Observed Assets",
    "Potential Risks",
    "Confidence",
    "Recommended Next Actions",
)


def render_ai_summary_card(summary: str | list[str], title: str = "AI Summary") -> str:
    lines = summary if isinstance(summary, list) else str(summary or "").splitlines()
    sections = _parse_sections([str(line).rstrip() for line in lines])
    title_icon = icon("ai")
    rendered = [f"{title_icon} {title}".strip()]

    for section_title in AI_SUMMARY_SECTIONS:
        body = sections.get(section_title, [])
        section = render_section(section_title, "\n".join(body).strip())
        if section:
            rendered.extend(["", section])

    if len(rendered) == 1:
        fallback = "\n".join(line for line in lines if str(line).strip()).strip()
        if fallback:
            rendered.extend(["", render_section("Executive Summary", fallback)])

    return "\n".join(rendered)


def _parse_sections(lines: list[str]) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {section: [] for section in AI_SUMMARY_SECTIONS}
    current_section: str | None = None

    for line in lines:
        stripped = line.strip()
        normalized_heading = stripped.rstrip(":")
        if normalized_heading in sections and not stripped.startswith(("-", "•", "*")):
            current_section = normalized_heading
            continue
        if current_section is None:
            continue
        if stripped or sections[current_section]:
            sections[current_section].append(stripped)

    return {title: _trim_blank_lines(body) for title, body in sections.items()}


def _trim_blank_lines(lines: list[str]) -> list[str]:
    trimmed = list(lines)
    while trimmed and not trimmed[0].strip():
        trimmed.pop(0)
    while trimmed and not trimmed[-1].strip():
        trimmed.pop()
    return trimmed
