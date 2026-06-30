from app.ui.icons import icon

DEFAULT_LIST_LIMIT = 5


def cap_list(items: list[str], limit: int = DEFAULT_LIST_LIMIT) -> list[str]:
    cleaned_items = [str(item).strip() for item in items if str(item).strip()]
    if limit < 1 or len(cleaned_items) <= limit:
        return cleaned_items

    visible_items = cleaned_items[:limit]
    visible_items.append(f"+{len(cleaned_items) - limit} more")
    return visible_items


def render_section(title: str, body: str | list[str] | None, icon_name: str | None = None) -> str:
    if body is None:
        return ""

    if isinstance(body, list):
        lines = cap_list(body)
        if not lines:
            return ""
        content = "\n".join(f"- {line}" if not line.startswith(("-", "+")) else line for line in lines)
    else:
        content = str(body).strip()
        if not content:
            return ""

    return "\n".join([_label(icon_name, title), content])


def render_scan_result_card(
    *,
    tool_name: str,
    target: str,
    status: str = "Complete",
    elapsed: str | None = None,
    risk: str | None = None,
    summary: str | None = None,
    findings: list[str] | str | None = None,
    assets: list[str] | str | None = None,
    ai_assessment: str | None = None,
) -> str:
    sections = [
        _label("scan", f"{tool_name} Scan Complete"),
        "",
        render_section("Target", target or "unknown", "target"),
        "",
        render_section("Status", status, "status"),
    ]
    optional_sections = [
        render_section("Time", elapsed, "elapsed"),
        render_section("Risk", risk, "risk"),
        render_section("Summary", summary, "summary"),
        render_section("Findings", findings, "findings"),
        render_section("Observed Assets", assets, "assets"),
        render_section("AI Assessment", ai_assessment, "ai"),
    ]
    for section in optional_sections:
        if section:
            sections.extend(["", section])

    return "\n".join(sections)


def _label(icon_name: str | None, title: str) -> str:
    symbol = icon(icon_name or "")
    return f"{symbol} {title}" if symbol else title
