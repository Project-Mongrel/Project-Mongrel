from app.ui.icons import ICONS, icon


def test_icons_contains_required_keys() -> None:
    required_keys = {
        "scan",
        "target",
        "status",
        "running",
        "elapsed",
        "risk",
        "summary",
        "findings",
        "assets",
        "ai",
        "report",
        "success",
        "warning",
        "error",
        "info",
        "settings",
        "upload",
        "history",
        "home",
        "cancel",
        "back",
        "complete",
        "comparison",
        "impact",
    }

    assert required_keys <= set(ICONS)


def test_icon_returns_empty_string_for_unknown_key() -> None:
    assert icon("unknown") == ""
