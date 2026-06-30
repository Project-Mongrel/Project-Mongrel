from app.ui.ai_summary import render_ai_summary_card
from app.ui.icons import icon


def test_render_ai_summary_card_formats_headings_without_colons() -> None:
    card = render_ai_summary_card(
        [
            "Executive Summary:",
            "- Evidence reviewed.",
            "",
            "Observed Facts:",
            "- SSH service exposed.",
            "",
            "Confidence:",
            "Low",
        ]
    )

    assert card.startswith(f"{icon('ai')} AI Summary".strip())
    assert "Executive Summary:" not in card
    assert "Observed Facts:" not in card
    assert "Confidence:" not in card
    assert "Executive Summary\n- Evidence reviewed." in card
    assert "Observed Facts\n- SSH service exposed." in card
    assert "Confidence\nLow" in card


def test_render_ai_summary_card_hides_empty_sections() -> None:
    card = render_ai_summary_card(["Executive Summary", "- Evidence reviewed."])

    assert "Executive Summary" in card
    assert "Potential Risks" not in card
