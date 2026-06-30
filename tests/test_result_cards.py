from app.ui.icons import icon
from app.ui.result_cards import cap_list, render_scan_result_card, render_section


def test_render_section_hides_empty_values() -> None:
    assert render_section("Findings", None) == ""
    assert render_section("Findings", "") == ""
    assert render_section("Findings", []) == ""


def test_cap_list_caps_long_lists() -> None:
    assert cap_list(["one", "two", "three"], limit=2) == ["one", "two", "+1 more"]


def test_render_scan_result_card_includes_standard_sections() -> None:
    card = render_scan_result_card(
        tool_name="Nmap",
        target="scanme.nmap.org",
        elapsed="1s",
        risk="LOW",
        summary="Host is up.",
        findings=["22/tcp ssh"],
        assets=["scanme.nmap.org"],
    )

    assert "Nmap Scan Complete" in card
    assert "Target\nscanme.nmap.org" in card
    assert f"{icon('status')} Status\nComplete" in card
    assert f"{icon('elapsed')} Time\n1s" in card
    assert f"{icon('risk')} Risk\nLOW" in card
    assert "Summary\nHost is up." in card
    assert "Findings\n- 22/tcp ssh" in card
    assert "Observed Assets\n- scanme.nmap.org" in card


def test_render_scan_result_card_omits_empty_sections() -> None:
    card = render_scan_result_card(tool_name="BBOT", target="example.com")

    assert "Summary" not in card
    assert "Findings" not in card
    assert "Observed Assets" not in card


def test_render_scan_result_card_caps_lists() -> None:
    card = render_scan_result_card(
        tool_name="Nuclei",
        target="example.com",
        findings=["one", "two", "three", "four", "five", "six"],
    )

    assert "+1 more" in card
