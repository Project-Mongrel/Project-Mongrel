from app.ui.scan_progress import render_scan_loading_card
from app.ui.icons import icon


def test_render_scan_loading_card_uses_universal_layout() -> None:
    assert render_scan_loading_card("Nmap Scan", "scanme.nmap.org", "Launching scan...", 7) == (
        " Nmap Scan\n\n"
        " Target\nscanme.nmap.org\n\n"
        f"{icon('running')} Status\nLaunching scan...\n\n"
        f"{icon('elapsed')} Elapsed\n7s"
    )
