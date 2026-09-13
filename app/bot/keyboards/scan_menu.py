from telegram import InlineKeyboardButton, InlineKeyboardMarkup


SCAN_TOOL_LAYOUT = (
    (("Nmap Scan", "nmap"), ("Nuclei Scan", "nuclei"), ("BBOT Recon", "bbot")),
    (("httpx Fingerprint", "httpx"), ("Katana Crawl", "katana"), ("Playwright Observe", "playwright")),
    (("ffuf Discovery", "ffuf"), ("testssl.sh TLS", "testssl"), ("Gitleaks Secrets", "gitleaks")),
    (("Prowler Cloud", "prowler"), ("Metasploit Validation", "metasploit"), ("TShark PCAP", "tshark")),
)


def build_scan_tool_rows(callback_for_tool) -> list[list[InlineKeyboardButton]]:
    return [
        [InlineKeyboardButton(label, callback_data=callback_for_tool(tool)) for label, tool in row]
        for row in SCAN_TOOL_LAYOUT
    ]


def build_scan_type_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        build_scan_tool_rows(lambda tool: f"scan:{tool}") + [
            [InlineKeyboardButton("Back", callback_data="nav:home")],
        ]
    )
