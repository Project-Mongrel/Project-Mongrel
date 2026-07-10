from telegram import InlineKeyboardButton, InlineKeyboardMarkup


def build_scan_type_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("Nmap Scan", callback_data="scan:nmap"),
                InlineKeyboardButton("Nuclei Scan", callback_data="scan:nuclei"),
                InlineKeyboardButton("BBOT Recon", callback_data="scan:bbot"),
            ],
            [InlineKeyboardButton("httpx Fingerprint", callback_data="scan:httpx")],
            [InlineKeyboardButton("Katana Crawl", callback_data="scan:katana")],
            [InlineKeyboardButton("Playwright Observe", callback_data="scan:playwright")],
            [InlineKeyboardButton("ffuf Discovery", callback_data="scan:ffuf")],
            [InlineKeyboardButton("testssl.sh TLS", callback_data="scan:testssl")],
            [InlineKeyboardButton("Gitleaks Secrets", callback_data="scan:gitleaks")],
            [InlineKeyboardButton("Prowler Cloud", callback_data="scan:prowler")],
            [InlineKeyboardButton("Metasploit Validation", callback_data="scan:metasploit")],
            [InlineKeyboardButton("TShark PCAP", callback_data="scan:tshark")],
            [InlineKeyboardButton("Back", callback_data="nav:home")],
        ]
    )
