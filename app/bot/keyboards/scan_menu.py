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
            [InlineKeyboardButton("Back", callback_data="nav:home")],
        ]
    )
