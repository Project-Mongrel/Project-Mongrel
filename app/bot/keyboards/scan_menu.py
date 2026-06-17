from telegram import InlineKeyboardButton, InlineKeyboardMarkup


def build_scan_type_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("Nmap", callback_data="scan:nmap"),
                InlineKeyboardButton("Nuclei", callback_data="scan:nuclei"),
                InlineKeyboardButton("BBOT", callback_data="scan:bbot"),
            ],
            [InlineKeyboardButton("Back", callback_data="nav:home")],
        ]
    )
