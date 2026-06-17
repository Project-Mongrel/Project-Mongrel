from telegram import KeyboardButton, ReplyKeyboardMarkup

MAIN_MENU_BUTTONS: tuple[str, ...] = (
    "Home",
    "Scan",
    "Upload",
    "Findings",
    "Ask Mongrel",
    "Reports",
    "Settings",
)


def build_main_menu_keyboard() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        [
            [KeyboardButton("Home"), KeyboardButton("Scan"), KeyboardButton("Upload")],
            [KeyboardButton("Findings"), KeyboardButton("Ask Mongrel")],
            [KeyboardButton("Reports"), KeyboardButton("Settings")],
        ],
        resize_keyboard=True,
        is_persistent=True,
    )
