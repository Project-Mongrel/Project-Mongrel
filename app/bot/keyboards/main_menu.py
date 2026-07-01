from telegram import KeyboardButton, ReplyKeyboardMarkup

MAIN_MENU_BUTTONS: tuple[str, ...] = (
    "Home",
    "New Assessment",
    "Scan",
    "Upload Findings",
    "Findings",
    "Ask Mongrel",
    "Reports",
    "Settings",
    "Cancel",
)


def build_main_menu_keyboard() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        [
            [KeyboardButton("Home"), KeyboardButton("New Assessment"), KeyboardButton("Scan")],
            [KeyboardButton("Upload Findings"), KeyboardButton("Findings")],
            [KeyboardButton("Ask Mongrel"), KeyboardButton("Reports")],
            [KeyboardButton("Settings"), KeyboardButton("Cancel")],
        ],
        resize_keyboard=True,
        is_persistent=True,
    )
