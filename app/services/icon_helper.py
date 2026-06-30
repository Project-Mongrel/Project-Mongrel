from app.ui.icons import ICONS, icon


def icon_label(name: str, text: str) -> str:
    symbol = icon(name)
    return f"{symbol} {text}" if symbol else text


def section_label(name: str, text: str) -> str:
    symbol = icon(name)
    return f"{text} {symbol}" if symbol else text
