ICONS = {
    "nmap": "⌁",
    "nuclei": "◇",
    "bbot": "◆",
    "observation": "◌",
    "attack_path": "⟶",
    "mongrel_ai": "✦",
    "report": "▣",
    "investigation": "▤",
    "risk": "⚠",
    "completed": "✓",
    "running": "⏳",
    "saved": "▥",
    "upload": "⇧",
    "statistics": "▦",
    "target": "◎",
    "security": "⌾",
}


def icon(name: str) -> str:
    return ICONS.get(name, "")


def icon_label(name: str, text: str) -> str:
    symbol = icon(name)
    return f"{symbol} {text}" if symbol else text


def section_label(name: str, text: str) -> str:
    symbol = icon(name)
    return f"{text} {symbol}" if symbol else text
