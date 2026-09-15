from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from app.services.mongrel_self_knowledge import get_mongrel_tool_names


TOOL_MODE_ACTION_PREFIX = "toolmode"
TOOL_MODE_TOOLS = tuple(name.lower().removesuffix(".sh") for name in get_mongrel_tool_names())


def build_tool_mode_post_scan_keyboard(tool: str) -> InlineKeyboardMarkup:
    normalized = str(tool or "").strip().lower().removesuffix(".sh")
    if normalized not in TOOL_MODE_TOOLS:
        raise ValueError("Unsupported Tool Mode tool.")
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔄 Run Again", callback_data=f"scan:{normalized}")],
        [InlineKeyboardButton("✦ Ask Mongrel", callback_data=f"{TOOL_MODE_ACTION_PREFIX}:ask")],
        [InlineKeyboardButton("⬅️ Back to Tools", callback_data=f"{TOOL_MODE_ACTION_PREFIX}:back")],
    ])
