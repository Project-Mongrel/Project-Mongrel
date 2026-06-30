import time

from app.bot.progress import safe_edit_text
from app.ui.icons import icon


def render_scan_loading_card(title: str, target: str, status: str, elapsed_seconds: int) -> str:
    status_icon = icon("success") if str(status or "").strip().lower() == "complete" else icon("running")
    return (
        f" {title}\n\n"
        f"{icon('target')} Target\n{target or 'unknown'}\n\n"
        f"{status_icon} Status\n{status}\n\n"
        f"{icon('elapsed')} Elapsed\n{elapsed_seconds}s"
    )


class ScanProgressCard:
    def __init__(self, message: object | None, title: str, target: str, *, started_at: float | None = None) -> None:
        self.message = message
        self.title = title
        self.target = target
        self.started_at = time.monotonic() if started_at is None else started_at
        self.status_message: object | None = None

    @classmethod
    def from_status_message(cls, status_message: object, title: str, target: str, started_at: float) -> "ScanProgressCard":
        card = cls(None, title, target, started_at=started_at)
        card.status_message = status_message
        return card

    def elapsed_seconds(self) -> int:
        return max(0, int(time.monotonic() - self.started_at))

    async def start(self, status: str) -> object | None:
        reply_text = getattr(self.message, "reply_text", None)
        if reply_text is None:
            return None

        self.status_message = await reply_text(self.render(status))
        return self.status_message

    async def update(self, status: str) -> None:
        if self.status_message is None:
            return

        await safe_edit_text(self.status_message, self.render(status), context=f"{self.title} progress")

    async def complete(self, final_text: str | None = None) -> None:
        await self.update("Complete")
        if final_text and self.message is not None:
            reply_text = getattr(self.message, "reply_text", None)
            if reply_text is not None:
                await reply_text(final_text)

    async def fail(self, error_text: str) -> None:
        status = f"Failed: {error_text}" if error_text else "Failed"
        await self.update(status)

    def render(self, status: str) -> str:
        return render_scan_loading_card(self.title, self.target, status, self.elapsed_seconds())
