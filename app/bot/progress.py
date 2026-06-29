import asyncio
import logging
from collections.abc import Sequence

from telegram.error import BadRequest, NetworkError, RetryAfter, TimedOut

SPINNER_FRAMES = ("/", "-", "\\", "|")
DEFAULT_PROGRESS_INTERVAL_SECONDS = 1.75
logger = logging.getLogger(__name__)


def build_spinner_frames(label: str, frames: Sequence[str] = SPINNER_FRAMES) -> list[str]:
    return [f"{label} {frame}" for frame in frames]


async def safe_edit_text(target: object, text: str, *, context: str = "Telegram progress") -> None:
    edit_method = getattr(target, "edit_text", None) or getattr(target, "edit_message_text", None)
    if edit_method is None:
        return

    try:
        await edit_method(text)
    except RetryAfter as exc:
        logger.warning("%s edit was rate limited: %s", context, exc)
    except TimedOut as exc:
        logger.warning("%s edit timed out: %s", context, exc)
    except NetworkError as exc:
        logger.warning("%s edit failed due to Telegram network error: %s", context, exc)
    except BadRequest as exc:
        logger.warning("%s edit was rejected by Telegram: %s", context, exc)
    except Exception:
        logger.warning("%s edit failed unexpectedly.", context, exc_info=True)


async def run_progress_frames(
    target: object,
    frames: Sequence[str],
    stop_event: asyncio.Event,
    *,
    interval_seconds: float = DEFAULT_PROGRESS_INTERVAL_SECONDS,
    start_index: int = 0,
    context: str = "Telegram progress",
) -> None:
    if not frames:
        return

    frame_index = start_index
    while not stop_event.is_set():
        await safe_edit_text(target, frames[frame_index % len(frames)], context=context)
        frame_index += 1
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
        except TimeoutError:
            continue
