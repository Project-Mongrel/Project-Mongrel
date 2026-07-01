import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from app.ui.scan_progress import ScanProgressCard
from app.ui.scan_progress import render_scan_loading_card
from app.ui.icons import icon


def test_render_scan_loading_card_uses_universal_layout() -> None:
    assert render_scan_loading_card("Nmap Scan", "scanme.nmap.org", "Launching scan...", 7) == (
        " Nmap Scan\n\n"
        f"{icon('target')} Target\nscanme.nmap.org\n\n"
        f"{icon('running')} Status\nLaunching scan...\n\n"
        f"{icon('elapsed')} Elapsed\n7s"
    )


def test_render_scan_loading_card_uses_success_icon_when_complete() -> None:
    assert f"{icon('success')} Status\nComplete" in render_scan_loading_card(
        "Nmap Scan",
        "scanme.nmap.org",
        "Complete",
        9,
    )


def test_render_scan_loading_card_uses_terminal_icon_for_partial_and_failed() -> None:
    assert f"{icon('success')} Status\nPartial" in render_scan_loading_card(
        "BBOT Scan",
        "example.com",
        "Partial",
        19,
    )
    assert f"{icon('success')} Status\nFailed" in render_scan_loading_card(
        "BBOT Scan",
        "example.com",
        "Failed",
        19,
    )


def test_scan_progress_auto_refresh_updates_elapsed_and_cleans_up() -> None:
    async def run_test() -> None:
        status_message = SimpleNamespace(edit_text=AsyncMock())
        card = ScanProgressCard.from_status_message(status_message, "BBOT Scan", "example.com", started_at=100.0)
        real_sleep = asyncio.sleep
        monotonic_value = 100.0

        async def fast_sleep(_: float) -> None:
            await real_sleep(0)

        def fake_monotonic() -> float:
            nonlocal monotonic_value
            monotonic_value += 5.0
            return monotonic_value

        with (
            patch("app.ui.scan_progress.asyncio.sleep", side_effect=fast_sleep),
            patch("app.ui.scan_progress.time.monotonic", side_effect=fake_monotonic),
        ):
            await card.start_auto_refresh("Launching scan...", interval_seconds=5)
            for _ in range(20):
                if status_message.edit_text.await_count >= 3:
                    break
                await real_sleep(0)
            await card.stop_auto_refresh()

        assert card._refresh_task is None
        assert status_message.edit_text.await_count >= 3
        rendered_updates = [call.args[0] for call in status_message.edit_text.call_args_list]
        assert all("Launching scan..." in update for update in rendered_updates)
        elapsed_values = [
            int(update.rsplit("Elapsed\n", 1)[1].removesuffix("s"))
            for update in rendered_updates
        ]
        assert elapsed_values == sorted(elapsed_values)
        assert len(set(elapsed_values)) >= 2

    asyncio.run(run_test())


def test_scan_progress_complete_stops_auto_refresh_task() -> None:
    async def run_test() -> None:
        status_message = SimpleNamespace(edit_text=AsyncMock())
        card = ScanProgressCard.from_status_message(status_message, "BBOT Scan", "example.com", started_at=100.0)
        real_sleep = asyncio.sleep

        async def fast_sleep(_: float) -> None:
            await real_sleep(0)

        with patch("app.ui.scan_progress.asyncio.sleep", side_effect=fast_sleep):
            await card.start_auto_refresh("Launching scan...", interval_seconds=5)
            await real_sleep(0)
            await card.complete()

        assert card._refresh_task is None
        assert f"{icon('success')} Status\nComplete" in status_message.edit_text.call_args_list[-1].args[0]

    asyncio.run(run_test())


def test_scan_progress_partial_stops_auto_refresh_task() -> None:
    async def run_test() -> None:
        status_message = SimpleNamespace(edit_text=AsyncMock())
        card = ScanProgressCard.from_status_message(status_message, "BBOT Scan", "example.com", started_at=100.0)
        real_sleep = asyncio.sleep

        async def fast_sleep(_: float) -> None:
            await real_sleep(0)

        with patch("app.ui.scan_progress.asyncio.sleep", side_effect=fast_sleep):
            await card.start_auto_refresh("Launching scan...", interval_seconds=5)
            await real_sleep(0)
            await card.partial()

        assert card._refresh_task is None
        assert f"{icon('success')} Status\nPartial" in status_message.edit_text.call_args_list[-1].args[0]

    asyncio.run(run_test())
