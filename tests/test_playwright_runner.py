import builtins
import sys
import types
from unittest.mock import patch

from app.core.config import Settings
from app.parsers.playwright_parser import normalize_playwright_observation, summarize_playwright_observation
from app.tools.playwright_runner import run_playwright_observation


class FakePlaywrightError(Exception):
    pass


class FakePlaywrightTimeoutError(Exception):
    pass


class FakeRequest:
    def __init__(self, url: str, redirected_from: object | None = None) -> None:
        self.url = url
        self._redirected_from = redirected_from

    def redirected_from(self) -> object | None:
        return self._redirected_from


class FakeResponse:
    def __init__(self) -> None:
        self.status = 200
        self.request = FakeRequest("https://example.com/final", FakeRequest("https://example.com/start"))


class FakeLocator:
    def __init__(self, count: int) -> None:
        self._count = count

    def count(self) -> int:
        return self._count


class FakeConsoleMessage:
    type = "error"


class FakePage:
    url = "https://example.com/final"

    def __init__(self, *, timeout_on_goto: bool = False) -> None:
        self.handlers = {}
        self.timeout_on_goto = timeout_on_goto

    def set_default_timeout(self, _: int) -> None:
        return None

    def set_default_navigation_timeout(self, _: int) -> None:
        return None

    def on(self, event: str, handler: object) -> None:
        self.handlers[event] = handler

    def goto(self, *_: object, **__: object) -> FakeResponse:
        if self.timeout_on_goto:
            raise FakePlaywrightTimeoutError("timeout")
        self.handlers["console"](FakeConsoleMessage())
        self.handlers["requestfailed"](object())
        return FakeResponse()

    def wait_for_load_state(self, *_: object, **__: object) -> None:
        return None

    def title(self) -> str:
        return "Example"

    def locator(self, selector: str) -> FakeLocator:
        counts = {"form": 2, "input, textarea, select, button": 5, "a[href]": 7}
        return FakeLocator(counts[selector])

    def eval_on_selector_all(self, *_: object) -> list[str]:
        return ["https://example.com/a", "https://example.com/b"]


class FakeBrowser:
    def __init__(self, page: FakePage) -> None:
        self.page = page
        self.closed = False

    def new_page(self) -> FakePage:
        return self.page

    def close(self) -> None:
        self.closed = True


class FakeChromium:
    def __init__(self, browser: FakeBrowser | None = None, error: Exception | None = None) -> None:
        self.browser = browser
        self.error = error

    def launch(self, *, headless: bool) -> FakeBrowser:
        assert headless is True
        if self.error is not None:
            raise self.error
        assert self.browser is not None
        return self.browser


class FakePlaywrightManager:
    def __init__(self, chromium: FakeChromium) -> None:
        self.chromium = chromium

    def __enter__(self) -> object:
        return self

    def __exit__(self, *_: object) -> None:
        return None


def _install_fake_playwright(chromium: FakeChromium) -> None:
    playwright_module = types.ModuleType("playwright")
    sync_api_module = types.ModuleType("playwright.sync_api")
    sync_api_module.Error = FakePlaywrightError
    sync_api_module.TimeoutError = FakePlaywrightTimeoutError
    sync_api_module.sync_playwright = lambda: FakePlaywrightManager(chromium)
    sys.modules["playwright"] = playwright_module
    sys.modules["playwright.sync_api"] = sync_api_module


def test_playwright_runner_success_with_mocked_browser() -> None:
    page = FakePage()
    _install_fake_playwright(FakeChromium(FakeBrowser(page)))

    with patch("app.tools.playwright_runner.get_settings", return_value=Settings(_env_file=None, playwright_scan_timeout_seconds=9)):
        result = run_playwright_observation("example.com")

    assert result["success"] is True
    assert result["target"] == "https://example.com"
    observation = result["output"]
    assert observation["requested_url"] == "https://example.com"
    assert observation["final_url"] == "https://example.com/final"
    assert observation["title"] == "Example"
    assert observation["status_code"] == 200
    assert observation["forms_count"] == 2
    assert observation["inputs_count"] == 5
    assert observation["links_count"] == 7
    assert observation["console_issue_count"] == 1
    assert observation["network_issue_count"] == 1
    assert observation["link_samples"] == ["https://example.com/a", "https://example.com/b"]
    assert observation["limitations"]


def test_playwright_missing_dependency_is_clean_failure() -> None:
    original_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "playwright.sync_api":
            raise ImportError("missing")
        return original_import(name, *args, **kwargs)

    with (
        patch("builtins.__import__", side_effect=fake_import),
        patch("app.tools.playwright_runner.get_settings", return_value=Settings(_env_file=None)),
    ):
        result = run_playwright_observation("https://example.com")

    assert result["success"] is False
    assert result["error_type"] == "missing_dependency"


def test_playwright_missing_browser_runtime_is_clean_failure() -> None:
    _install_fake_playwright(FakeChromium(error=FakePlaywrightError("Executable doesn't exist")))

    with patch("app.tools.playwright_runner.get_settings", return_value=Settings(_env_file=None)):
        result = run_playwright_observation("https://example.com")

    assert result["success"] is False
    assert result["error_type"] == "browser_missing"


def test_playwright_navigation_timeout_is_clean_failure() -> None:
    _install_fake_playwright(FakeChromium(FakeBrowser(FakePage(timeout_on_goto=True))))

    with patch("app.tools.playwright_runner.get_settings", return_value=Settings(_env_file=None)):
        result = run_playwright_observation("https://example.com")

    assert result["success"] is False
    assert result["error_type"] == "timeout"


def test_playwright_observation_normalizer_shape() -> None:
    observation = normalize_playwright_observation(
        {
            "requested_url": "https://example.com",
            "final_url": "https://www.example.com",
            "title": "Example",
            "load_status": "loaded",
            "status_code": "200",
            "forms_count": "1",
            "inputs_count": "3",
            "links_count": "9",
            "link_samples": ["https://www.example.com/a"],
            "console_issue_count": "2",
            "network_issue_count": "1",
        }
    )
    summary = summarize_playwright_observation(observation)

    assert observation["host"] == "www.example.com"
    assert observation["status_code"] == 200
    assert summary["forms_count"] == 1
    assert summary["links_count"] == 9
    assert summary["console_issue_count"] == 2
