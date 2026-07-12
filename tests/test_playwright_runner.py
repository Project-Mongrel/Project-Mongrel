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

    def text(self) -> str:
        return "console error"


class FakePage:
    url = "https://example.com/final"

    def __init__(self, *, timeout_on_goto: bool = False) -> None:
        self.handlers = {}
        self.timeout_on_goto = timeout_on_goto
        self.default_timeout = None
        self.default_navigation_timeout = None
        self.screenshot_called = False

    def set_default_timeout(self, timeout: int) -> None:
        self.default_timeout = timeout

    def set_default_navigation_timeout(self, timeout: int) -> None:
        self.default_navigation_timeout = timeout

    def on(self, event: str, handler: object) -> None:
        self.handlers[event] = handler

    def goto(self, *_: object, **__: object) -> FakeResponse:
        if self.timeout_on_goto:
            raise FakePlaywrightTimeoutError("timeout")
        self.handlers["console"](FakeConsoleMessage())
        self.handlers["requestfailed"](object())
        if "response" in self.handlers:
            response = types.SimpleNamespace(url="https://example.com/api", status=200)
            self.handlers["response"](response)
        return FakeResponse()

    def wait_for_load_state(self, *_: object, **__: object) -> None:
        return None

    def title(self) -> str:
        return "Example"

    def locator(self, selector: str) -> FakeLocator:
        counts = {"form": 2, "input, textarea, select, button": 5, "a[href]": 7}
        return FakeLocator(counts[selector])

    def eval_on_selector_all(self, selector: str, *_: object) -> list[object]:
        if selector == "a[href]":
            return ["https://example.com/a", "https://other.example/b", "https://example.com/c"]
        if selector == "form":
            return [{"action": "/login", "method": "post", "input_count": 2}]
        return [{"tag": "INPUT", "type": "text", "name": "q", "id": "search", "required": True}]

    def screenshot(self, **_: object) -> bytes:
        self.screenshot_called = True
        return b"png"


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
    assert observation["link_samples"] == ["https://example.com/a", "https://example.com/c"]
    assert observation["form_samples"] == [{"action": "/login", "method": "post", "input_count": "2"}]
    assert observation["input_samples"] == [{"id": "search", "name": "q", "required": True, "tag": "INPUT", "type": "text"}]
    assert observation["console_messages"] == [{"text": "console error", "type": "error"}]
    assert observation["network_events"] == [{"host": "example.com", "same_host": True, "status": "200", "url": "https://example.com/api"}]
    assert observation["screenshot"] == {"bytes": 3, "captured": True, "type": "png"}
    assert observation["limitations"]
    assert page.default_timeout == 9000
    assert page.default_navigation_timeout == 9000
    assert page.screenshot_called is True


def test_playwright_runner_clamps_timeout_and_result_bounds() -> None:
    page = FakePage()
    _install_fake_playwright(FakeChromium(FakeBrowser(page)))

    settings = Settings(
        _env_file=None,
        playwright_scan_timeout_seconds=999,
        playwright_max_links=1,
        playwright_max_forms=1,
        playwright_max_inputs=1,
        playwright_max_console_messages=1,
        playwright_max_network_events=1,
        playwright_capture_screenshot_metadata=False,
    )
    with patch("app.tools.playwright_runner.get_settings", return_value=settings):
        result = run_playwright_observation("example.com")

    observation = result["output"]
    assert page.default_timeout == 120000
    assert observation["link_samples"] == ["https://example.com/a"]
    assert len(observation["form_samples"]) == 1
    assert len(observation["input_samples"]) == 1
    assert len(observation["console_messages"]) == 1
    assert len(observation["network_events"]) == 1
    assert "screenshot" not in observation


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
            "redirected_out_of_scope": True,
            "form_samples": [{"action": "/login", "method": "POST"}],
            "input_samples": [{"name": "q", "type": "search"}],
            "network_events": [{"url": "https://www.example.com/api", "status": 200}],
        }
    )
    summary = summarize_playwright_observation(observation)

    assert observation["host"] == "www.example.com"
    assert observation["status_code"] == 200
    assert summary["forms_count"] == 1
    assert summary["links_count"] == 9
    assert summary["console_issue_count"] == 2
    assert summary["redirected_out_of_scope"] is True
    assert summary["form_samples_count"] == 1
    assert summary["input_samples_count"] == 1
    assert summary["network_events_count"] == 1
