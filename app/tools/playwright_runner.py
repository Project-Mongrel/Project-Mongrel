import logging
import time
from typing import Any
from urllib.parse import urlparse

from app.core.config import get_settings
from app.parsers.playwright_parser import normalize_playwright_observation
from app.services.target_normalizer import normalize_for_playwright

logger = logging.getLogger(__name__)
PLAYWRIGHT_NOT_AVAILABLE_ERROR = "Playwright Python package is not installed."
PLAYWRIGHT_BROWSER_MISSING_ERROR = "Playwright browser runtime is not installed."
PLAYWRIGHT_TIMEOUT_ERROR = "Playwright navigation timed out."
MAX_PLAYWRIGHT_TIMEOUT_SECONDS = 120


def run_playwright_observation(target: str) -> dict[str, object]:
    validated_target = normalize_for_playwright(target)
    settings = get_settings()
    timeout_seconds = max(1, min(int(settings.playwright_scan_timeout_seconds or 45), MAX_PLAYWRIGHT_TIMEOUT_SECONDS))
    timeout_ms = timeout_seconds * 1000
    limits = _playwright_limits(settings)
    requested_host = urlparse(validated_target).netloc.lower()
    start_time = time.monotonic()
    logger.info("Playwright observation started: target=%s timeout_ms=%s", validated_target, timeout_ms)

    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ImportError:
        return _result(
            target=validated_target,
            success=False,
            error=PLAYWRIGHT_NOT_AVAILABLE_ERROR,
            error_type="missing_dependency",
            elapsed_seconds=time.monotonic() - start_time,
        )

    browser = None
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            page.set_default_timeout(timeout_ms)
            page.set_default_navigation_timeout(timeout_ms)
            console_issue_count = 0
            page_error_count = 0
            network_issue_count = 0
            console_messages: list[dict] = []
            network_events: list[dict] = []

            def on_console(message: Any) -> None:
                nonlocal console_issue_count
                message_type = str(getattr(message, "type", "") or "").lower()
                if message_type in {"error", "warning"}:
                    console_issue_count += 1
                if len(console_messages) < limits["console"]:
                    console_messages.append({"type": message_type or "unknown", "text": _bounded_text(_call_or_attr(message, "text"), 300)})

            def on_page_error(_: Any) -> None:
                nonlocal page_error_count
                page_error_count += 1

            def on_request_failed(_: Any) -> None:
                nonlocal network_issue_count
                network_issue_count += 1

            def on_response(response: Any) -> None:
                if len(network_events) >= limits["network"]:
                    return
                url = str(getattr(response, "url", "") or "").strip()
                host = urlparse(url).netloc.lower()
                network_events.append(
                    {
                        "url": _bounded_text(url, 300),
                        "host": host,
                        "status": _safe_int(getattr(response, "status", None)),
                        "same_host": host == requested_host if host else None,
                    }
                )

            page.on("console", on_console)
            page.on("pageerror", on_page_error)
            page.on("requestfailed", on_request_failed)
            page.on("response", on_response)
            response = page.goto(validated_target, wait_until="domcontentloaded", timeout=timeout_ms)
            try:
                page.wait_for_load_state("load", timeout=min(timeout_ms, 10000))
                load_status = "loaded"
            except PlaywrightTimeoutError:
                load_status = "domcontentloaded"

            final_url = str(getattr(page, "url", "") or validated_target)
            final_host = urlparse(final_url).netloc.lower()
            observation = normalize_playwright_observation(
                {
                    "requested_url": validated_target,
                    "final_url": final_url,
                    "title": _safe_title(page),
                    "load_status": load_status,
                    "status_code": getattr(response, "status", None) if response is not None else None,
                    "redirects": _redirect_chain(response),
                    "redirected_out_of_scope": bool(final_host and final_host != requested_host),
                    "forms_count": _safe_count(page, "form"),
                    "inputs_count": _safe_count(page, "input, textarea, select, button"),
                    "links_count": _safe_count(page, "a[href]"),
                    "link_samples": _safe_link_samples(page, requested_host=requested_host, limit=limits["links"]),
                    "form_samples": _safe_form_samples(page, limit=limits["forms"]),
                    "input_samples": _safe_input_samples(page, limit=limits["inputs"]),
                    "console_issue_count": console_issue_count,
                    "console_messages": console_messages,
                    "network_issue_count": network_issue_count,
                    "network_events": network_events,
                    "page_error_count": page_error_count,
                    "screenshot": _safe_screenshot_metadata(page, enabled=bool(settings.playwright_capture_screenshot_metadata)),
                    "limits": limits,
                    "limitations": [
                        "Passive browser observation only. No clicks, form submissions, logins, or bypass attempts were performed.",
                        "Observed fields are raw page structure metadata, not inferred business meaning.",
                        "No vulnerability conclusion is made from page structure alone.",
                    ],
                }
            )
    except PlaywrightTimeoutError:
        return _result(
            target=validated_target,
            success=False,
            error=PLAYWRIGHT_TIMEOUT_ERROR,
            error_type="timeout",
            elapsed_seconds=time.monotonic() - start_time,
        )
    except PlaywrightError as exc:
        error_text = str(exc)
        error_type = "browser_missing" if "Executable doesn't exist" in error_text or "playwright install" in error_text.lower() else "navigation_failed"
        error = PLAYWRIGHT_BROWSER_MISSING_ERROR if error_type == "browser_missing" else "Playwright navigation failed."
        logger.warning("Playwright observation failed: target=%s error_type=%s error=%s", validated_target, error_type, exc)
        return _result(
            target=validated_target,
            success=False,
            error=error,
            error_type=error_type,
            elapsed_seconds=time.monotonic() - start_time,
        )
    except Exception:
        logger.exception("Playwright runner error: target=%s", validated_target)
        return _result(
            target=validated_target,
            success=False,
            error="Playwright runner error.",
            error_type="runner_error",
            elapsed_seconds=time.monotonic() - start_time,
        )
    finally:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                logger.warning("Playwright browser close failed.", exc_info=True)

    elapsed_seconds = time.monotonic() - start_time
    return _result(
        target=validated_target,
        success=True,
        output=observation,
        elapsed_seconds=elapsed_seconds,
    )


def _safe_title(page: object) -> str:
    try:
        return str(page.title() or "")
    except Exception:
        return ""


def _safe_count(page: object, selector: str) -> int:
    try:
        return int(page.locator(selector).count())
    except Exception:
        return 0


def _safe_link_samples(page: object, *, requested_host: str, limit: int = 5) -> list[str]:
    try:
        links = page.eval_on_selector_all("a[href]", "(links) => links.map((link) => link.href).filter(Boolean)")
    except Exception:
        return []
    if not isinstance(links, list):
        return []
    samples = []
    for link in links:
        cleaned = str(link).strip()
        if not cleaned:
            continue
        host = urlparse(cleaned).netloc.lower()
        if host and requested_host and host != requested_host:
            continue
        samples.append(cleaned)
        if len(samples) >= limit:
            break
    return samples


def _safe_form_samples(page: object, limit: int) -> list[dict]:
    try:
        forms = page.eval_on_selector_all(
            "form",
            """(forms) => forms.map((form) => ({
                action: form.action || form.getAttribute('action') || '',
                method: form.method || form.getAttribute('method') || '',
                input_count: form.querySelectorAll('input, textarea, select, button').length
            }))""",
        )
    except Exception:
        return []
    if not isinstance(forms, list):
        return []
    return [_clean_mapping(form, {"action", "method", "input_count"}) for form in forms[:limit] if isinstance(form, dict)]


def _safe_input_samples(page: object, limit: int) -> list[dict]:
    try:
        inputs = page.eval_on_selector_all(
            "input, textarea, select, button",
            """(inputs) => inputs.map((input) => ({
                tag: input.tagName || '',
                type: input.type || input.getAttribute('type') || '',
                name: input.name || input.getAttribute('name') || '',
                id: input.id || '',
                required: Boolean(input.required)
            }))""",
        )
    except Exception:
        return []
    if not isinstance(inputs, list):
        return []
    return [_clean_mapping(item, {"tag", "type", "name", "id", "required"}) for item in inputs[:limit] if isinstance(item, dict)]


def _safe_screenshot_metadata(page: object, *, enabled: bool) -> dict:
    if not enabled:
        return {}
    try:
        data = page.screenshot(full_page=False, type="png", timeout=3000)
    except Exception:
        return {"captured": False}
    size = len(data) if isinstance(data, (bytes, bytearray)) else 0
    return {"captured": True, "type": "png", "bytes": size}


def _redirect_chain(response: object | None) -> list[str]:
    if response is None:
        return []
    redirects = []
    request = getattr(response, "request", None)
    seen = set()
    while request is not None:
        redirected_from = getattr(request, "redirected_from", None)
        if callable(redirected_from):
            request = redirected_from()
        else:
            request = None
        url = str(getattr(request, "url", "") or "").strip() if request is not None else ""
        if url and url not in seen:
            seen.add(url)
            redirects.append(url)
    redirects.reverse()
    return redirects


def _playwright_limits(settings: object) -> dict[str, int]:
    return {
        "links": _bounded_int(getattr(settings, "playwright_max_links", 25), default=25, maximum=100),
        "forms": _bounded_int(getattr(settings, "playwright_max_forms", 10), default=10, maximum=50),
        "inputs": _bounded_int(getattr(settings, "playwright_max_inputs", 25), default=25, maximum=100),
        "console": _bounded_int(getattr(settings, "playwright_max_console_messages", 10), default=10, maximum=50),
        "network": _bounded_int(getattr(settings, "playwright_max_network_events", 25), default=25, maximum=100),
        "max_response_size_bytes": _bounded_int(getattr(settings, "playwright_max_response_size_bytes", 1_000_000), default=1_000_000, maximum=5_000_000),
    }


def _bounded_int(value: object, *, default: int, maximum: int) -> int:
    try:
        parsed = int(value if value not in (None, "") else default)
    except (TypeError, ValueError):
        parsed = default
    return max(1, min(parsed, maximum))


def _bounded_text(value: object, limit: int) -> str:
    return str(value or "").replace("\n", " ").strip()[:limit]


def _call_or_attr(obj: object, name: str) -> object:
    value = getattr(obj, name, "")
    return value() if callable(value) else value


def _safe_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _clean_mapping(item: dict, allowed_keys: set[str]) -> dict:
    cleaned = {}
    for key in allowed_keys:
        value = item.get(key)
        if isinstance(value, bool):
            cleaned[key] = value
        elif value not in (None, ""):
            cleaned[key] = _bounded_text(value, 200)
    return cleaned


def _result(
    *,
    target: str,
    success: bool,
    output: dict | None = None,
    error: str = "",
    error_type: str | None = None,
    elapsed_seconds: float,
) -> dict[str, object]:
    return {
        "target": target,
        "success": success,
        "output": output or {},
        "error": error,
        "error_type": error_type,
        "returncode": None,
        "exit_code": None,
        "elapsed_seconds": elapsed_seconds,
        "command": None,
        "stdout_len": 0,
        "stderr_len": len(error or ""),
    }
