import logging
import time
from typing import Any

from app.core.config import get_settings
from app.parsers.playwright_parser import normalize_playwright_observation
from app.services.target_normalizer import normalize_for_playwright

logger = logging.getLogger(__name__)
PLAYWRIGHT_NOT_AVAILABLE_ERROR = "Playwright Python package is not installed."
PLAYWRIGHT_BROWSER_MISSING_ERROR = "Playwright browser runtime is not installed."
PLAYWRIGHT_TIMEOUT_ERROR = "Playwright navigation timed out."


def run_playwright_observation(target: str) -> dict[str, object]:
    validated_target = normalize_for_playwright(target)
    settings = get_settings()
    timeout_ms = max(1, int(settings.playwright_scan_timeout_seconds or 45)) * 1000
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

            def on_console(message: Any) -> None:
                nonlocal console_issue_count
                message_type = str(getattr(message, "type", "") or "").lower()
                if message_type in {"error", "warning"}:
                    console_issue_count += 1

            def on_page_error(_: Any) -> None:
                nonlocal page_error_count
                page_error_count += 1

            def on_request_failed(_: Any) -> None:
                nonlocal network_issue_count
                network_issue_count += 1

            page.on("console", on_console)
            page.on("pageerror", on_page_error)
            page.on("requestfailed", on_request_failed)
            response = page.goto(validated_target, wait_until="domcontentloaded", timeout=timeout_ms)
            try:
                page.wait_for_load_state("load", timeout=min(timeout_ms, 10000))
                load_status = "loaded"
            except PlaywrightTimeoutError:
                load_status = "domcontentloaded"

            observation = normalize_playwright_observation(
                {
                    "requested_url": validated_target,
                    "final_url": str(getattr(page, "url", "") or validated_target),
                    "title": _safe_title(page),
                    "load_status": load_status,
                    "status_code": getattr(response, "status", None) if response is not None else None,
                    "redirects": _redirect_chain(response),
                    "forms_count": _safe_count(page, "form"),
                    "inputs_count": _safe_count(page, "input, textarea, select, button"),
                    "links_count": _safe_count(page, "a[href]"),
                    "link_samples": _safe_link_samples(page),
                    "console_issue_count": console_issue_count,
                    "network_issue_count": network_issue_count,
                    "page_error_count": page_error_count,
                    "limitations": ["Passive browser observation only. No clicks, form submissions, logins, or bypass attempts were performed."],
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


def _safe_link_samples(page: object, limit: int = 5) -> list[str]:
    try:
        links = page.eval_on_selector_all("a[href]", "(links) => links.map((link) => link.href).filter(Boolean).slice(0, 5)")
    except Exception:
        return []
    if not isinstance(links, list):
        return []
    return [str(link).strip() for link in links[:limit] if str(link).strip()]


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
