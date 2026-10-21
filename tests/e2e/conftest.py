"""Fixtures for the browser e2e tests (marker ``e2e``, plan §13.3).

- ``e2e_base_url``: a threaded Django live server on 127.0.0.1 with static files served by
  ``StaticFilesHandler``, so ``/static/capwx/cap.min.js`` and the wasm files are the real vendored
  ones. ``pytest-django``'s ``live_server`` is not used: it requests ``transactional_db``, and the
  test settings deliberately have no database.
- ``browser``: one headless Chromium per session. ``CAPWX_E2E_CHROME`` may name a Chrome/Chromium
  executable; otherwise Playwright's bundled Chromium is used when present, else the installed
  Google Chrome channel.
- ``recorder``: a per-test page with request/response/console recording and a init script that
  captures the widget's ``solve`` and ``error`` events.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.e2e.support import BASE_HOST, Recorder

# Records widget events in the page. Capture phase on window sees non-bubbling CustomEvents
# dispatched on <cap-widget>.
_CAP_EVENT_INIT = """
window.__capEvents = [];
for (const type of ["solve", "error"]) {
  window.addEventListener(type, (event) => {
    const detail = event.detail && typeof event.detail === "object" ? event.detail : {};
    window.__capEvents.push({
      type,
      code: detail.code ?? null,
      message: detail.message ?? null,
      isCap: detail.isCap ?? null,
    });
  }, true);
}
"""


@pytest.fixture(scope="session")
def e2e_base_url() -> Iterator[str]:
    from django.contrib.staticfiles.handlers import StaticFilesHandler
    from django.test.testcases import LiveServerThread

    thread = LiveServerThread(BASE_HOST, StaticFilesHandler, connections_override={}, port=0)
    thread.daemon = True
    thread.start()
    thread.is_ready.wait(timeout=30)
    if thread.error is not None:
        raise thread.error
    try:
        yield f"http://{BASE_HOST}:{thread.port}"
    finally:
        thread.terminate()


def _launch_options(playwright: Any) -> dict[str, Any]:
    explicit = os.environ.get("CAPWX_E2E_CHROME")
    if explicit:
        return {"executable_path": explicit}
    if Path(playwright.chromium.executable_path).exists():
        return {}
    return {"channel": "chrome"}


@pytest.fixture(scope="session")
def browser() -> Iterator[Any]:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        instance = playwright.chromium.launch(headless=True, **_launch_options(playwright))
        try:
            yield instance
        finally:
            instance.close()


@pytest.fixture
def recorder(browser: Any) -> Iterator[Recorder]:
    context = browser.new_context(viewport={"width": 480, "height": 800})
    context.set_default_timeout(120_000)
    page = context.new_page()
    rec = Recorder(page=page, context=context)
    context.on("request", lambda r: rec.requests.append(r))
    page.on("response", lambda r: rec.responses.append(r))
    page.on("console", lambda m: rec.console.append(f"[{m.type}] {m.text}"))
    page.on("pageerror", lambda e: rec.page_errors.append(str(e)))
    page.add_init_script(_CAP_EVENT_INIT)
    try:
        yield rec
    finally:
        context.close()
