"""Browser e2e tests (marker ``e2e``, plan §13.3): the REAL vendored cap-widget in headless Chromium.

Run with: ``uv run pytest -m e2e tests/e2e -v`` (the default run deselects them).

The main test (``test_widget_solves_and_server_accepts``) is the proof that the instrumentation
port is bit-exact: the browser runs the obfuscated probe script, the server verifies its result,
and the form submission is accepted. Failures are reported with the widget's own error event and
the redeem response, not with a bare timeout.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

from tests.django_project.views import E2E_CSP_NONCE
from tests.e2e.support import BASE_HOST, Recorder

pytestmark = pytest.mark.e2e

# Wait for the widget to fill the hidden cap-token input or to report an error, whichever first.
SOLVE_TIMEOUT_MS = 180_000
_SOLVED_OR_ERRORED = """() => {
  const input = document.querySelector('input[name="cap-token"]');
  const hasToken = Boolean(input && input.value);
  const hasError = (window.__capEvents || []).some((e) => e.type === "error");
  return hasToken || hasError;
}"""


def _widget_error_summary(rec: Recorder) -> str:
    errors = [e for e in rec.widget_events() if e["type"] == "error"]
    if not errors:
        return "widget reported no error event"
    return "; ".join(f"widget error code={e['code']!r} message={e['message']!r}" for e in errors)


def _solve(rec: Recorder, base: str, site: str) -> dict[str, Any]:
    """Load the e2e page, click the widget, wait for the token. Returns what the server saw."""
    page = rec.page
    page.goto(f"{base}/e2e/{site}/")
    page.locator("cap-widget").wait_for(state="attached")
    page.locator("cap-widget").click()
    try:
        page.wait_for_function(_SOLVED_OR_ERRORED, timeout=SOLVE_TIMEOUT_MS)
    except PlaywrightTimeoutError:
        pytest.fail(
            f"site {site}: widget neither filled cap-token nor reported an error within "
            f"{SOLVE_TIMEOUT_MS // 1000}s. page errors={rec.page_errors} "
            f"console={rec.console[-10:]}"
        )

    token = page.locator('input[name="cap-token"]').input_value()
    events = rec.widget_events()
    challenge_responses = rec.responses_ending(f"/cap/{site}/challenge")
    redeem_responses = rec.responses_ending(f"/cap/{site}/redeem")
    return {
        "token": token,
        "events": events,
        "challenge": challenge_responses[-1].json() if challenge_responses else None,
        "redeem_status": redeem_responses[-1].status if redeem_responses else None,
        "redeem_body": redeem_responses[-1].json() if redeem_responses else None,
        "redeem_request": redeem_responses[-1].request.post_data_json if redeem_responses else None,
        "redeem_count": len(redeem_responses),
    }


def _submit(rec: Recorder, site: str) -> tuple[int, Any]:
    page = rec.page
    with page.expect_response(
        lambda r: r.request.method == "POST" and r.url.endswith(f"/e2e/{site}/")
    ) as info:
        page.get_by_role("button", name="Verify").click()
    response = info.value
    return response.status, response.json()


def _assert_accepted(rec: Recorder, base: str, site: str) -> dict[str, Any]:
    """The full §13.3 flow: solve in the browser, submit, server says valid."""
    seen = _solve(rec, base, site)
    assert seen["token"], f"site {site}: no token. {_widget_error_summary(rec)}"

    redeem_status, redeem_body = seen["redeem_status"], seen["redeem_body"]
    assert redeem_status == 200 and redeem_body and redeem_body.get("success") is True, (
        f"site {site}: redeem answered {redeem_status} {redeem_body}; {_widget_error_summary(rec)}"
    )

    status, body = _submit(rec, site)
    assert status == 200 and body == {"ok": True, "site": site}, (
        f"site {site}: form submission answered {status} {body}; {_widget_error_summary(rec)}"
    )
    return seen


def _assert_only_local(rec: Recorder) -> None:
    for request in rec.requests:
        parts = urlsplit(request.url)
        if parts.scheme in ("data", "blob", "about"):
            continue
        assert parts.hostname == BASE_HOST, (
            f"request left localhost: {request.method} {request.url}"
        )


# --- 1. the bit-exact instrumentation proof (site e2e, obfuscation level 3, hashwx) -----------


def test_widget_solves_and_server_accepts(recorder: Recorder, e2e_base_url: str) -> None:
    seen = _assert_accepted(recorder, e2e_base_url, "e2e")

    # The hashwx path ran: the widget fetched the wasm from /static, not from a CDN.
    wasm = recorder.responses_ending("/static/capwx/hashwx.wasm")
    assert wasm and wasm[-1].status == 200, "hashwx.wasm was not loaded from /static"

    # The redeem body follows the format-2 contract: one solution per challenge, and the
    # instrumentation slot carries its result under solutions[i].instr.
    challenge = seen["challenge"]
    assert challenge["format"] == 2
    protocols = [c["protocol"] for c in challenge["challenges"]]
    # hashwx_challenge_count=4 (default) gives four hashwx entries, then the instrumentation entry.
    assert protocols == ["hashwx"] * 4 + ["instrumentation"], protocols
    body = seen["redeem_request"]
    assert len(body["solutions"]) == len(protocols)
    assert "instr" in body["solutions"][protocols.index("instrumentation")], body.keys()
    assert "instr" not in body, "widget sent a top-level instr key for a format-2 challenge"


# --- 2. obfuscation levels 1, 4, 7 -----------------------------------------------------------


@pytest.mark.parametrize("site", ["e2e-obf1", "e2e-obf4", "e2e-obf7"])
def test_obfuscation_level_is_accepted(recorder: Recorder, e2e_base_url: str, site: str) -> None:
    _assert_accepted(recorder, e2e_base_url, site)


# --- 2b. without the hashwx wasm path: sha256-pow challenges + instrumentation ---------------


def test_sha256_path_without_hashwx_is_accepted(recorder: Recorder, e2e_base_url: str) -> None:
    seen = _assert_accepted(recorder, e2e_base_url, "e2e-nohashwx")
    protocols = [c["protocol"] for c in seen["challenge"]["challenges"]]
    assert protocols == ["sha256-pow"] * 4 + ["instrumentation"], protocols
    assert not recorder.responses_ending("/static/capwx/hashwx.wasm")


# --- 3. blocking site: Playwright's Chromium is detected -------------------------------------


def test_blocking_site_rejects_playwright_chromium(recorder: Recorder, e2e_base_url: str) -> None:
    seen = _solve(recorder, e2e_base_url, "e2e-blocking")

    # Documented behaviour (plan §13.3): the probe sees automation, the server refuses the
    # solution with instr_automated_browser, and the widget shows an error, not a token.
    assert not seen["token"], "a headless Playwright Chromium passed the blocking site"
    assert seen["redeem_status"] == 403, seen
    assert seen["redeem_body"] == {"success": False, "error": "instr_automated_browser"}, seen
    errors = [e for e in seen["events"] if e["type"] == "error"]
    assert errors, "the widget did not show an error for the blocked browser"


# --- 4. network: nothing leaves localhost (no CDN) -------------------------------------------


def test_no_request_leaves_localhost(recorder: Recorder, e2e_base_url: str) -> None:
    _assert_accepted(recorder, e2e_base_url, "e2e")
    assert recorder.requests, "no requests were recorded"
    _assert_only_local(recorder)
    assert not any("cdn." in r.url for r in recorder.requests)


# --- 5. strict CSP without 'unsafe-eval' (issue #1) -------------------------------------------

_STRICT_CSP = (
    "default-src 'self'; "
    f"script-src 'self' 'nonce-{E2E_CSP_NONCE}' 'wasm-unsafe-eval'; "
    "worker-src 'self' blob:; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:"
)


def _serve_under_strict_csp(rec: Recorder, site: str) -> None:
    """Add a CSP without 'unsafe-eval' to the e2e page; the srcdoc probe iframe inherits it."""

    def handle(route: Any) -> None:
        if route.request.method != "GET":
            route.continue_()
            return
        response = route.fetch()
        headers = {**response.headers, "content-security-policy": _STRICT_CSP}
        route.fulfill(response=response, headers=headers)

    rec.page.route(f"**/e2e/{site}/", handle)


def test_strict_csp_fails_fast_with_csp_eval_blocked(recorder: Recorder, e2e_base_url: str) -> None:
    _serve_under_strict_csp(recorder, "e2e-csp")
    started = time.monotonic()
    seen = _solve(recorder, e2e_base_url, "e2e-csp")
    elapsed = time.monotonic() - started

    assert not seen["token"]
    assert seen["redeem_status"] == 403, seen
    assert seen["redeem_body"] == {"success": False, "error": "instr_csp_eval_blocked"}, seen
    # Before the fix the widget waited the full 20 s probe timeout and got instr_timeout.
    assert elapsed < 20, f"took {elapsed:.1f}s: the probe did not post"


def test_strict_csp_is_accepted_when_allowed(recorder: Recorder, e2e_base_url: str) -> None:
    _serve_under_strict_csp(recorder, "e2e-csp-allow")
    seen = _assert_accepted(recorder, e2e_base_url, "e2e-csp-allow")

    instr = seen["redeem_request"]["solutions"][-1]["instr"]
    assert instr["ce"] is True
