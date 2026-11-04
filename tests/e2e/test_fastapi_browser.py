"""Browser e2e for the FastAPI integration (marker ``e2e``): the real widget against a FastAPI app.

Run with: ``uv run pytest -m e2e tests/e2e/test_fastapi_browser.py -v``

The app (``build_app``) runs under uvicorn in a background thread on a free localhost port. It
mirrors the Django e2e sites: a normal page and two strict-CSP pages (without 'unsafe-eval'), one
of which opts into ``allow_csp_eval_blocked``. The helpers come from ``test_browser.py``, so the
assertions are the same ones the Django tests make.
"""

from __future__ import annotations

import secrets
import socket
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest

pytest.importorskip("playwright")
pytest.importorskip("fastapi")
uvicorn = pytest.importorskip("uvicorn")

from fastapi import Depends, FastAPI, Response
from fastapi.responses import HTMLResponse

from capwx import CapConfig, InstrumentationOptions
from capwx.contrib.fastapi import Cap
from capwx.stores.memory import AsyncMemoryStore
from tests.e2e.support import BASE_HOST, Recorder
from tests.e2e.test_browser import (
    _assert_accepted,
    _assert_only_local,
    _solve,
    _widget_error_summary,
)

pytestmark = pytest.mark.e2e

SECRET = "fastapi-e2e-secret-0123456789"
STRICT_SITES = ("e2e-csp", "e2e-csp-allow")
SITES: dict[str, CapConfig] = {
    "e2e": CapConfig(
        secret=SECRET,
        hashwx_difficulty=20_000,
        instrumentation=InstrumentationOptions(obfuscation_level=3),
    ),
    "e2e-csp": CapConfig(secret=SECRET, hashwx_difficulty=20_000),
    "e2e-csp-allow": CapConfig(
        secret=SECRET,
        hashwx_difficulty=20_000,
        instrumentation=InstrumentationOptions(allow_csp_eval_blocked=True),
    ),
}

# Same policy as the Django strict-CSP tests; the script nonce is per request here.
_STRICT_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'nonce-{nonce}' 'wasm-unsafe-eval'; "
    "worker-src 'self' blob:; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:"
)

_PAGE = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>capwx fastapi e2e</title>{scripts}</head>
<body>
<form method="post">
  <label for="id_username">Username</label>
  <input id="id_username" name="username" type="text" value="alice">
  {widget}
  <button type="submit">Verify</button>
</form>
</body>
</html>
"""


def _add_site(app: FastAPI, cap: Cap, site: str) -> None:
    strict = site in STRICT_SITES

    @app.get(f"/e2e/{site}/", response_class=HTMLResponse)
    async def page(response: Response) -> str:
        nonce = secrets.token_urlsafe(16) if strict else None
        if nonce is not None:
            response.headers["Content-Security-Policy"] = _STRICT_CSP.format(nonce=nonce)
        return _PAGE.format(scripts=cap.scripts(nonce=nonce), widget=cap.widget(site))

    @app.post(f"/e2e/{site}/", dependencies=[Depends(cap.require(site=site))])
    async def submit() -> dict[str, Any]:
        return {"ok": True, "site": site}


def build_app() -> FastAPI:
    cap = Cap(SITES, store=AsyncMemoryStore())
    app = FastAPI()
    app.include_router(cap.router, prefix="/cap")
    cap.install(app)
    cap.mount_assets(app)  # /cap-static, the default path that cap.scripts() points at
    for site in SITES:
        _add_site(app, cap, site)
    return app


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((BASE_HOST, 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="session")
def fastapi_base_url() -> Iterator[str]:
    port = _free_port()
    config = uvicorn.Config(
        build_app(), host=BASE_HOST, port=port, log_level="warning", lifespan="off"
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 30
    while not server.started:
        if not thread.is_alive() or time.monotonic() > deadline:
            pytest.fail("the FastAPI test server did not start")
        time.sleep(0.05)
    try:
        yield f"http://{BASE_HOST}:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


# --- 1. normal page: solve in the browser, the require()-guarded POST accepts the token -------


def test_fastapi_widget_solves_and_server_accepts(
    recorder: Recorder, fastapi_base_url: str
) -> None:
    _assert_accepted(recorder, fastapi_base_url, "e2e")

    # The hashwx wasm came from the mounted assets, not from a CDN, and nothing left localhost.
    wasm = recorder.responses_ending("/cap-static/hashwx.wasm")
    assert wasm and wasm[-1].status == 200, "hashwx.wasm was not loaded from /cap-static"
    _assert_only_local(recorder)


# --- 2. strict CSP without 'unsafe-eval' (issue #1), instrumentation refuses by default -------


def test_fastapi_strict_csp_fails_fast_with_csp_eval_blocked(
    recorder: Recorder, fastapi_base_url: str
) -> None:
    started = time.monotonic()
    seen = _solve(recorder, fastapi_base_url, "e2e-csp")
    elapsed = time.monotonic() - started

    assert not seen["token"], _widget_error_summary(recorder)
    assert seen["redeem_status"] == 403, seen
    assert seen["redeem_body"] == {"success": False, "error": "instr_csp_eval_blocked"}, seen
    # Before the fix the widget waited the full 20 s probe timeout and got instr_timeout.
    assert elapsed < 20, f"took {elapsed:.1f}s: the probe did not post"


# --- 3. strict CSP, with allow_csp_eval_blocked: accepted with the risk flag -----------------


def test_fastapi_strict_csp_is_accepted_when_allowed(
    recorder: Recorder, fastapi_base_url: str
) -> None:
    seen = _assert_accepted(recorder, fastapi_base_url, "e2e-csp-allow")

    instr = seen["redeem_request"]["solutions"][-1]["instr"]
    assert instr["ce"] is True
