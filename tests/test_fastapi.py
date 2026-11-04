"""Tests for capwx.contrib.fastapi: the widget router, Depends(cap.require), assets, templates.

Mirrors tests/test_ninja.py. Most tests use the sha256-pow protocol only, so no wasmtime is needed.
The whole module is skipped when fastapi or httpx is not installed.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

import httpx
from _solver import body_for, expected_entries, solve_instrumentation
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.testclient import TestClient

import capwx.challenge
from capwx import CapConfig, CapwxError, MemoryStore
from capwx.contrib.fastapi import Blocked, Cap, SiteSettings
from capwx.contrib.fastapi import assets as assets_module
from capwx.contrib.fastapi import config as config_module
from capwx.contrib.fastapi.deps import CaptchaRequired
from capwx.stores.memory import AsyncMemoryStore

ROOT = Path(__file__).resolve().parent.parent
SECRET = "test-secret-0123456789abcdef"
SITE_SECRET = "site-secret-0123456789abcdef"
MAX_BODY = 64 * 1024
PREFIX = "/cap"
SHA = CapConfig(secret=SECRET, protocols=("sha256-pow",), sha256_count=3, sha256_difficulty=1)
SHA_SITE = SiteSettings(config=SHA, site_secret=SITE_SECRET)


def make_cap(sites: dict[str, Any] | None = None, **kwargs: Any) -> Cap:
    return Cap(sites or {"login": SHA}, store=AsyncMemoryStore(), **kwargs)


def make_app(cap: Cap) -> FastAPI:
    app = FastAPI()
    app.include_router(cap.router, prefix=PREFIX)
    cap.install(app)
    return app


@pytest.fixture
def cap() -> Cap:
    return make_cap()


@pytest.fixture
def client(cap: Cap) -> TestClient:
    app = make_app(cap)

    @app.post("/orders", dependencies=[Depends(cap.require("login"))])
    async def orders() -> dict[str, bool]:
        return {"ok": True}

    return TestClient(app)


def _challenge(client: TestClient, site: str = "login") -> dict[str, Any]:
    response = client.post(f"{PREFIX}/{site}/challenge")
    assert response.status_code == 200, response.content
    return response.json()


def _token(client: TestClient, site: str = "login") -> str:
    challenge = _challenge(client, site)
    response = client.post(f"{PREFIX}/{site}/redeem", json=body_for(SECRET, challenge))
    assert response.status_code == 200, response.content
    return response.json()["token"]


# --------------------------------------------------------------------------- challenge and flow


def test_challenge_shape_and_no_store(client: TestClient) -> None:
    response = client.post(f"{PREFIX}/login/challenge")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    data = response.json()
    assert set(data) == {"token", "format", "challenges", "expires"}
    assert data["format"] == 2
    assert [c["protocol"] for c in data["challenges"]] == ["sha256-pow"] * 3


def test_redeem_success_shape(client: TestClient) -> None:
    challenge = _challenge(client)
    response = client.post(f"{PREFIX}/login/redeem", json=body_for(SECRET, challenge))
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert set(response.json()) == {"success", "token", "expires"}
    assert response.json()["success"] is True


def test_replay_of_same_redeem_body_is_already_redeemed(client: TestClient) -> None:
    challenge = _challenge(client)
    body = body_for(SECRET, challenge)
    assert client.post(f"{PREFIX}/login/redeem", json=body).status_code == 200
    second = client.post(f"{PREFIX}/login/redeem", json=body)
    assert second.status_code == 403
    assert second.json() == {"success": False, "error": "already_redeemed"}


def test_redeem_token_for_another_site_is_scope_mismatch() -> None:
    other = make_cap({"login": SHA, "signup": SHA})
    other_client = TestClient(make_app(other))
    challenge = _challenge(other_client, "signup")
    response = other_client.post(f"{PREFIX}/login/redeem", json=body_for(SECRET, challenge))
    assert response.status_code == 403
    assert response.json() == {"success": False, "error": "scope_mismatch"}


def test_wrong_solution_is_invalid_solution_400(client: TestClient) -> None:
    challenge = _challenge(client)
    body = {"token": challenge["token"], "solutions": [{"nonce": "x"}] * 3}
    response = client.post(f"{PREFIX}/login/redeem", json=body)
    assert response.status_code == 400
    assert response.json() == {"success": False, "error": "invalid_solution"}


def test_full_flow_then_require_consumes_the_token_once(client: TestClient) -> None:
    token = _token(client)
    assert client.post("/orders", headers={"X-Cap-Token": token}).json() == {"ok": True}
    again = client.post("/orders", headers={"X-Cap-Token": token})
    assert again.status_code == 403
    assert again.json() == {"error": "captcha_required"}


def test_async_client_runs_the_whole_flow() -> None:
    cap = make_cap()
    app = make_app(cap)

    @app.post("/orders", dependencies=[Depends(cap.require("login"))])
    async def orders() -> dict[str, bool]:
        return {"ok": True}

    async def scenario() -> tuple[int, int, dict[str, Any]]:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            challenge = (await client.post(f"{PREFIX}/login/challenge")).json()
            redeemed = await client.post(f"{PREFIX}/login/redeem", json=body_for(SECRET, challenge))
            token = redeemed.json()["token"]
            used = await client.post("/orders", headers={"X-Cap-Token": token})
            replay = await client.post("/orders", headers={"X-Cap-Token": token})
            return used.status_code, replay.status_code, replay.json()

    used, replay, body = asyncio.run(scenario())
    assert used == 200
    assert replay == 403
    assert body == {"error": "captcha_required"}


def test_challenge_does_not_block_the_event_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    real_create = capwx.challenge.create_challenge

    def slow_create(*args: Any, **kwargs: Any) -> dict[str, Any]:
        time.sleep(0.3)  # CPU-bound minting; acreate_challenge runs it in a worker thread
        return real_create(*args, **kwargs)

    monkeypatch.setattr(capwx.challenge, "create_challenge", slow_create)
    app = make_app(make_cap())

    async def scenario() -> tuple[int, int]:
        ticks = 0

        async def ticker() -> None:
            nonlocal ticks
            while True:
                await asyncio.sleep(0.01)
                ticks += 1

        task = asyncio.create_task(ticker())
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(f"{PREFIX}/login/challenge")
        task.cancel()
        return response.status_code, ticks

    status, ticks = asyncio.run(scenario())
    assert status == 200
    assert ticks >= 5, "the event loop was blocked while the challenge was minted"


# --------------------------------------------------------------------------- site, method, size


@pytest.mark.parametrize("path", ["challenge", "redeem", "siteverify"])
def test_unknown_site_is_404(client: TestClient, path: str) -> None:
    response = client.post(f"{PREFIX}/nope/{path}", json={})
    assert response.status_code == 404
    assert response.json() == {"error": "Invalid site key"}
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("path", ["challenge", "redeem", "siteverify"])
@pytest.mark.parametrize("method", ["get", "put", "delete"])
def test_non_post_is_405_json_with_allow(client: TestClient, path: str, method: str) -> None:
    response = client.request(method.upper(), f"{PREFIX}/login/{path}")
    assert response.status_code == 405
    assert response.headers["allow"] == "POST"
    assert response.json() == {"error": "method_not_allowed"}


def test_oversized_body_is_413_even_without_content_length(client: TestClient) -> None:
    chunks = (b"x" * 1024 for _ in range(MAX_BODY // 1024 + 1))  # sent chunked: no length header
    response = client.post(
        f"{PREFIX}/login/redeem", content=chunks, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 413
    assert response.json() == {"success": False, "error": "body_too_large"}


def test_body_at_the_limit_is_not_rejected_for_size(client: TestClient) -> None:
    data = b"[" + b" " * (MAX_BODY - 2) + b"]"  # exactly MAX_BODY bytes, valid JSON array
    response = client.post(
        f"{PREFIX}/login/redeem", content=data, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 400  # not 413: parsed, then rejected as an invalid body
    assert response.json() == {"success": False, "error": "invalid_body"}


def test_challenge_also_refuses_an_oversized_body(client: TestClient) -> None:
    response = client.post(f"{PREFIX}/login/challenge", content=b"x" * (MAX_BODY + 1))
    assert response.status_code == 413


def test_malformed_json_is_400_invalid_body(client: TestClient) -> None:
    response = client.post(
        f"{PREFIX}/login/redeem", content=b"{", headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 400
    assert response.json() == {"success": False, "error": "invalid_body"}


def test_non_utf8_json_is_400_invalid_body(client: TestClient) -> None:
    response = client.post(
        f"{PREFIX}/login/redeem",
        content=b"\xff\xfe{}",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_body"


# --------------------------------------------------------------------------- siteverify


def _siteverify_client() -> TestClient:
    return TestClient(make_app(make_cap({"login": SHA_SITE})))


def test_siteverify_consumes_the_token_and_reports_errors() -> None:
    client = _siteverify_client()
    token = _token(client)
    url = f"{PREFIX}/login/siteverify"
    assert client.post(url, json={"secret": SITE_SECRET, "response": token}).json() == {
        "success": True
    }
    used = client.post(url, json={"secret": SITE_SECRET, "response": token})
    assert used.status_code == 400
    assert used.json() == {"success": False, "error": "invalid_token"}

    wrong = client.post(url, json={"secret": "nope", "response": token})
    assert wrong.status_code == 403
    assert wrong.json() == {"success": False, "error": "invalid_secret"}

    missing = client.post(url, json={"response": token})
    assert missing.status_code == 400
    assert missing.json() == {"success": False, "error": "missing_parameters"}


def test_siteverify_rejects_a_non_object_body() -> None:
    client = _siteverify_client()
    response = client.post(f"{PREFIX}/login/siteverify", json=[1, 2])
    assert response.status_code == 400
    assert response.json() == {"success": False, "error": "invalid_body"}


def test_siteverify_without_a_site_secret_is_404() -> None:
    client = TestClient(make_app(make_cap()))
    response = client.post(f"{PREFIX}/login/siteverify", json={"secret": "x", "response": "y"})
    assert response.status_code == 404
    assert response.json() == {"success": False, "error": "siteverify_not_configured"}


# --------------------------------------------------------------------------- token sources


def test_token_from_json_body(client: TestClient) -> None:
    token = _token(client)
    assert client.post("/orders", json={"cap-token": token}).status_code == 200


def test_token_from_urlencoded_form(client: TestClient) -> None:
    token = _token(client)
    assert client.post("/orders", data={"cap-token": token}).status_code == 200


def test_form_token_is_ignored_on_a_get_request() -> None:
    cap = make_cap()
    app = make_app(cap)

    @app.get("/peek", dependencies=[Depends(cap.require("login"))])
    async def peek() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app)
    token = _token(TestClient(app))
    response = client.request("GET", "/peek", data={"cap-token": token})
    assert response.status_code == 403


def test_multipart_token_needs_python_multipart(client: TestClient) -> None:
    token = _token(client)
    response = client.post("/orders", files={"cap-token": (None, token)})
    if _has_multipart():
        assert response.status_code == 200
    else:  # without python-multipart a multipart body yields no token, never a crash
        assert response.status_code == 403


def _has_multipart() -> bool:
    try:
        import multipart  # noqa: F401  # the python-multipart package
    except ImportError:
        return False
    return True


def _form_parameter_client(cap: Cap) -> TestClient:
    app = make_app(cap)

    # FastAPI parses this Form parameter before the dependency runs.
    @app.post("/form-orders", dependencies=[Depends(cap.require("login"))])
    async def form_orders(name: str = Form(...)) -> dict[str, str]:
        return {"name": name}

    return TestClient(app)


def test_token_is_read_from_a_form_body_that_fastapi_already_parsed() -> None:
    pytest.importorskip("multipart")  # FastAPI requires python-multipart to declare Form()
    cap = make_cap()
    client = _form_parameter_client(cap)
    token = _token(client)
    urlencoded = client.post("/form-orders", data={"name": "a", "cap-token": token})
    assert urlencoded.status_code == 200, urlencoded.content
    assert urlencoded.json() == {"name": "a"}
    replay = client.post("/form-orders", data={"name": "a", "cap-token": token})
    assert replay.status_code == 403
    assert replay.json() == {"error": "captcha_required"}
    multipart = client.post(
        "/form-orders", data={"name": "b"}, files={"cap-token": (None, _token(client))}
    )
    assert multipart.status_code == 200, multipart.content


def test_form_parameter_route_without_a_token_is_403() -> None:
    pytest.importorskip("multipart")
    client = _form_parameter_client(make_cap())
    response = client.post("/form-orders", data={"name": "a"})
    assert response.status_code == 403
    assert response.json() == {"error": "captcha_required"}


def test_token_from_a_custom_header_and_field() -> None:
    cap = make_cap()
    app = make_app(cap)

    @app.post("/custom", dependencies=[Depends(cap.require("login", header="X-Mine", field="t"))])
    async def custom() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app)
    token = _token(client)
    assert client.post("/custom", headers={"X-Mine": token}).status_code == 200
    token = _token(client)
    assert client.post("/custom", json={"t": token}).status_code == 200
    token = _token(client)
    assert client.post("/custom", json={"cap-token": token}).status_code == 403


def test_empty_field_disables_the_body_lookup() -> None:
    cap = make_cap()
    app = make_app(cap)

    @app.post("/headers-only", dependencies=[Depends(cap.require("login", field=""))])
    async def headers_only() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app)
    token = _token(client)
    assert client.post("/headers-only", json={"cap-token": token}).status_code == 403
    assert client.post("/headers-only", headers={"X-Cap-Token": token}).status_code == 200


def test_missing_or_malformed_token_is_403_captcha_required(client: TestClient) -> None:
    assert client.post("/orders").json() == {"error": "captcha_required"}
    bad_json = client.post("/orders", content=b"{", headers={"Content-Type": "application/json"})
    assert bad_json.status_code == 403
    array = client.post("/orders", json=["cap-token"])
    assert array.status_code == 403
    assert client.post("/orders", json={"cap-token": 42}).status_code == 403
    assert client.post("/orders", content="plain").status_code == 403
    assert client.post("/orders", headers={"X-Cap-Token": "garbage"}).status_code == 403


def test_oversized_body_is_treated_as_no_token(client: TestClient) -> None:
    blob = b'{"cap-token": "' + b"a" * MAX_BODY + b'"}'
    response = client.post("/orders", content=blob, headers={"Content-Type": "application/json"})
    assert response.status_code == 403
    assert response.json() == {"error": "captcha_required"}


def test_endpoint_can_still_read_the_body_after_the_dependency(client: TestClient) -> None:
    cap = make_cap()
    app = make_app(cap)

    @app.post("/echo", dependencies=[Depends(cap.require("login"))])
    async def echo(request: Request) -> dict[str, Any]:
        return await request.json()

    client = TestClient(app)
    token = _token(client)
    response = client.post("/echo", json={"cap-token": token, "note": "kept"})
    assert response.status_code == 200
    assert response.json() == {"cap-token": token, "note": "kept"}


def test_require_for_an_unknown_site_is_a_programmer_error(cap: Cap) -> None:
    with pytest.raises(CapwxError, match="not configured"):
        cap.require("missing")


def test_require_default_site_is_default_when_configured() -> None:
    cap = make_cap({"default": SHA})
    app = make_app(cap)

    @app.post("/d", dependencies=[Depends(cap.require())])
    async def d() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app)
    assert client.post("/d", headers={"X-Cap-Token": _token(client, "default")}).status_code == 200


def test_captcha_required_body_without_install_is_the_fastapi_default() -> None:
    cap = make_cap()
    app = FastAPI()
    app.include_router(cap.router, prefix=PREFIX)  # no cap.install(app)

    @app.post("/orders", dependencies=[Depends(cap.require("login"))])
    async def orders() -> dict[str, bool]:
        return {"ok": True}

    response = TestClient(app).post("/orders")
    assert response.status_code == 403
    assert response.json() == {"detail": "captcha_required"}


def test_install_does_not_change_other_http_exceptions() -> None:
    cap = make_cap()
    app = make_app(cap)

    @app.get("/missing")
    async def missing() -> None:
        raise HTTPException(status_code=404, detail="nothing here")

    response = TestClient(app).get("/missing")
    assert response.status_code == 404
    assert response.json() == {"detail": "nothing here"}


def test_captcha_required_exception_is_an_http_403() -> None:
    error = CaptchaRequired()
    assert error.status_code == 403
    assert error.detail == "captcha_required"


# --------------------------------------------------------------------------- hooks


def test_before_challenge_blocked_is_403_and_hides_the_message() -> None:
    def refuse(request: Request, site: str) -> None:
        raise Blocked("the reason stays on the server")

    response = TestClient(make_app(make_cap(before_challenge=refuse))).post(
        f"{PREFIX}/login/challenge"
    )
    assert response.status_code == 403
    assert response.json() == {"success": False, "error": "blocked"}
    assert "reason" not in response.text


def test_before_challenge_async_hook_receives_site_and_request() -> None:
    seen: list[tuple[str, str]] = []

    async def record(request: Request, site: str) -> None:
        seen.append((site, type(request).__name__))

    client = TestClient(make_app(make_cap({"login": SHA, "signup": SHA}, before_challenge=record)))
    assert client.post(f"{PREFIX}/login/challenge").status_code == 200
    assert client.post(f"{PREFIX}/signup/challenge").status_code == 200
    assert seen == [("login", "Request"), ("signup", "Request")]


def test_before_challenge_may_raise_an_http_exception() -> None:
    async def teapot(request: Request, site: str) -> None:
        raise HTTPException(status_code=418, detail="short and stout")

    response = TestClient(make_app(make_cap(before_challenge=teapot))).post(
        f"{PREFIX}/login/challenge"
    )
    assert response.status_code == 418
    assert response.json() == {"detail": "short and stout"}


def test_sync_before_challenge_that_returns_normally_allows_the_challenge() -> None:
    client = TestClient(make_app(make_cap(before_challenge=lambda request, site: None)))
    assert client.post(f"{PREFIX}/login/challenge").status_code == 200


def test_difficulty_hook_overrides_the_challenge() -> None:
    def harder(request: Request, site: str) -> dict[str, int]:
        return {"sha256_difficulty": 2, "sha256_count": 2}

    response = TestClient(make_app(make_cap(difficulty_hook=harder))).post(
        f"{PREFIX}/login/challenge"
    )
    challenges = response.json()["challenges"]
    assert len(challenges) == 2
    assert all(len(c["payload"]["target"]) == 2 for c in challenges)


def test_async_difficulty_hook_returning_none_keeps_the_defaults() -> None:
    async def no_change(request: Request, site: str) -> None:
        return None

    response = TestClient(make_app(make_cap(difficulty_hook=no_change))).post(
        f"{PREFIX}/login/challenge"
    )
    assert len(response.json()["challenges"]) == 3


def test_difficulty_hook_returning_a_non_mapping_is_a_programmer_error() -> None:
    def broken(request: Request, site: str) -> str:
        return "harder please"

    client = TestClient(make_app(make_cap(difficulty_hook=broken)))
    with pytest.raises(CapwxError, match="difficulty_hook must return a mapping"):
        client.post(f"{PREFIX}/login/challenge")


def test_difficulty_hook_with_an_invalid_override_raises() -> None:
    def bad(request: Request, site: str) -> dict[str, object]:
        return {"not_a_field": 1}

    client = TestClient(make_app(make_cap(difficulty_hook=bad)))
    with pytest.raises(CapwxError, match="invalid config override"):
        client.post(f"{PREFIX}/login/challenge")


# --------------------------------------------------------------------------- strict CSP


def test_instr_csp_eval_blocked_is_403_via_the_shared_mapping() -> None:
    instrumentation = CapConfig(secret=SECRET, protocols=("instrumentation",))
    app = make_app(make_cap({"login": instrumentation}))
    client = TestClient(app)
    challenge = _challenge(client)
    entry = expected_entries(SECRET, challenge["token"])[0]
    solution = solve_instrumentation(entry)
    solution["instr"]["ce"] = True  # the page's CSP blocked eval
    response = client.post(
        f"{PREFIX}/login/redeem", json={"token": challenge["token"], "solutions": [solution]}
    )
    assert response.status_code == 403
    assert response.json() == {"success": False, "error": "instr_csp_eval_blocked"}


# --------------------------------------------------------------------------- Cap validation


def test_cap_needs_at_least_one_site() -> None:
    with pytest.raises(CapwxError, match="at least one site"):
        Cap({}, store=AsyncMemoryStore())


def test_site_value_must_be_a_config_or_settings() -> None:
    with pytest.raises(CapwxError, match="must be a CapConfig or a SiteSettings"):
        Cap({"login": "not a config"}, store=AsyncMemoryStore())  # type: ignore[dict-item]


def test_site_name_must_be_a_safe_path_segment() -> None:
    with pytest.raises(CapwxError, match="must match"):
        Cap({"bad/name": SHA}, store=AsyncMemoryStore())


@pytest.mark.parametrize("name", [".", ".."])
def test_dot_site_names_are_refused(name: str) -> None:
    with pytest.raises(CapwxError, match="must match"):
        Cap({name: SHA}, store=AsyncMemoryStore())


def test_sync_store_is_rejected() -> None:
    with pytest.raises(CapwxError, match="must be async"):
        Cap({"login": SHA}, store=MemoryStore())


def test_store_without_the_three_methods_is_rejected() -> None:
    with pytest.raises(CapwxError, match="claim\\(\\), put\\(\\) and take\\(\\)"):
        Cap({"login": SHA}, store=object())


def test_hashwx_site_without_wasmtime_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_module, "hashwx_available", lambda: False)
    with pytest.raises(CapwxError, match="uses hashwx"):
        Cap({"login": CapConfig(secret=SECRET)}, store=AsyncMemoryStore())
    Cap({"login": SHA}, store=AsyncMemoryStore())  # sha256-pow sites are fine without it


@pytest.mark.parametrize("label", ["before_challenge", "difficulty_hook"])
def test_hooks_must_be_callable(label: str) -> None:
    with pytest.raises(CapwxError, match=f"{label} must be callable"):
        Cap({"login": SHA}, store=AsyncMemoryStore(), **{label: "a string"})  # type: ignore[arg-type]


@pytest.mark.parametrize("secret", ["", 42, b"x"])
def test_site_secret_must_be_a_non_empty_str(secret: Any) -> None:
    with pytest.raises(CapwxError, match="non-empty"):
        SiteSettings(config=SHA, site_secret=secret)


def test_site_secret_is_not_shown_in_repr() -> None:
    assert SITE_SECRET not in repr(SiteSettings(config=SHA, site_secret=SITE_SECRET))


# --------------------------------------------------------------------------- assets


def test_mount_assets_serves_the_widget_script() -> None:
    app = FastAPI()
    make_cap().mount_assets(app)
    response = TestClient(app).get("/cap-static/cap.min.js")
    assert response.status_code == 200
    assert response.content == (assets_module.ASSETS_DIR / "cap.min.js").read_bytes()


def test_mount_assets_path_is_configurable() -> None:
    app = FastAPI()
    make_cap().mount_assets(app, path="/static/capwx")
    assert TestClient(app).get("/static/capwx/hashwx.wasm").status_code == 200


def _copy_assets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    copied = tmp_path / "assets"
    shutil.copytree(assets_module.ASSETS_DIR, copied)
    monkeypatch.setattr(assets_module, "ASSETS_DIR", copied)
    return copied


def test_tampered_asset_is_refused_and_nothing_is_mounted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    copied = _copy_assets(tmp_path, monkeypatch)
    (copied / "cap.min.js").write_bytes(b"alert('pwned')")
    app = FastAPI()
    before = len(app.routes)
    with pytest.raises(CapwxError, match="cap.min.js does not match"):
        make_cap().mount_assets(app)
    assert len(app.routes) == before


def test_missing_asset_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    copied = _copy_assets(tmp_path, monkeypatch)
    (copied / "pako_inflate.min.js").unlink()
    with pytest.raises(CapwxError, match="pako_inflate.min.js is missing"):
        make_cap().mount_assets(FastAPI())


@pytest.mark.parametrize(
    ("manifest", "message"),
    [
        ("{", "cannot read the asset manifest"),
        ("[]", "no 'files' object"),
    ],
)
def test_bad_manifest_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, manifest: str, message: str
) -> None:
    copied = _copy_assets(tmp_path, monkeypatch)
    (copied / "VERSIONS.json").write_text(manifest, encoding="utf-8")
    with pytest.raises(CapwxError, match=message):
        make_cap().mount_assets(FastAPI())


def test_manifest_entry_without_sha256_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    copied = _copy_assets(tmp_path, monkeypatch)
    manifest = json.loads((copied / "VERSIONS.json").read_text(encoding="utf-8"))
    manifest["files"]["cap.min.js"] = {}
    (copied / "VERSIONS.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(CapwxError, match="no sha256 for cap.min.js"):
        make_cap().mount_assets(FastAPI())


@pytest.mark.parametrize(
    "name", ["cap.min.js", "cap_wasm_bg.wasm", "hashwx.wasm", "pako_inflate.min.js"]
)
def test_manifest_without_a_required_entry_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    copied = _copy_assets(tmp_path, monkeypatch)
    manifest = json.loads((copied / "VERSIONS.json").read_text(encoding="utf-8"))
    del manifest["files"][name]
    (copied / "VERSIONS.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(CapwxError, match=f"no entry for {name}"):
        make_cap().mount_assets(FastAPI())


def test_empty_manifest_files_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    copied = _copy_assets(tmp_path, monkeypatch)
    (copied / "VERSIONS.json").write_text('{"files": {}}', encoding="utf-8")
    with pytest.raises(CapwxError, match="no entry for cap.min.js"):
        assets_module.check_assets()


def test_unreadable_asset_is_a_capwx_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(self: Path) -> bytes:
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "read_bytes", refuse)
    with pytest.raises(CapwxError, match="cannot read vendored asset cap.min.js"):
        assets_module.check_assets()


def test_check_assets_passes_for_the_vendored_files() -> None:
    assets_module.check_assets()  # must not raise


# --------------------------------------------------------------------------- templates


def test_scripts_without_a_nonce_matches_the_django_layout() -> None:
    expected = (
        "<script>\n"
        '  window.CAP_CUSTOM_HASHWX_URL = "/cap-static/hashwx.wasm";\n'
        '  window.CAP_CUSTOM_WASM_URL = "/cap-static/cap_wasm_bg.wasm";\n'
        '  window.CAP_PAKO_URL = "/cap-static/pako_inflate.min.js";\n'
        "</script>\n"
        '<script src="/cap-static/cap.min.js" defer></script>'
    )
    assert make_cap().scripts() == expected


def test_scripts_with_a_nonce_sets_both_nonces_and_the_attributes() -> None:
    out = make_cap().scripts(nonce="abc123")
    assert out.startswith('<script nonce="abc123">\n')
    assert '  window.CAP_SCRIPT_NONCE = "abc123";' in out
    assert '  window.CAP_CSS_NONCE = "abc123";' in out
    assert out.endswith('<script src="/cap-static/cap.min.js" defer nonce="abc123"></script>')


def test_scripts_uses_the_cap_default_nonce_unless_overridden() -> None:
    cap = make_cap(script_nonce="from-cap")
    assert 'nonce="from-cap"' in cap.scripts()
    assert 'nonce="explicit"' in cap.scripts(nonce="explicit")
    assert "from-cap" not in cap.scripts(nonce="explicit")


def test_scripts_escapes_hostile_values() -> None:
    nonce = '"></script><script>alert(1)//&'
    out = make_cap().scripts(nonce=nonce)
    assert "<script>alert" not in out
    assert "</script><script>" not in out
    assert "\\u003c/script\\u003e" in out
    assert "&amp;" in out
    assert "&quot;" in out


def test_scripts_static_path_is_normalised() -> None:
    out = make_cap().scripts(static_path="/static/")
    assert '"/static/hashwx.wasm"' in out
    assert 'src="/static/cap.min.js"' in out


def test_widget_renders_the_cap_widget_element() -> None:
    cap = make_cap({"login": SHA, "signup": SHA})
    assert cap.widget("login") == (
        '<cap-widget data-cap-api-endpoint="/cap/login/" data-cap-hidden-field-name="cap-token">'
        '<input type="hidden" name="cap-token" value=""></cap-widget>'
    )


def test_widget_escapes_endpoint_and_field() -> None:
    out = make_cap().widget("login", endpoint='/x"onmouseover="a', field='t"x')
    assert 'data-cap-api-endpoint="/x&quot;onmouseover=&quot;a"' in out
    assert 'name="t&quot;x"' in out
    assert '"onmouseover' not in out


def test_widget_for_an_unknown_site_is_a_programmer_error() -> None:
    with pytest.raises(CapwxError, match="not configured"):
        make_cap().widget("missing")


def test_templates_return_plain_strings() -> None:
    cap = make_cap()
    assert type(cap.scripts()) is str
    assert type(cap.widget("login")) is str


# --------------------------------------------------------------------------- packaging


def test_import_capwx_does_not_import_fastapi_starlette_or_wasmtime() -> None:
    code = (
        "import sys, capwx\n"
        "print([m for m in ('fastapi', 'starlette', 'wasmtime') if m in sys.modules])\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, timeout=180
    )
    assert done.stdout.strip() == "[]"


def test_importing_the_contrib_without_fastapi_gives_the_install_hint() -> None:
    code = (
        "import importlib.abc, sys\n"
        "class Block(importlib.abc.MetaPathFinder):\n"
        "    def find_spec(self, name, path, target=None):\n"
        "        if name.split('.')[0] in ('fastapi', 'starlette'):\n"
        "            raise ModuleNotFoundError(f'No module named {name!r}', name=name)\n"
        "        return None\n"
        "sys.meta_path.insert(0, Block())\n"
        "import capwx.contrib.fastapi\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False, timeout=180
    )
    assert done.returncode != 0
    assert "pip install 'capwx[fastapi]'" in done.stderr
    assert "ImportError" in done.stderr


def test_package_exports() -> None:
    import capwx.contrib.fastapi as package

    assert set(package.__all__) == {"Blocked", "Cap", "SiteSettings"}
    assert package.Cap is Cap
