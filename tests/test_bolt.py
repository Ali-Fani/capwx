"""Tests for capwx.contrib.bolt (django-bolt): the widget endpoints, CapRequired, hooks and CSRF.

The API lives in tests/django_project/bolt_api.py and is driven by django-bolt's own in-process
``TestClient`` (no Rust HTTP server is started). The widget is replaced by tests/_solver.py. The
whole module is skipped on Python < 3.12 and when django-bolt is not installed.
"""

from __future__ import annotations

import copy
import importlib
import logging
import sys
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest

if sys.version_info[:2] < (3, 12):
    pytest.skip("django-bolt needs Python 3.12 or newer", allow_module_level=True)
pytest.importorskip("django_bolt")

from _solver import body_for
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.middleware.csrf import _get_new_csrf_string, _mask_cipher_secret
from django.test import override_settings
from django_bolt.testing import TestClient

from capwx.contrib.bolt import router as bolt_router
from tests.django_project import hooks
from tests.django_project.bolt_api import api

BASE = copy.deepcopy(settings.CAPWX)
SECRET = BASE["SECRET"]
LOGIN_SITE_SECRET = BASE["SITES"]["login"]["SITE_SECRET"]
MAX_BODY = 64 * 1024


def _capwx(**changes: Any) -> dict[str, Any]:
    cfg = copy.deepcopy(BASE)
    cfg.update(changes)
    return cfg


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    with TestClient(api) as test_client:
        yield test_client


def _post_json(client: TestClient, url: str, body: object, **headers: str) -> Any:
    return client.post(url, json=body, headers=headers or None)


def _challenge(client: TestClient, site: str = "login", **headers: str) -> dict[str, Any]:
    response = client.post(f"/cap/{site}/challenge", headers=headers or None)
    assert response.status_code == 200, response.text
    data: dict[str, Any] = response.json()
    return data


def _verification_token(client: TestClient, site: str = "login", **headers: str) -> str:
    challenge = _challenge(client, site, **headers)
    response = _post_json(client, f"/cap/{site}/redeem", body_for(SECRET, challenge), **headers)
    assert response.status_code == 200, response.text
    token: str = response.json()["token"]
    return token


# --------------------------------------------------------------------------- challenge and redeem


def test_challenge_shape_headers_and_protocols(client):
    response = client.post("/cap/login/challenge")
    assert response.status_code == 200
    assert "no-store" in response.headers["cache-control"]
    data = response.json()
    assert data["format"] == 2
    assert data["expires"] > 0
    assert [c["protocol"] for c in data["challenges"]] == ["hashwx"] * 4 + ["instrumentation"]

    signup = client.post("/cap/signup/challenge").json()
    assert {c["protocol"] for c in signup["challenges"]} == {"sha256-pow"}


def test_full_flow_challenge_solve_redeem_then_validate_once(client):
    token = _verification_token(client, "login")
    assert token.startswith("login:")

    first = client.post("/protected", headers={"X-Cap-Token": token})
    assert first.status_code == 200
    assert first.json() == {"ok": True}

    replay = client.post("/protected", headers={"X-Cap-Token": token})
    assert replay.status_code == 403
    assert replay.json() == {"error": "captcha_required"}


def test_sha256_site_flow_also_redeems(client):
    challenge = client.post("/cap/signup/challenge").json()
    response = _post_json(client, "/cap/signup/redeem", body_for(SECRET, challenge))
    assert response.status_code == 200
    assert response.json()["success"] is True


def test_redeem_replay_is_rejected_with_403(client):
    challenge = _challenge(client, "login")
    body = body_for(SECRET, challenge)
    assert _post_json(client, "/cap/login/redeem", body).status_code == 200
    response = _post_json(client, "/cap/login/redeem", body)
    assert response.status_code == 403
    assert response.json() == {"success": False, "error": "already_redeemed"}


def test_redeem_with_wrong_solutions_is_400_or_403(client):
    challenge = _challenge(client, "login")
    response = _post_json(
        client, "/cap/login/redeem", {"token": challenge["token"], "solutions": []}
    )
    assert response.status_code in (400, 403)
    assert response.json()["success"] is False


def test_unknown_site_is_404_json(client):
    for path in ("challenge", "redeem", "siteverify"):
        response = client.post(f"/cap/nope/{path}", json={})
        assert response.status_code == 404
        assert response.json() == {"error": "Invalid site key"}


@pytest.mark.parametrize("method", ["get", "put", "patch", "delete", "head", "options"])
def test_wrong_method_is_405_json_with_allow(client, method):
    response = client.request(method.upper(), "/cap/login/challenge")
    assert response.status_code == 405
    assert response.headers["allow"] == "POST"
    if method != "head":  # HEAD responses carry no body
        assert response.json() == {"error": "method_not_allowed"}


def test_body_over_64_kib_is_413(client):
    response = client.post(
        "/cap/login/redeem",
        content=b"x" * (MAX_BODY + 1),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json() == {"success": False, "error": "body_too_large"}


def test_body_exactly_64_kib_is_not_rejected_for_size(client):
    response = client.post(
        "/cap/login/redeem",
        content=b" " * MAX_BODY,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400  # padded, still malformed: size is accepted


def test_declared_content_length_over_limit_is_413_without_reading():
    request = SimpleNamespace(headers={"content-length": str(MAX_BODY + 1)}, body=b"{}")
    assert bolt_router._read_body(request) is None
    small = SimpleNamespace(headers={"content-length": "2"}, body=b"{}")
    assert bolt_router._read_body(small) == b"{}"


def test_malformed_json_is_400_invalid_body(client):
    for raw in (b"{nope", b"\xff\xfe", b"[1, 2]"):
        response = client.post(
            "/cap/login/redeem", content=raw, headers={"content-type": "application/json"}
        )
        assert response.status_code == 400, raw
        assert response.json()["success"] is False


# --------------------------------------------------------------------------- siteverify


def test_siteverify_consumes_token_once(client):
    token = _verification_token(client, "login")
    url = "/cap/login/siteverify"
    ok = _post_json(client, url, {"secret": LOGIN_SITE_SECRET, "response": token})
    assert ok.status_code == 200
    assert ok.json() == {"success": True}

    again = _post_json(client, url, {"secret": LOGIN_SITE_SECRET, "response": token})
    assert again.status_code == 400
    assert again.json()["error"] == "invalid_token"


def test_siteverify_wrong_secret_is_403_and_does_not_burn_token(client):
    token = _verification_token(client, "login")
    wrong = _post_json(client, "/cap/login/siteverify", {"secret": "nope", "response": token})
    assert wrong.status_code == 403
    assert wrong.json()["error"] == "invalid_secret"

    good = _post_json(
        client, "/cap/login/siteverify", {"secret": LOGIN_SITE_SECRET, "response": token}
    )
    assert good.status_code == 200


def test_siteverify_missing_parameters_and_bad_json(client):
    missing = _post_json(client, "/cap/login/siteverify", {"secret": LOGIN_SITE_SECRET})
    assert missing.status_code == 400
    assert missing.json()["error"] == "missing_parameters"
    bad = client.post("/cap/login/siteverify", content=b"{nope")
    assert bad.status_code == 400
    assert bad.json() == {"success": False, "error": "invalid_body"}


def test_siteverify_not_configured_for_site_without_site_secret(client):
    response = _post_json(client, "/cap/strict/siteverify", {"secret": "x", "response": "y"})
    assert response.status_code == 404
    assert response.json() == {"success": False, "error": "siteverify_not_configured"}


# --------------------------------------------------------------------------- CapRequired


def test_cap_required_rejects_missing_and_wrong_tokens(client):
    assert client.post("/protected").json() == {"error": "captcha_required"}
    assert client.post("/protected").status_code == 403
    bogus = client.post("/protected", headers={"X-Cap-Token": "login:nonsense"})
    assert bogus.status_code == 403
    assert bogus.json() == {"error": "captcha_required"}


def test_cap_required_rejects_token_issued_for_another_site(client):
    signup_challenge = client.post("/cap/signup/challenge").json()
    signup_token = _post_json(
        client, "/cap/signup/redeem", body_for(SECRET, signup_challenge)
    ).json()["token"]
    response = client.post("/protected", headers={"X-Cap-Token": signup_token})
    assert response.status_code == 403
    assert response.json() == {"error": "captcha_required"}


def test_cap_required_reads_json_body_field(client):
    token = _verification_token(client, "login")
    response = client.post(
        "/protected",
        json={"cap-token": token},
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 200
    assert client.post("/protected", json={"cap-token": token}).status_code == 403  # consumed


def test_cap_required_reads_form_field(client):
    token = _verification_token(client, "login")
    response = client.post("/protected", data={"cap-token": token})
    assert response.status_code == 200


def test_header_only_cap_required_ignores_body_field(client):
    token = _verification_token(client, "login")
    assert client.post("/header-only", json={"cap-token": token}).status_code == 403
    assert client.post("/header-only", headers={"X-Cap-Token": token}).status_code == 200


def test_cap_required_does_not_log_the_token(client, caplog):
    token = _verification_token(client, "login")
    with caplog.at_level(logging.DEBUG, logger="capwx"):
        client.post("/protected", headers={"X-Cap-Token": token})
        client.post("/protected", headers={"X-Cap-Token": "login:bad"})
    assert token not in caplog.text


# --------------------------------------------------------------------------- hooks


def test_difficulty_hook_sees_bolt_headers(client):
    hooks.CALLS.clear()
    plain = _challenge(client, "login")
    hard = _challenge(client, "login", **{"X-Hard": "1"})
    plain_d = {c["payload"]["d"] for c in plain["challenges"] if c["protocol"] == "hashwx"}
    hard_d = {c["payload"]["d"] for c in hard["challenges"] if c["protocol"] == "hashwx"}
    assert plain_d == {250}
    assert hard_d == {1000}
    assert ("difficulty", "login") in hooks.CALLS


def _block_when_header(request, site):
    if request.META.get("HTTP_X_BLOCK"):
        raise PermissionDenied("blocked by test hook")


def test_before_challenge_hook_blocks_with_403(client):
    cfg = _capwx(BEFORE_CHALLENGE_HOOK=_block_when_header)
    with override_settings(CAPWX=cfg):
        blocked = client.post("/cap/login/challenge", headers={"X-Block": "1"})
        assert blocked.status_code == 403
        assert blocked.json() == {"success": False, "error": "blocked"}
        allowed = client.post("/cap/login/challenge")
        assert allowed.status_code == 200


def test_hook_receives_a_django_http_request_shim(client):
    seen = {}

    def spy(request, site):
        seen["meta_ua"] = request.META.get("HTTP_USER_AGENT")
        seen["path"] = request.path
        seen["method"] = request.method

    with override_settings(CAPWX=_capwx(DIFFICULTY_HOOK=spy)):
        client.post("/cap/login/challenge", headers={"User-Agent": "capwx-test"})
    assert seen == {"meta_ua": "capwx-test", "path": "/cap/login/challenge", "method": "POST"}


# --------------------------------------------------------------------------- CSRF


def test_csrf_enforced_when_csrf_exempt_is_false(client):
    cfg = _capwx(CSRF_EXEMPT=False)
    with override_settings(CAPWX=cfg):
        denied = client.post("/cap/login/challenge")
        assert denied.status_code == 403
        assert denied.json() == {"success": False, "error": "csrf_failed"}

        secret = _get_new_csrf_string()
        client.cookies.set("csrftoken", secret)
        try:
            ok = client.post(
                "/cap/login/challenge", headers={"X-CSRFToken": _mask_cipher_secret(secret)}
            )
            assert ok.status_code == 200
        finally:
            client.cookies.delete("csrftoken")


# --------------------------------------------------------------------------- install and imports


def test_install_mounts_post_routes_under_cap_prefix(client):
    posts = {path for method, path, _id, _fn in api._routes if method == "POST"}  # pyright: ignore
    assert {"/cap/{site}/challenge", "/cap/{site}/redeem", "/cap/{site}/siteverify"} <= posts
    schema = client.get("/docs/openapi.json")
    if schema.status_code == 200:
        assert "/cap/{site}/challenge" in schema.json()["paths"]


def test_missing_django_bolt_gives_a_clear_import_error(monkeypatch):
    for name in [m for m in sys.modules if m.startswith("capwx.contrib.bolt")]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setitem(sys.modules, "django_bolt", None)
    with pytest.raises(ImportError, match="pip install 'capwx\\[bolt\\]'"):
        importlib.import_module("capwx.contrib.bolt")
