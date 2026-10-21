"""Tests for capwx.contrib.ninja (M11): the widget router, CapRequired, install() and CSRF.

The NinjaAPI lives in tests/django_project/urls_ninja.py. Each test selects it with the pytest-django
``settings`` fixture (ROOT_URLCONF), so tests/test_django.py keeps its own urls module. The whole
module is skipped when django-ninja is not installed.
"""

from __future__ import annotations

import copy
import json

import pytest

pytest.importorskip("ninja")

from _solver import body_for
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.middleware.csrf import get_token
from django.test import Client, RequestFactory, override_settings
from django.urls import resolve

from capwx.contrib.django import conf
from capwx.contrib.ninja import CapRequired
from capwx.tokens import validate_token

BASE = copy.deepcopy(settings.CAPWX)
SECRET = BASE["SECRET"]
LOGIN_SITE_SECRET = BASE["SITES"]["login"]["SITE_SECRET"]
MAX_BODY = 64 * 1024
PREFIX = "/api/cap"


@pytest.fixture(autouse=True)
def ninja_urls(settings):
    settings.ROOT_URLCONF = "tests.django_project.urls_ninja"
    return settings


def _capwx(sites: dict | None = None, **changes) -> dict:
    cfg = copy.deepcopy(BASE)
    for name, change in (sites or {}).items():
        cfg["SITES"].setdefault(name, {}).update(change)
    cfg.update(changes)
    return cfg


def _post_json(client: Client, url: str, body: object, **extra: str):
    return client.post(url, data=json.dumps(body), content_type="application/json", **extra)


def _challenge(client: Client, site: str = "login", **extra: str) -> dict:
    response = client.post(f"{PREFIX}/{site}/challenge", **extra)
    assert response.status_code == 200, response.content
    return response.json()


def _verification_token(client: Client, site: str = "login", **extra: str) -> str:
    challenge = _challenge(client, site, **extra)
    response = _post_json(client, f"{PREFIX}/{site}/redeem", body_for(SECRET, challenge), **extra)
    assert response.status_code == 200, response.content
    return response.json()["token"]


# --------------------------------------------------------------------------- challenge and flow


def test_challenge_is_format_two_with_expected_protocols(client):
    response = client.post(f"{PREFIX}/login/challenge")
    assert response.status_code == 200
    assert "no-store" in response["Cache-Control"]
    data = response.json()
    assert data["format"] == 2
    assert [c["protocol"] for c in data["challenges"]] == ["hashwx"] * 4 + ["instrumentation"]
    assert data["expires"] > 0

    signup = client.post(f"{PREFIX}/signup/challenge").json()
    assert {c["protocol"] for c in signup["challenges"]} == {"sha256-pow"}


def test_full_flow_challenge_solve_redeem_validate_consumes_once(client):
    with override_settings(CAPWX=_capwx(sites={"login": {"INSTRUMENTATION": {"ENABLED": False}}})):
        challenge = _challenge(client, "login")
        response = _post_json(client, f"{PREFIX}/login/redeem", body_for(SECRET, challenge))
        assert response.status_code == 200, response.content
        data = response.json()
        assert data["success"] is True
        assert set(data) == {"success", "token", "expires"}

        site = conf.get_site("login")
        store = conf.get_conf().store
        assert validate_token(site.config, data["token"], scope="login", token_store=store)
        assert not validate_token(site.config, data["token"], scope="login", token_store=store)


def test_full_flow_with_instrumentation_enabled(client):
    challenge = _challenge(client, "login")
    response = _post_json(client, f"{PREFIX}/login/redeem", body_for(SECRET, challenge))
    assert response.status_code == 200, response.content
    assert response.json()["success"] is True


def test_replay_of_same_redeem_body_is_already_redeemed(client):
    challenge = _challenge(client, "login")
    body = body_for(SECRET, challenge)
    assert _post_json(client, f"{PREFIX}/login/redeem", body).status_code == 200
    second = _post_json(client, f"{PREFIX}/login/redeem", body)
    assert second.status_code == 403
    assert second.json() == {"success": False, "error": "already_redeemed"}


def test_redeem_with_token_for_another_site_is_scope_mismatch(client):
    challenge = _challenge(client, "signup")
    response = _post_json(client, f"{PREFIX}/login/redeem", body_for(SECRET, challenge))
    assert response.status_code == 403
    assert response.json() == {"success": False, "error": "scope_mismatch"}


def test_wrong_solution_is_invalid_solution_400(client):
    challenge = _challenge(client, "signup")
    body = {"token": challenge["token"], "solutions": [{"nonce": "x"}] * 50}
    response = _post_json(client, f"{PREFIX}/signup/redeem", body)
    assert response.status_code == 400
    assert response.json() == {"success": False, "error": "invalid_solution"}


# --------------------------------------------------------------------------- site, method, size


@pytest.mark.parametrize("path", ["challenge", "redeem", "siteverify"])
def test_unknown_site_is_404(client, path):
    response = client.post(f"{PREFIX}/nope/{path}", data="{}", content_type="application/json")
    assert response.status_code == 404
    assert response.json() == {"error": "Invalid site key"}


@pytest.mark.parametrize("path", ["challenge", "redeem", "siteverify"])
@pytest.mark.parametrize("method", ["get", "put"])
def test_non_post_is_405_json_like_django(client, path, method):
    response = getattr(client, method)(f"{PREFIX}/login/{path}")
    assert response.status_code == 405
    assert response["Allow"] == "POST"
    assert response.json() == {"error": "method_not_allowed"}


def test_oversized_body_is_413_by_content_length(client):
    response = client.post(
        f"{PREFIX}/login/redeem", data=b"x" * (MAX_BODY + 1), content_type="application/json"
    )
    assert response.status_code == 413
    assert response.json() == {"success": False, "error": "body_too_large"}


def test_oversized_body_is_413_when_content_length_is_missing():
    # The test client always sets CONTENT_LENGTH, so resolve the ninja route and call it directly.
    url = f"{PREFIX}/login/redeem"
    request = RequestFactory().post(
        url, data=b"{" + b" " * MAX_BODY + b"}", content_type="application/json"
    )
    del request.META["CONTENT_LENGTH"]
    match = resolve(url)
    response = match.func(request, *match.args, **match.kwargs)
    assert response.status_code == 413
    assert json.loads(response.content) == {"success": False, "error": "body_too_large"}


def test_malformed_json_is_400_invalid_body(client):
    for raw in (b"{not json", b"\xff\xfe", b"[1, 2]", b""):
        response = client.post(f"{PREFIX}/login/redeem", data=raw, content_type="application/json")
        assert response.status_code == 400, raw
        assert response.json() == {"success": False, "error": "invalid_body"}


# --------------------------------------------------------------------------- siteverify


def test_siteverify_success_failure_and_single_use(client):
    token = _verification_token(client, "login")
    url = f"{PREFIX}/login/siteverify"

    wrong = _post_json(client, url, {"secret": "not-the-secret", "response": token})
    assert wrong.status_code == 403
    assert wrong.json() == {"success": False, "error": "invalid_secret"}

    missing = _post_json(client, url, {"response": token})
    assert missing.status_code == 400
    assert missing.json() == {"success": False, "error": "missing_parameters"}

    ok = _post_json(client, url, {"secret": LOGIN_SITE_SECRET, "response": token})
    assert ok.status_code == 200
    assert ok.json() == {"success": True}

    again = _post_json(client, url, {"secret": LOGIN_SITE_SECRET, "response": token})
    assert again.status_code == 400
    assert again.json() == {"success": False, "error": "invalid_token"}


def test_siteverify_without_site_secret_is_404(client):
    response = _post_json(client, f"{PREFIX}/strict/siteverify", {"secret": "x", "response": "y"})
    assert response.status_code == 404
    assert response.json()["error"] == "siteverify_not_configured"


# --------------------------------------------------------------------------- CapRequired


def test_cap_required_accepts_header_token_once_then_rejects_replay(client):
    token = _verification_token(client, "login")
    assert client.post("/api/protected", HTTP_X_CAP_TOKEN=token).status_code == 200
    replay = client.post("/api/protected", HTTP_X_CAP_TOKEN=token)
    assert replay.status_code == 403
    assert replay.json() == {"error": "captcha_required"}


def test_cap_required_reads_json_field_and_rejects_missing(client):
    url = "/api/protected"
    missing = client.post(url)
    assert missing.status_code == 403
    assert missing.json() == {"error": "captcha_required"}

    token = _verification_token(client, "login")
    ok = _post_json(client, url, {"cap-token": token})
    assert ok.status_code == 200


def test_cap_required_reads_form_field(client):
    token = _verification_token(client, "login")
    assert client.post("/api/protected", {"cap-token": token}).status_code == 200


def test_cap_required_rejects_garbage_token(client):
    response = client.post("/api/protected", HTTP_X_CAP_TOKEN="garbage")
    assert response.status_code == 403
    assert response.json() == {"error": "captcha_required"}


def test_cap_required_with_empty_field_ignores_body_token(client):
    token = _verification_token(client, "login")
    rejected = _post_json(client, "/api/header-only", {"cap-token": token})
    assert rejected.status_code == 403
    assert rejected.json() == {"error": "captcha_required"}
    assert client.post("/api/header-only", HTTP_X_CAP_TOKEN=token).status_code == 200


def test_cap_required_without_install_uses_ninja_detail_body(client):
    token = _verification_token(client, "login")
    missing = client.post("/plain/protected")
    assert missing.status_code == 403
    assert missing.json() == {"detail": "captcha_required"}
    assert client.post("/plain/protected", HTTP_X_CAP_TOKEN=token).status_code == 200


def test_cap_required_unknown_site_is_a_configuration_error():
    auth = CapRequired(site="missing")
    request = RequestFactory().post("/api/protected", HTTP_X_CAP_TOKEN="x")
    with pytest.raises(ImproperlyConfigured, match="not configured"):
        auth(request)


def test_cap_required_security_scheme_is_a_header_api_key():
    auth = CapRequired(site="login")
    assert auth.openapi_security_schema["type"] == "apiKey"
    assert auth.openapi_security_schema["in"] == "header"
    assert auth.openapi_security_schema["name"] == "X-Cap-Token"


# --------------------------------------------------------------------------- CSRF


def test_csrf_exempt_true_allows_post_without_token():
    client = Client(enforce_csrf_checks=True)
    assert client.post(f"{PREFIX}/login/challenge").status_code == 200


def test_csrf_exempt_false_is_enforced_on_ninja_endpoints():
    with override_settings(CAPWX=_capwx(CSRF_EXEMPT=False)):
        client = Client(enforce_csrf_checks=True)
        denied = client.post(f"{PREFIX}/login/challenge")
        assert denied.status_code == 403
        assert denied.json() == {"success": False, "error": "csrf_failed"}

        # The ninja urls have no page that sets the cookie, so mint the token the way Django does.
        factory_request = RequestFactory().get("/")
        token = get_token(factory_request)
        client.cookies[settings.CSRF_COOKIE_NAME] = factory_request.META["CSRF_COOKIE"]
        challenge = _challenge(client, "login", HTTP_X_CSRFTOKEN=token)
        response = _post_json(
            client, f"{PREFIX}/login/redeem", body_for(SECRET, challenge), HTTP_X_CSRFTOKEN=token
        )
        assert response.status_code == 200, response.content


# --------------------------------------------------------------------------- OpenAPI document


def test_openapi_document_lists_the_widget_operations_without_get():
    response = Client().get("/api/openapi.json")
    assert response.status_code == 200
    paths = response.json()["paths"]
    for name in ("challenge", "redeem", "siteverify"):
        operation = paths[f"/api/cap/{{site}}/{name}"]
        assert set(operation) == {"post"}, f"{name} must not advertise a GET operation"
    redeem_body = paths["/api/cap/{site}/redeem"]["post"]["requestBody"]
    schema = redeem_body["content"]["application/json"]["schema"]
    assert {"token", "solutions"} <= set(schema["properties"])
    assert paths["/api/cap/{site}/challenge"]["post"]["tags"] == ["capwx"]
