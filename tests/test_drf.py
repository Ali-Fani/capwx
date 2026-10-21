"""Tests for capwx.contrib.drf (the DRF widget views, IsCapVerified, CapTokenField) and CSRF.

The DRF urls and sample views live in tests/django_project/urls_drf.py. Each test selects that
urlconf with the pytest-django ``settings`` fixture (ROOT_URLCONF), as tests/test_ninja.py does. The
whole module is skipped when djangorestframework is not installed.
"""

from __future__ import annotations

import copy
import json

import pytest

pytest.importorskip("rest_framework")

from _solver import body_for
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.middleware.csrf import get_token
from django.test import Client, RequestFactory, override_settings
from django.urls import resolve
from rest_framework.request import Request

from capwx.contrib.django import conf
from capwx.contrib.drf import CaptchaRequired, CapTokenField, IsCapVerified, cap_permission
from capwx.tokens import validate_token

BASE = copy.deepcopy(settings.CAPWX)
SECRET = BASE["SECRET"]
LOGIN_SITE_SECRET = BASE["SITES"]["login"]["SITE_SECRET"]
MAX_BODY = 64 * 1024
PREFIX = "/drf/cap"
PROTECTED = "/drf/protected"
CAPTCHA_REQUIRED = {"error": "captcha_required"}
VERIFY_MESSAGE = "Please complete the verification."


@pytest.fixture(autouse=True)
def drf_urls(settings):
    settings.ROOT_URLCONF = "tests.django_project.urls_drf"
    # DRF's default anonymous user is django.contrib.auth's model, which needs auth in
    # INSTALLED_APPS. The test project has no auth app, so use no user object instead. The capwx
    # endpoints never read request.user, so this changes nothing they do.
    settings.REST_FRAMEWORK = {"UNAUTHENTICATED_USER": None}
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


def _login_store():
    return conf.get_site("login").config, conf.get_conf().store


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
    challenge = _challenge(client, "login")
    response = _post_json(client, f"{PREFIX}/login/redeem", body_for(SECRET, challenge))
    assert response.status_code == 200, response.content
    data = response.json()
    assert data["success"] is True
    assert set(data) == {"success", "token", "expires"}

    site_config, store = _login_store()
    assert validate_token(site_config, data["token"], scope="login", token_store=store)
    assert not validate_token(site_config, data["token"], scope="login", token_store=store)


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
@pytest.mark.parametrize("method", ["get", "put", "patch", "delete", "options", "head"])
def test_non_post_is_405_json_with_allow_post(client, path, method):
    response = getattr(client, method)(f"{PREFIX}/login/{path}")
    assert response.status_code == 405
    assert response["Allow"] == "POST"
    if method != "head":  # HEAD responses carry no body
        assert response.json() == {"error": "method_not_allowed"}


@pytest.mark.parametrize("accept", ["text/plain", "application/xml", "*/*;q=0"])
def test_unsatisfiable_accept_header_is_not_406(client, accept):
    # DRF's content negotiation would answer 406 here. The Django view answers as usual.
    response = client.post(f"{PREFIX}/login/challenge", HTTP_ACCEPT=accept)
    assert response.status_code == 200


def test_unknown_site_and_method_match_the_django_urls(client):
    django_client = Client()
    for method, path in (("post", "unknown/challenge"), ("get", "login/challenge")):
        drf = getattr(client, method)(f"{PREFIX}/{path}")
        plain = getattr(django_client, method)(f"/cap/{path}")
        assert drf.status_code == plain.status_code
        assert drf.json() == plain.json()
        assert drf.get("Allow") == plain.get("Allow")


def test_oversized_body_is_413_by_content_length(client):
    response = client.post(
        f"{PREFIX}/login/redeem", data=b"x" * (MAX_BODY + 1), content_type="application/json"
    )
    assert response.status_code == 413
    assert response.json() == {"success": False, "error": "body_too_large"}


def test_oversized_body_is_413_when_content_length_is_missing():
    # The test client always sets CONTENT_LENGTH, so resolve the route and call it directly.
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


# --------------------------------------------------------------------------- IsCapVerified


def test_permission_accepts_header_token_once_then_rejects_replay(client):
    token = _verification_token(client, "login")
    assert client.post(PROTECTED, HTTP_X_CAP_TOKEN=token).status_code == 200
    replay = client.post(PROTECTED, HTTP_X_CAP_TOKEN=token)
    assert replay.status_code == 403
    assert replay.json() == CAPTCHA_REQUIRED


def test_permission_reads_json_body_field_and_rejects_missing(client):
    missing = client.post(PROTECTED)
    assert missing.status_code == 403
    assert missing.json() == CAPTCHA_REQUIRED

    token = _verification_token(client, "login")
    assert _post_json(client, PROTECTED, {"cap-token": token}).status_code == 200


def test_permission_reads_form_field(client):
    token = _verification_token(client, "login")
    assert client.post(PROTECTED, {"cap-token": token}).status_code == 200


def test_permission_rejects_garbage_token(client):
    response = client.post(PROTECTED, HTTP_X_CAP_TOKEN="garbage")
    assert response.status_code == 403
    assert response.json() == CAPTCHA_REQUIRED


def test_permission_rejects_malformed_json_body_without_a_token(client):
    response = client.post(PROTECTED, data=b"{not json", content_type="application/json")
    assert response.status_code == 403
    assert response.json() == CAPTCHA_REQUIRED


def test_header_wins_over_body_field_and_the_body_token_is_not_consumed(client):
    token = _verification_token(client, "login")
    rejected = _post_json(client, PROTECTED, {"cap-token": token}, HTTP_X_CAP_TOKEN="garbage")
    assert rejected.status_code == 403
    assert rejected.json() == CAPTCHA_REQUIRED
    # The header decided, so the body token was never checked and is still usable.
    assert _post_json(client, PROTECTED, {"cap-token": token}).status_code == 200


def test_empty_field_ignores_body_token(client):
    token = _verification_token(client, "login")
    rejected = _post_json(client, "/drf/header-only", {"cap-token": token})
    assert rejected.status_code == 403
    assert rejected.json() == CAPTCHA_REQUIRED
    assert client.post("/drf/header-only", HTTP_X_CAP_TOKEN=token).status_code == 200


def test_captcha_failure_is_403_not_401_with_drf_authentication(client):
    # BasicAuthentication would answer 401 with a WWW-Authenticate header from permission_denied.
    token = _verification_token(client, "login")
    missing = client.post("/drf/basic-protected")
    assert missing.status_code == 403
    assert missing.json() == CAPTCHA_REQUIRED
    assert client.post("/drf/basic-protected", HTTP_X_CAP_TOKEN=token).status_code == 200


def test_permission_consumes_once_even_when_checked_twice(client):
    token = _verification_token(client, "login")
    request = Request(RequestFactory().post("/anything", HTTP_X_CAP_TOKEN=token))
    permission = cap_permission(site="login")()
    assert permission.has_permission(request, None) is True
    assert permission.has_permission(request, None) is True  # cached on the request
    site_config, store = _login_store()
    assert not validate_token(site_config, token, scope="login", token_store=store)


def test_permission_for_an_unknown_site_is_a_configuration_error():
    request = Request(RequestFactory().post("/anything", HTTP_X_CAP_TOKEN="x"))
    with pytest.raises(ImproperlyConfigured, match="not configured"):
        cap_permission(site="missing")().has_permission(request, None)


def test_permission_subclass_is_configurable():
    class Strict(IsCapVerified):
        site = "login"
        header = "X-Other-Token"
        field = ""

    # The header is not the configured one and the body lookup is off, so no token is found.
    request = Request(RequestFactory().post("/anything", HTTP_X_CAP_TOKEN="x"))
    with pytest.raises(CaptchaRequired):
        Strict().has_permission(request, None)


# --------------------------------------------------------------------------- CapTokenField


def test_serializer_accepts_cap_token_key_once(client):
    token = _verification_token(client, "login")
    body = {"cap_token": token, "note": "hi"}
    assert _post_json(client, "/drf/signup", body).json() == {"ok": True}
    replay = _post_json(client, "/drf/signup", body)
    assert replay.status_code == 400
    assert replay.json() == {"cap_token": [VERIFY_MESSAGE]}


def test_serializer_falls_back_to_the_widget_key(client):
    token = _verification_token(client, "login")
    response = _post_json(client, "/drf/signup", {"cap-token": token, "note": "hi"})
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_serializer_rejects_invalid_token_with_the_message(client):
    response = _post_json(client, "/drf/signup", {"cap_token": "garbage", "note": "hi"})
    assert response.status_code == 400
    assert response.json() == {"cap_token": [VERIFY_MESSAGE]}


def test_serializer_missing_and_blank_do_not_consume(client):
    token = _verification_token(client, "login")
    missing = _post_json(client, "/drf/signup", {"note": "hi"})
    assert missing.json() == {"cap_token": ["This field is required."]}
    blank = _post_json(client, "/drf/signup", {"cap_token": "", "note": "hi"})
    assert blank.status_code == 400
    assert blank.json() == {"cap_token": ["This field may not be blank."]}
    # Neither attempt used the token.
    assert _post_json(client, "/drf/signup", {"cap_token": token, "note": "hi"}).status_code == 200


def test_serializer_field_is_write_only_and_checks_its_site():
    from rest_framework import serializers

    class Form(serializers.Serializer):
        cap_token = CapTokenField(site="login")

    field = Form().fields["cap_token"]
    assert isinstance(field, CapTokenField)
    assert field.write_only is True
    assert field.body_key == "cap-token"
    assert field.error_messages["captcha_required"] == VERIFY_MESSAGE
    assert "max_length" in field.error_messages  # the CharField messages are kept


def test_serializer_direct_use_consumes_once(client):
    token = _verification_token(client, "login")
    from tests.django_project.urls_drf import SignupSerializer

    first = SignupSerializer(data={"cap_token": token, "note": "x"})
    assert first.is_valid(), first.errors
    second = SignupSerializer(data={"cap_token": token, "note": "x"})
    assert not second.is_valid()
    assert second.errors == {"cap_token": [VERIFY_MESSAGE]}


# --------------------------------------------------------------------------- CSRF modes


def test_csrf_exempt_true_allows_post_without_token():
    client = Client(enforce_csrf_checks=True)
    assert client.post(f"{PREFIX}/login/challenge").status_code == 200


def test_csrf_exempt_false_is_enforced_on_drf_endpoints():
    with override_settings(CAPWX=_capwx(CSRF_EXEMPT=False)):
        client = Client(enforce_csrf_checks=True)
        denied = client.post(f"{PREFIX}/login/challenge")
        assert denied.status_code == 403
        assert denied.json() == {"success": False, "error": "csrf_failed"}

        # The DRF urls have no page that sets the cookie, so mint the token the way Django does.
        factory_request = RequestFactory().get("/")
        token = get_token(factory_request)
        client.cookies[settings.CSRF_COOKIE_NAME] = factory_request.META["CSRF_COOKIE"]
        challenge = _challenge(client, "login", HTTP_X_CSRFTOKEN=token)
        response = _post_json(
            client, f"{PREFIX}/login/redeem", body_for(SECRET, challenge), HTTP_X_CSRFTOKEN=token
        )
        assert response.status_code == 200, response.content
