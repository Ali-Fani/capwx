"""Tests for capwx.contrib.django (M10): settings, endpoints, form field, decorator, template tags,
hooks, CSRF modes, siteverify, and the capwx_check command.

Runs under pytest-django with tests/django_project/settings.py (locmem cache, no database).
The widget is replaced by tests/_solver.py, which solves challenges in-process.
"""

from __future__ import annotations

import copy
import json
from io import StringIO

import pytest
from _solver import body_for
from django.apps import apps
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.core.management.base import CommandError
from django.template import Context, Template
from django.test import Client, RequestFactory, override_settings

from capwx._crypto import jwt_verify
from capwx.contrib.django import conf
from capwx.contrib.django.views import redeem_view
from capwx.protocols import hashwx
from capwx.tokens import validate_token
from tests.django_project import hooks
from tests.django_project.forms import LoginForm

BASE = copy.deepcopy(settings.CAPWX)
SECRET = BASE["SECRET"]
LOGIN_SITE_SECRET = BASE["SITES"]["login"]["SITE_SECRET"]
MAX_BODY = 64 * 1024


def _capwx(sites: dict | None = None, **changes) -> dict:
    """Base CAPWX settings with top-level changes, and per-site changes merged into SITES."""
    cfg = copy.deepcopy(BASE)
    for name, change in (sites or {}).items():
        cfg["SITES"].setdefault(name, {}).update(change)
    cfg.update(changes)
    return cfg


def _post_json(client: Client, url: str, body: object, **extra: str):
    return client.post(url, data=json.dumps(body), content_type="application/json", **extra)


def _challenge(client: Client, site: str = "login", **extra: str) -> dict:
    response = client.post(f"/cap/{site}/challenge", **extra)
    assert response.status_code == 200, response.content
    return response.json()


def _verification_token(client: Client, site: str = "login", **extra: str) -> str:
    challenge = _challenge(client, site, **extra)
    response = _post_json(client, f"/cap/{site}/redeem", body_for(SECRET, challenge), **extra)
    assert response.status_code == 200, response.content
    return response.json()["token"]


# --------------------------------------------------------------------------- settings


def test_apps_ready_registers_the_capwx_app():
    assert apps.get_app_config("capwx").name == "capwx.contrib.django"


def test_missing_secret_is_improperly_configured():
    cfg = copy.deepcopy(BASE)
    del cfg["SECRET"]
    with override_settings(CAPWX=cfg), pytest.raises(ImproperlyConfigured, match="SECRET"):
        conf.get_conf()


def test_short_secret_is_improperly_configured():
    with (
        override_settings(CAPWX=_capwx(SECRET="x" * 15)),
        pytest.raises(ImproperlyConfigured, match="at least 16 bytes"),
    ):
        conf.get_conf()


def test_unknown_global_key_is_rejected():
    with (
        override_settings(CAPWX=_capwx(BOGUS=1)),
        pytest.raises(ImproperlyConfigured, match="BOGUS"),
    ):
        conf.get_conf()


def test_unknown_site_key_is_rejected():
    with (
        override_settings(CAPWX=_capwx(sites={"login": {"NOPE": 1}})),
        pytest.raises(ImproperlyConfigured, match="NOPE"),
    ):
        conf.get_conf()


def test_secret_is_global_only():
    with (
        override_settings(CAPWX=_capwx(sites={"login": {"SECRET": "y" * 32}})),
        pytest.raises(ImproperlyConfigured, match="global only"),
    ):
        conf.get_conf()


def test_site_overrides_map_to_config_fields():
    with override_settings(
        CAPWX=_capwx(
            sites={
                "login": {
                    "HASHWX_DIFFICULTY": 5000,
                    "INSTRUMENTATION": {
                        "BLOCK_AUTOMATED_BROWSERS": True,
                        "OBFUSCATION_LEVEL": 2,
                        "ALLOW_CSP_EVAL_BLOCKED": True,
                    },
                }
            }
        )
    ):
        login = conf.get_site("login")
        assert login is not None
        assert login.config.hashwx_difficulty == 5000
        assert login.config.instrumentation.block_automated_browsers is True
        assert login.config.instrumentation.obfuscation_level == 2
        assert login.config.instrumentation.allow_csp_eval_blocked is True
        assert login.config.secret == SECRET
        assert conf.get_site("default") is not None  # always present
        assert conf.get_site("nope") is None


def test_default_site_exists_when_not_listed():
    cfg = _capwx()
    del cfg["SITES"]["default"]
    with override_settings(CAPWX=cfg):
        assert conf.get_site("default") is not None


# --------------------------------------------------------------------------- challenge endpoint


def test_challenge_is_format_two_with_expected_protocols(client):
    response = client.post("/cap/login/challenge")
    assert response.status_code == 200
    assert "no-store" in response["Cache-Control"]
    data = response.json()
    assert data["format"] == 2
    assert [c["protocol"] for c in data["challenges"]] == ["hashwx"] * 4 + ["instrumentation"]
    assert jwt_verify(data["token"], SECRET)["sk"] == "login"
    assert data["expires"] > 0

    signup = client.post("/cap/signup/challenge").json()
    assert {c["protocol"] for c in signup["challenges"]} == {"sha256-pow"}


def test_hashwx_difficulty_split_across_challenges(client):
    data = _challenge(client, "login")
    d_values = {c["payload"]["d"] for c in data["challenges"] if c["protocol"] == "hashwx"}
    assert d_values == {250}  # HASHWX_DIFFICULTY 1000 over 4 challenges


def test_full_flow_without_instrumentation_redeems_once(client):
    with override_settings(CAPWX=_capwx(sites={"login": {"INSTRUMENTATION": {"ENABLED": False}}})):
        challenge = _challenge(client, "login")
        assert [c["protocol"] for c in challenge["challenges"]] == ["hashwx"] * 4
        response = _post_json(client, "/cap/login/redeem", body_for(SECRET, challenge))
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert set(data) == {"success", "token", "expires"}

        site = conf.get_site("login")
        store = conf.get_conf().store
        assert validate_token(site.config, data["token"], scope="login", token_store=store)
        assert not validate_token(site.config, data["token"], scope="login", token_store=store)


def test_full_flow_with_instrumentation_enabled(client):
    challenge = _challenge(client, "login")
    response = _post_json(client, "/cap/login/redeem", body_for(SECRET, challenge))
    assert response.status_code == 200, response.content
    assert response.json()["success"] is True


def test_replay_of_same_redeem_body_is_already_redeemed(client):
    challenge = _challenge(client, "login")
    body = body_for(SECRET, challenge)
    first = _post_json(client, "/cap/login/redeem", body)
    assert first.status_code == 200
    second = _post_json(client, "/cap/login/redeem", body)
    assert second.status_code == 403
    assert second.json() == {"success": False, "error": "already_redeemed"}


def test_redeem_with_token_for_another_site_is_scope_mismatch(client):
    challenge = _challenge(client, "signup")
    response = _post_json(client, "/cap/login/redeem", body_for(SECRET, challenge))
    assert response.status_code == 403
    assert response.json() == {"success": False, "error": "scope_mismatch"}


def test_wrong_solution_is_invalid_solution_400(client):
    challenge = _challenge(client, "signup")
    body = {"token": challenge["token"], "solutions": [{"nonce": "x"}] * 50}
    response = _post_json(client, "/cap/signup/redeem", body)
    assert response.status_code == 400
    assert response.json() == {"success": False, "error": "invalid_solution"}


def test_wrong_number_of_solutions_is_invalid_solutions(client):
    challenge = _challenge(client, "signup")
    response = _post_json(
        client, "/cap/signup/redeem", {"token": challenge["token"], "solutions": []}
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_solutions"


# --------------------------------------------------------------------------- site, method, size


@pytest.mark.parametrize("path", ["challenge", "redeem", "siteverify"])
def test_unknown_site_is_404(client, path):
    response = client.post(f"/cap/nope/{path}", data="{}", content_type="application/json")
    assert response.status_code == 404
    assert response.json() == {"error": "Invalid site key"}


@pytest.mark.parametrize("path", ["challenge", "redeem", "siteverify"])
def test_get_is_405_json(client, path):
    response = client.get(f"/cap/login/{path}")
    assert response.status_code == 405
    assert response["Allow"] == "POST"
    assert response.json() == {"error": "method_not_allowed"}


def test_oversized_body_is_413_by_content_length(client):
    response = client.post(
        "/cap/login/redeem", data=b"x" * (MAX_BODY + 1), content_type="application/json"
    )
    assert response.status_code == 413
    assert response.json() == {"success": False, "error": "body_too_large"}


def test_oversized_body_is_413_when_header_is_missing():
    request = RequestFactory().post(
        "/cap/login/redeem",
        data=b"{" + b" " * MAX_BODY + b"}",
        content_type="application/json",
    )
    del request.META["CONTENT_LENGTH"]
    response = redeem_view(request, "login")
    assert response.status_code == 413


def test_malformed_json_is_400_invalid_body(client):
    for raw in (b"{not json", b"\xff\xfe", b"[1, 2]", b""):
        response = client.post("/cap/login/redeem", data=raw, content_type="application/json")
        assert response.status_code == 400, raw
        assert response.json() == {"success": False, "error": "invalid_body"}


# --------------------------------------------------------------------------- siteverify


def test_siteverify_success_failure_and_single_use(client):
    token = _verification_token(client, "login")
    url = "/cap/login/siteverify"

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
    response = _post_json(client, "/cap/strict/siteverify", {"secret": "x", "response": "y"})
    assert response.status_code == 404
    assert response.json()["error"] == "siteverify_not_configured"


# --------------------------------------------------------------------------- form field and decorator


def test_capfield_accepts_a_fresh_token_once(client):
    token = _verification_token(client, "login")
    form = LoginForm(data={"username": "ana", "cap-token": token})
    assert form.is_valid(), form.errors

    replay = LoginForm(data={"username": "ana", "cap-token": token})
    assert not replay.is_valid()
    assert replay.errors["captcha"] == ["Please complete the verification."]


@pytest.mark.parametrize("data", [{"username": "a", "cap-token": "garbage"}, {"username": "a"}])
def test_capfield_rejects_invalid_or_missing_token(data):
    form = LoginForm(data=data)
    assert not form.is_valid()
    assert form.errors["captcha"] == ["Please complete the verification."]


def test_capwidget_renders_cap_token_input_and_endpoint():
    html = LoginForm().as_p()
    assert 'name="cap-token"' in html
    assert 'data-cap-api-endpoint="/cap/login/"' in html


def test_form_view_end_to_end(client):
    token = _verification_token(client, "login")
    response = client.post("/form/", {"username": "ana", "cap-token": token})
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_require_cap_accepts_header_once_and_rejects_replay(client):
    token = _verification_token(client, "login")
    url = "/api/protected/"
    assert client.post(url, HTTP_X_CAP_TOKEN=token).status_code == 200
    replay = client.post(url, HTTP_X_CAP_TOKEN=token)
    assert replay.status_code == 403
    assert replay.json() == {"error": "captcha_required"}


def test_require_cap_reads_json_field_and_rejects_missing(client):
    url = "/api/protected/"
    missing = client.post(url)
    assert missing.status_code == 403
    assert missing.json() == {"error": "captcha_required"}

    token = _verification_token(client, "login")
    ok = _post_json(client, url, {"cap-token": token})
    assert ok.status_code == 200


def test_require_cap_reads_form_field(client):
    token = _verification_token(client, "login")
    assert client.post("/api/protected/", {"cap-token": token}).status_code == 200


# --------------------------------------------------------------------------- CSRF modes


def test_csrf_exempt_true_allows_post_without_token():
    client = Client(enforce_csrf_checks=True)
    assert client.post("/cap/login/challenge").status_code == 200


def test_csrf_exempt_false_enforces_csrf_on_every_endpoint():
    with override_settings(CAPWX=_capwx(CSRF_EXEMPT=False)):
        client = Client(enforce_csrf_checks=True)
        denied = client.post("/cap/login/challenge")
        assert denied.status_code == 403
        assert denied.json() == {"success": False, "error": "csrf_failed"}

        client.get("/page/")  # the page sets the csrftoken cookie
        token = client.cookies["csrftoken"].value
        challenge = _challenge(client, "login", HTTP_X_CSRFTOKEN=token)
        response = _post_json(
            client, "/cap/login/redeem", body_for(SECRET, challenge), HTTP_X_CSRFTOKEN=token
        )
        assert response.status_code == 200, response.content
        assert _post_json(client, "/cap/login/siteverify", {}).status_code == 403  # CSRF first


# --------------------------------------------------------------------------- template tags


def test_page_renders_static_urls_endpoint_and_no_nonce(client):
    html = client.get("/page/").content.decode()
    for asset in ("hashwx.wasm", "cap_wasm_bg.wasm", "pako_inflate.min.js", "cap.min.js"):
        assert f"/static/capwx/{asset}" in html
    assert 'data-cap-api-endpoint="/cap/login/"' in html
    assert "CAP_CUSTOM_HASHWX_URL" in html
    assert "nonce=" not in html
    assert "CAP_CUSTOM_FETCH" not in html  # CSRF_EXEMPT is True


def test_scripts_tag_uses_request_csp_nonce():
    request = RequestFactory().get("/")
    request.csp_nonce = "n0nceABC123"
    html = Template("{% load capwx %}{% capwx_scripts %}").render(Context({"request": request}))
    assert html.count('nonce="n0nceABC123"') == 2  # inline block and the widget script tag
    assert 'window.CAP_SCRIPT_NONCE = "n0nceABC123"' in html


def test_scripts_tag_uses_django_native_csp_nonce():
    request = RequestFactory().get("/")
    request._csp_nonce = "native-nonce"
    html = Template("{% load capwx %}{% capwx_scripts %}").render(Context({"request": request}))
    assert 'nonce="native-nonce"' in html


def test_scripts_tag_installs_csrf_fetch_when_not_exempt():
    request = RequestFactory().get("/")
    with override_settings(CAPWX=_capwx(CSRF_EXEMPT=False)):
        html = Template("{% load capwx %}{% capwx_scripts %}").render(Context({"request": request}))
    assert "window.CAP_CUSTOM_FETCH" in html
    assert "X-CSRFToken" in html
    assert 'credentials: "same-origin"' in html


def test_widget_tag_for_unknown_site_is_an_error():
    with pytest.raises(ImproperlyConfigured, match="not configured"):
        Template("{% load capwx %}{% capwx_widget site='missing' %}").render(Context({}))


def test_widget_tag_renders_hidden_input():
    html = Template("{% load capwx %}{% capwx_widget site='login' %}").render(Context({}))
    assert "<cap-widget" in html
    assert 'name="cap-token"' in html
    assert 'data-cap-api-endpoint="/cap/login/"' in html


# --------------------------------------------------------------------------- hooks


def test_difficulty_hook_overrides_per_request(client):
    hooks.CALLS.clear()
    plain = _challenge(client, "login")
    hard = _challenge(client, "login", HTTP_X_HARD="1")
    plain_d = {c["payload"]["d"] for c in plain["challenges"] if c["protocol"] == "hashwx"}
    hard_d = {c["payload"]["d"] for c in hard["challenges"] if c["protocol"] == "hashwx"}
    assert plain_d == {250}
    assert hard_d == {1000}  # hashwx_difficulty 4000 over 4 challenges
    assert ("difficulty", "login") in hooks.CALLS


def test_before_challenge_hook_blocks_with_403(client):
    hooks.CALLS.clear()
    response = client.post("/cap/login/challenge", REMOTE_ADDR=hooks.BLOCKED_IP)
    assert response.status_code == 403
    assert response.json() == {"success": False, "error": "blocked"}
    assert ("before", "login") in hooks.CALLS


def test_difficulty_hook_must_return_a_mapping_or_none(client):
    cfg = _capwx(DIFFICULTY_HOOK="tests.django_project.hooks.bad_difficulty")
    with override_settings(CAPWX=cfg), pytest.raises(ImproperlyConfigured, match="DIFFICULTY_HOOK"):
        client.post("/cap/login/challenge")


# --------------------------------------------------------------------------- capwx_check


def test_capwx_check_passes():
    out, err = StringIO(), StringIO()
    call_command("capwx_check", stdout=out, stderr=err)
    text = out.getvalue()
    assert "capwx_check: OK" in text
    for name in ("default", "login", "signup", "strict"):
        assert f"site '{name}'" in text
    assert "[FAIL]" not in text


def test_capwx_check_fails_when_wasm_hash_does_not_match(monkeypatch):
    monkeypatch.setattr(hashwx, "_vendored_sha256", lambda: "00" * 32)
    err = StringIO()
    with pytest.raises(CommandError, match="capwx_check failed"):
        call_command("capwx_check", stdout=StringIO(), stderr=err)
    assert "vendored hashwx.wasm sha256 mismatch" in err.getvalue()
