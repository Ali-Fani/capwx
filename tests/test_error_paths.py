"""Error paths and edge cases that the feature tests do not reach (M13 coverage pass).

Each test pins a promise the code already makes in its docstring: client input never raises,
store outages become reasons instead of crashes, and programmer errors raise ``CapwxError``.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from _solver import FORMAT_INFO, body_for
from django.test import Client, RequestFactory
from wasmtime import Func

from capwx import challenge, tokens
from capwx._crypto import encrypt_gcm, jwt_sign, random_hex
from capwx._jsint import is_js_number
from capwx.challenge import RedeemResult, aredeem, create_challenge, redeem
from capwx.config import CapConfig
from capwx.contrib.django import views
from capwx.contrib.django.decorators import require_cap
from capwx.contrib.django.forms import CapWidget
from capwx.errors import CapwxError, Reason
from capwx.protocols import hashwx
from capwx.stores.django_cache import _parse_int
from capwx.stores.memory import MemoryStore
from capwx.tokens import aissue_token, avalidate_token, issue_token, validate_token

SECRET = "test-secret-0123456789abcdef"
NOW = 1_700_000_000_000  # ms
TTL_MS = 60_000
MAX_BODY = 64 * 1024


def _cfg(**overrides: Any) -> CapConfig:
    base: dict[str, Any] = {"secret": SECRET, "protocols": ("sha256-pow",), "sha256_difficulty": 1}
    base.update(overrides)
    return CapConfig(**base)


def _forge(ev_plain: object) -> str:
    """A token signed with the real secret whose encrypted claim is ``ev_plain``."""
    payload: dict[str, Any] = {
        "f": 2,
        "n": random_hex(16),
        "exp": NOW + TTL_MS,
        "iat": NOW,
        "ev": encrypt_gcm(ev_plain, SECRET, FORMAT_INFO),
    }
    return jwt_sign(payload, SECRET)


# --------------------------------------------------------------------------- challenge


def test_result_without_a_reason_reports_unknown() -> None:
    assert RedeemResult(success=False).to_widget_json() == {"success": False, "error": "unknown"}


@pytest.mark.parametrize("now_ms", [True, 1.5, "123"])
def test_now_ms_must_be_an_int_or_none(now_ms: Any) -> None:
    with pytest.raises(CapwxError, match="now_ms"):
        create_challenge(_cfg(), now_ms=now_ms)


def test_unknown_protocol_name_is_a_programmer_error() -> None:
    with pytest.raises(CapwxError, match="unknown protocol"):
        challenge._load("no-such-protocol")


def test_unknown_protocol_in_the_encrypted_claims_is_an_invalid_solution() -> None:
    token = _forge({"expected": [{"protocol": "no-such-protocol"}]})
    result = redeem(_cfg(), {"token": token, "solutions": [{"nonce": 0}]}, now_ms=NOW)
    assert result.success is False
    assert result.reason == Reason.INVALID_SOLUTION


@pytest.mark.parametrize("ev_plain", [{"expected": "not-a-list"}, [1, 2]])
def test_malformed_encrypted_claims_are_an_invalid_token(ev_plain: object) -> None:
    result = redeem(_cfg(), {"token": _forge(ev_plain), "solutions": []}, now_ms=NOW)
    assert result.reason == Reason.INVALID_TOKEN


def test_aredeem_rejects_a_bad_body_before_touching_the_stores() -> None:
    store = MemoryStore()
    result = asyncio.run(aredeem(_cfg(), None, nonce_store=store, token_store=store, now_ms=NOW))
    assert result.success is False
    assert result.reason == Reason.INVALID_BODY


def test_aredeem_without_a_nonce_store_still_issues_a_token() -> None:
    cfg = _cfg()
    resp = create_challenge(cfg, now_ms=NOW)
    result = asyncio.run(aredeem(cfg, body_for(SECRET, resp), now_ms=NOW + 1))
    assert result.success is True
    assert result.token is not None


class _OutageNonceStore:
    """An async nonce store whose backend is down."""

    async def claim(self, key: str, ttl_seconds: int) -> bool:
        raise OSError("backend unreachable")


def test_aredeem_store_outage_is_a_reason_and_issues_no_token() -> None:
    cfg = _cfg()
    body = body_for(SECRET, create_challenge(cfg, now_ms=NOW))
    result = asyncio.run(aredeem(cfg, body, nonce_store=_OutageNonceStore(), now_ms=NOW + 1))
    assert result.reason == Reason.NONCE_STORE_ERROR
    assert result.token is None


# --------------------------------------------------------------------------- tokens


class _SyncNoPeekStore:
    """A sync token store without ``peek``: non-consuming checks must take and put back."""

    def __init__(self) -> None:
        self.data: dict[str, int] = {}
        self.puts: list[str] = []

    def put(self, key: str, expires_ms: int, ttl_seconds: int) -> None:
        self.data[key] = expires_ms
        self.puts.append(key)

    def take(self, key: str) -> int | None:
        return self.data.pop(key, None)


class _AsyncNoPeekStore:
    def __init__(self) -> None:
        self.data: dict[str, int] = {}

    async def put(self, key: str, expires_ms: int, ttl_seconds: int) -> None:
        self.data[key] = expires_ms

    async def take(self, key: str) -> int | None:
        return self.data.pop(key, None)


class _AsyncPeekStore(_AsyncNoPeekStore):
    async def peek(self, key: str) -> int | None:
        return self.data.get(key)


def test_parse_stored_rejects_non_strings() -> None:
    assert tokens._parse_stored(12345) is None


def test_non_consuming_check_without_peek_puts_the_token_back() -> None:
    cfg = _cfg(token_ttl_ms=TTL_MS)
    store = _SyncNoPeekStore()
    token, _ = issue_token(cfg, scope="login", token_store=store)
    assert validate_token(cfg, token, scope="login", token_store=store, consume=False) is True
    assert validate_token(cfg, token, scope="login", token_store=store) is True
    assert validate_token(cfg, token, scope="login", token_store=store) is False


def test_non_consuming_check_without_peek_does_not_reinsert_a_missing_token() -> None:
    cfg = _cfg(token_ttl_ms=TTL_MS)
    store = _SyncNoPeekStore()
    token, _ = issue_token(cfg, scope="login", token_store=store)
    store.data.clear()
    store.puts.clear()
    assert validate_token(cfg, token, scope="login", token_store=store, consume=False) is False
    assert store.puts == []


def test_async_validate_rejects_a_scope_containing_a_colon() -> None:
    cfg = _cfg(token_ttl_ms=TTL_MS)
    store = _AsyncNoPeekStore()
    token, _ = asyncio.run(aissue_token(cfg, scope="login", token_store=store))
    assert asyncio.run(avalidate_token(cfg, token, scope="a:b", token_store=store)) is False


def test_async_validate_rejects_a_stateless_token_when_a_store_is_given() -> None:
    cfg = _cfg(token_ttl_ms=TTL_MS)
    token, _ = asyncio.run(aissue_token(cfg, scope="login"))  # no store: stateless
    assert (
        asyncio.run(avalidate_token(cfg, token, scope="login", token_store=_AsyncNoPeekStore()))
        is False
    )


def test_async_validate_without_a_store_rejects_a_stored_token() -> None:
    cfg = _cfg(token_ttl_ms=TTL_MS)
    store = _AsyncNoPeekStore()
    token, _ = asyncio.run(aissue_token(cfg, scope="login", token_store=store))
    assert asyncio.run(avalidate_token(cfg, token, scope="login")) is False


def test_async_validate_rejects_a_malformed_stored_token() -> None:
    cfg = _cfg(token_ttl_ms=TTL_MS)
    result = asyncio.run(
        avalidate_token(cfg, "not-a-token", scope="login", token_store=_AsyncNoPeekStore())
    )
    assert result is False


def test_async_non_consuming_check_uses_peek_when_present() -> None:
    cfg = _cfg(token_ttl_ms=TTL_MS)
    store = _AsyncPeekStore()

    async def scenario() -> list[bool]:
        token, _ = await aissue_token(cfg, scope="login", token_store=store)
        seen = [await avalidate_token(cfg, token, scope="login", token_store=store, consume=False)]
        seen.append(await avalidate_token(cfg, token, scope="login", token_store=store))
        seen.append(await avalidate_token(cfg, token, scope="login", token_store=store))
        return seen

    assert asyncio.run(scenario()) == [True, True, False]


def test_async_non_consuming_check_without_peek_puts_the_token_back() -> None:
    cfg = _cfg(token_ttl_ms=TTL_MS)
    store = _AsyncNoPeekStore()

    async def scenario() -> list[bool]:
        token, _ = await aissue_token(cfg, scope="login", token_store=store)
        seen = [await avalidate_token(cfg, token, scope="login", token_store=store, consume=False)]
        seen.append(await avalidate_token(cfg, token, scope="login", token_store=store))
        return seen

    assert asyncio.run(scenario()) == [True, True]


def test_async_non_consuming_check_of_a_missing_token_is_false() -> None:
    cfg = _cfg(token_ttl_ms=TTL_MS)
    store = _AsyncNoPeekStore()
    token = "login:0123456789abcdef:" + "a" * 30
    assert (
        asyncio.run(avalidate_token(cfg, token, scope="login", token_store=store, consume=False))
        is False
    )
    assert store.data == {}


# --------------------------------------------------------------------------- protocols and stores


def test_is_js_number_treats_a_double_overflow_as_not_finite() -> None:
    assert is_js_number(10**400) is False
    assert is_js_number(float("nan")) is False
    assert is_js_number(1.5) is True


def test_hash_rejects_a_seed_that_is_not_32_bytes() -> None:
    with pytest.raises(CapwxError, match="32 bytes"):
        hashwx.get_engine().hash(b"short", 0)


def test_wasm_export_lookup_rejects_missing_and_wrongly_typed_exports() -> None:
    with pytest.raises(CapwxError, match="hashwx_exec"):
        hashwx._export({}, "hashwx_exec", Func)
    with pytest.raises(CapwxError, match="hashwx_exec"):
        hashwx._export({"hashwx_exec": 1}, "hashwx_exec", Func)


def test_django_cache_parse_int_ignores_non_numeric_values() -> None:
    assert _parse_int("42") == 42
    assert _parse_int("not-a-number") is None
    assert _parse_int(True) is None


# --------------------------------------------------------------------------- django


class _UnreadableBody:
    """A request whose body cannot be read (for example a client that disconnects)."""

    def __init__(self) -> None:
        self.META: dict[str, str] = {}

    def read(self, size: int) -> bytes:
        raise OSError("connection reset")


class _OversizedBody(_UnreadableBody):
    def read(self, size: int) -> bytes:
        return b"x" * size


def test_redeem_status_maps_store_outages_to_500() -> None:
    assert views.redeem_status(Reason.NONCE_STORE_ERROR) == 500
    assert views.redeem_status("missing_meta") == 403
    assert views.redeem_status(Reason.INVALID_BODY) == 400


def test_read_body_rejects_a_cached_body_over_the_limit() -> None:
    request = RequestFactory().post("/cap/login/redeem")
    request._body = b"x" * (MAX_BODY + 1)  # type: ignore[attr-defined]
    assert views._read_body(request) is None


def test_read_body_treats_an_unreadable_body_as_empty() -> None:
    assert views._read_body(_UnreadableBody()) == b""


def test_read_body_rejects_a_body_over_the_limit_read_from_the_stream() -> None:
    assert views._read_body(_OversizedBody()) is None


def test_require_cap_refuses_a_json_body_that_does_not_parse() -> None:
    @require_cap(site="login")
    def view(request: Any) -> Any:  # pragma: no cover - never reached
        raise AssertionError("the view must not run without a token")

    request = RequestFactory().post("/some/page", data="{not json", content_type="application/json")
    response = view(request)
    assert response.status_code == 403
    assert json.loads(response.content) == {"error": "captcha_required"}


def test_require_cap_refuses_a_json_array_body() -> None:
    @require_cap(site="login")
    def view(request: Any) -> Any:  # pragma: no cover - never reached
        raise AssertionError("the view must not run without a token")

    request = RequestFactory().post("/some/page", data="[1, 2]", content_type="application/json")
    assert view(request).status_code == 403


def test_cap_widget_reports_an_omitted_token_field() -> None:
    widget = CapWidget()
    assert widget.value_omitted_from_data({}, None, "anything") is True
    assert widget.value_omitted_from_data({"cap-token": "x"}, None, "anything") is False


def test_siteverify_rejects_a_json_body_that_is_not_an_object(client: Client) -> None:
    response = client.post(
        "/cap/login/siteverify", data=json.dumps([1, 2]), content_type="application/json"
    )
    assert response.status_code == 400
    assert response.json() == {"success": False, "error": "invalid_body"}
