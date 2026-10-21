"""Tests for capwx.tokens (M9): issue/validate (stored and stateless), siteverify and async twins."""

from __future__ import annotations

import asyncio

import pytest

from capwx import tokens
from capwx._crypto import jwt_sign
from capwx.config import CapConfig
from capwx.errors import CapwxError
from capwx.stores.memory import MemoryStore
from capwx.tokens import (
    aissue_token,
    asiteverify,
    avalidate_token,
    issue_token,
    siteverify,
    validate_token,
)

SECRET = "s" * 32
SITE_SECRET = "site-secret-0123456789"
NOW = 1_700_000_000_000  # ms


@pytest.fixture
def cfg() -> CapConfig:
    return CapConfig(secret=SECRET, token_ttl_ms=60_000)


@pytest.fixture
def clock(monkeypatch):
    state = {"ms": NOW}
    monkeypatch.setattr(tokens, "_now_ms", lambda: state["ms"])

    class Clock:
        def set(self, ms: int) -> None:
            state["ms"] = ms

        def advance(self, ms: int) -> None:
            state["ms"] += ms

        @property
        def now(self) -> int:
            return state["ms"]

    return Clock()


@pytest.fixture
def store() -> MemoryStore:
    # Store's own clock is real time; tests control token expiry through the tokens clock.
    return MemoryStore()


class AsyncDictStore:
    """Async TokenStore + NonceStore fake."""

    def __init__(self) -> None:
        self.data: dict[str, int] = {}
        self.calls: list[str] = []

    async def claim(self, key: str, ttl_seconds: int) -> bool:
        self.calls.append("claim")
        if key in self.data:
            return False
        self.data[key] = 1
        return True

    async def put(self, key: str, expires_ms: int, ttl_seconds: int) -> None:
        self.calls.append("put")
        self.data[key] = expires_ms

    async def take(self, key: str) -> int | None:
        self.calls.append("take")
        return self.data.pop(key, None)


# ---------------------------------------------------------------- issue


def test_issue_stored_returns_expiry_and_format(cfg, clock, store):
    token, expires = issue_token(cfg, "login", store)
    assert expires == NOW + cfg.token_ttl_ms
    parts = token.split(":")
    assert len(parts) == 3
    assert parts[0] == "login"
    assert len(parts[1]) == 16 and len(parts[2]) == 30


def test_issue_stored_only_stores_hash(cfg, clock, store):
    token, _ = issue_token(cfg, "login", store)
    _, _, secret_part = token.split(":")
    assert len(store._data) == 1
    (key,) = store._data
    assert secret_part not in key
    assert key.startswith("capwx:token:login:")


def test_issue_default_site_when_no_scope(cfg, clock, store):
    token, _ = issue_token(cfg, None, store)
    assert token.startswith("default:")


def test_issue_stateless_without_store(cfg, clock):
    token, expires = issue_token(cfg, "login")
    assert token.startswith("v1.")
    assert expires == NOW + cfg.token_ttl_ms


def test_issue_rejects_scope_with_colon(cfg, clock, store):
    with pytest.raises(CapwxError):
        issue_token(cfg, "a:b", store)


def test_issue_rejects_non_string_scope(cfg, clock):
    with pytest.raises(CapwxError):
        issue_token(cfg, 123)  # type: ignore[arg-type]


def test_issue_stored_with_async_store_raises(cfg, clock):
    with pytest.raises(CapwxError):
        issue_token(cfg, "x", AsyncDictStore())


def test_issued_tokens_are_unique(cfg, clock, store):
    tokens_seen = {issue_token(cfg, "s", store)[0] for _ in range(50)}
    assert len(tokens_seen) == 50


# ---------------------------------------------------------------- validate (stored)


def test_stored_validates_once_then_rejects(cfg, clock, store):
    token, _ = issue_token(cfg, "login", store)
    assert validate_token(cfg, token, scope="login", token_store=store) is True
    assert validate_token(cfg, token, scope="login", token_store=store) is False


def test_consume_false_keeps_token(cfg, clock, store):
    token, _ = issue_token(cfg, "login", store)
    assert validate_token(cfg, token, scope="login", token_store=store, consume=False) is True
    assert validate_token(cfg, token, scope="login", token_store=store, consume=False) is True
    assert validate_token(cfg, token, scope="login", token_store=store) is True
    assert validate_token(cfg, token, scope="login", token_store=store) is False


def test_scope_mismatch_rejects_and_does_not_consume(cfg, clock, store):
    token, _ = issue_token(cfg, "login", store)
    assert validate_token(cfg, token, scope="signup", token_store=store) is False
    assert validate_token(cfg, token, scope=None, token_store=store) is False
    assert validate_token(cfg, token, scope="login", token_store=store) is True


def test_default_scope_token_needs_no_scope(cfg, clock, store):
    token, _ = issue_token(cfg, None, store)
    assert validate_token(cfg, token, token_store=store) is True
    assert validate_token(cfg, token, scope="login", token_store=store) is False


def test_expired_stored_token_rejected(cfg, clock, store):
    token, _ = issue_token(cfg, "login", store)
    clock.advance(cfg.token_ttl_ms)  # now == expires: not strictly greater, so expired
    assert validate_token(cfg, token, scope="login", token_store=store) is False


def test_expired_token_is_still_just_false_with_consume_false(cfg, clock, store):
    token, _ = issue_token(cfg, "login", store)
    clock.advance(cfg.token_ttl_ms + 1)
    assert validate_token(cfg, token, scope="login", token_store=store, consume=False) is False


def test_stored_token_without_store_rejected(cfg, clock, store):
    token, _ = issue_token(cfg, "login", store)
    assert validate_token(cfg, token, scope="login") is False


def test_tampered_stored_token_rejected(cfg, clock, store):
    token, _ = issue_token(cfg, "login", store)
    site, token_id, secret_part = token.split(":")
    flipped = ("0" if secret_part[0] != "0" else "1") + secret_part[1:]
    assert (
        validate_token(cfg, f"{site}:{token_id}:{flipped}", scope="login", token_store=store)
        is False
    )
    other_id = ("0" if token_id[0] != "0" else "1") + token_id[1:]
    assert (
        validate_token(cfg, f"{site}:{other_id}:{secret_part}", scope="login", token_store=store)
        is False
    )
    # Tampering did not consume the real token.
    assert validate_token(cfg, token, scope="login", token_store=store) is True


@pytest.mark.parametrize(
    "bad",
    [
        None,
        123,
        b"login:0123456789abcdef:" + b"0" * 30,
        "",
        "login",
        "login:abc",
        "a:b:c:d",
        ":::",
        "login::",
        "login:0123456789abcdef:short",
        "login:XYZ:" + "a" * 30,
        "login:" + "g" * 16 + ":" + "0" * 30,
        "login:0123456789ABCDEF:" + "0" * 30,
        "login:0123456789abcdef:" + "0" * 30 + ":extra",
        "v1.",
        "v1.a.b",
        "v1.!!!",
        "\x00\x01",
        "login:0123456789abcdef:0000\n0000",
        pytest.param("x" * 100_000, id="very-long"),
        "é:é:é",
    ],
)
def test_garbage_input_never_raises(cfg, clock, store, bad):
    assert validate_token(cfg, bad, scope="login", token_store=store) is False
    assert validate_token(cfg, bad, scope="login", token_store=store, consume=False) is False
    assert validate_token(cfg, bad, scope="login") is False
    assert validate_token(cfg, bad) is False


@pytest.mark.parametrize("bad_scope", [123, "a:b", ["x"]])
def test_invalid_scope_argument_returns_false(cfg, clock, store, bad_scope):
    token, _ = issue_token(cfg, "login", store)
    assert validate_token(cfg, token, scope=bad_scope, token_store=store) is False


def test_validate_with_async_store_raises(cfg, clock):
    with pytest.raises(CapwxError):
        validate_token(cfg, "default:0123456789abcdef:" + "0" * 30, token_store=AsyncDictStore())


def test_consume_false_fallback_for_store_without_peek(cfg, clock):
    """A store with only put/take still supports consume=False (take + put back)."""

    class TakeOnly:
        def __init__(self) -> None:
            self.inner = MemoryStore()

        def put(self, key, expires_ms, ttl_seconds):
            self.inner.put(key, expires_ms, ttl_seconds)

        def take(self, key):
            return self.inner.take(key)

    s = TakeOnly()
    token, _ = issue_token(cfg, "login", s)
    assert validate_token(cfg, token, scope="login", token_store=s, consume=False) is True
    assert validate_token(cfg, token, scope="login", token_store=s, consume=False) is True
    assert validate_token(cfg, token, scope="login", token_store=s) is True
    assert validate_token(cfg, token, scope="login", token_store=s) is False


# ---------------------------------------------------------------- validate (stateless)


def test_stateless_token_validates(cfg, clock):
    token, _ = issue_token(cfg, "login")
    assert validate_token(cfg, token, scope="login") is True


def test_stateless_token_is_replayable_until_expiry(cfg, clock):
    """Documented behaviour: stateless tokens are NOT single-use."""
    token, _ = issue_token(cfg, "login")
    assert validate_token(cfg, token, scope="login") is True
    assert validate_token(cfg, token, scope="login") is True  # replay succeeds
    clock.advance(cfg.token_ttl_ms)
    assert validate_token(cfg, token, scope="login") is False


def test_stateless_scope_mismatch(cfg, clock):
    token, _ = issue_token(cfg, "login")
    assert validate_token(cfg, token, scope="signup") is False
    assert validate_token(cfg, token) is False  # issued with a scope, checked without one


def test_stateless_scope_none_round_trip(cfg, clock):
    token, _ = issue_token(cfg)
    assert validate_token(cfg, token) is True
    assert validate_token(cfg, token, scope="login") is False


def test_stateless_expired(cfg, clock):
    token, _ = issue_token(cfg, "login")
    clock.advance(cfg.token_ttl_ms + 1)
    assert validate_token(cfg, token, scope="login") is False


def test_stateless_tampered_rejected(cfg, clock):
    token, _ = issue_token(cfg, "login")
    head, _, sig = token.rpartition(".")
    bad_sig = ("A" if sig[0] != "A" else "B") + sig[1:]
    assert validate_token(cfg, f"{head}.{bad_sig}", scope="login") is False


def test_stateless_wrong_secret_rejected(cfg, clock):
    token, _ = issue_token(cfg, "login")
    other = CapConfig(secret="z" * 32, token_ttl_ms=60_000)
    assert validate_token(other, token, scope="login") is False


def test_stateless_rejected_when_store_given(cfg, clock, store):
    token, _ = issue_token(cfg, "login")
    assert validate_token(cfg, token, scope="login", token_store=store) is False


def test_challenge_style_jwt_is_not_a_verify_token(cfg, clock):
    # A signed JWT with the right secret but no t=verify must not validate.
    payload = {"f": 2, "n": "x", "exp": NOW + 10_000, "sk": "login"}
    token = "v1." + jwt_sign(payload, SECRET)
    assert validate_token(cfg, token, scope="login") is False


def test_stateless_wrong_type_fields_rejected(cfg, clock):
    base = {"t": "verify", "sk": "login", "exp": NOW + 10_000, "n": "x"}
    for field, value in [("exp", "soon"), ("exp", True), ("exp", None), ("sk", "other")]:
        payload = dict(base, **{field: value})
        assert validate_token(cfg, "v1." + jwt_sign(payload, SECRET), scope="login") is False


# ---------------------------------------------------------------- siteverify


def test_siteverify_success_then_token_consumed(cfg, clock, store):
    token, _ = issue_token(cfg, "site1", store)
    assert siteverify(
        cfg, SITE_SECRET, token, site_secret=SITE_SECRET, scope="site1", token_store=store
    ) == {"success": True}
    result = siteverify(
        cfg, SITE_SECRET, token, site_secret=SITE_SECRET, scope="site1", token_store=store
    )
    assert result == {"success": False, "error": "invalid_token"}


def test_siteverify_wrong_secret_does_not_consume(cfg, clock, store):
    token, _ = issue_token(cfg, "site1", store)
    result = siteverify(
        cfg,
        "wrong-secret-xxxxxxx",
        token,
        site_secret=SITE_SECRET,
        scope="site1",
        token_store=store,
    )
    assert result == {"success": False, "error": "invalid_secret"}
    assert validate_token(cfg, token, scope="site1", token_store=store) is True


def test_siteverify_bytes_secret(cfg, clock, store):
    token, _ = issue_token(cfg, "site1", store)
    secret = SITE_SECRET.encode()
    assert siteverify(cfg, secret, token, site_secret=secret, scope="site1", token_store=store)[
        "success"
    ]


def test_siteverify_missing_and_non_string_secret(cfg, clock, store):
    token, _ = issue_token(cfg, "site1", store)
    for given in (None, ""):
        assert siteverify(
            cfg, given, token, site_secret=SITE_SECRET, scope="site1", token_store=store
        ) == {
            "success": False,
            "error": "missing_parameters",
        }
    for given in (123, ["x"], {"a": 1}):
        assert siteverify(
            cfg, given, token, site_secret=SITE_SECRET, scope="site1", token_store=store
        ) == {
            "success": False,
            "error": "invalid_secret",
        }


def test_siteverify_bad_token(cfg, clock, store):
    for bad in (None, "", "nope", "site1:zz:zz", 42):
        result = siteverify(
            cfg, SITE_SECRET, bad, site_secret=SITE_SECRET, scope="site1", token_store=store
        )
        assert result["success"] is False
        expected = "missing_parameters" if bad in (None, "") else "invalid_token"
        assert result["error"] == expected


def test_siteverify_token_for_other_site_rejected(cfg, clock, store):
    token, _ = issue_token(cfg, "site2", store)
    result = siteverify(
        cfg, SITE_SECRET, token, site_secret=SITE_SECRET, scope="site1", token_store=store
    )
    assert result == {"success": False, "error": "invalid_token"}


def test_siteverify_expired(cfg, clock, store):
    token, _ = issue_token(cfg, "site1", store)
    clock.advance(cfg.token_ttl_ms + 1)
    result = siteverify(
        cfg, SITE_SECRET, token, site_secret=SITE_SECRET, scope="site1", token_store=store
    )
    assert result == {"success": False, "error": "invalid_token"}


def test_siteverify_stateless_token(cfg, clock):
    token, _ = issue_token(cfg, "site1")
    assert siteverify(cfg, SITE_SECRET, token, site_secret=SITE_SECRET, scope="site1") == {
        "success": True
    }


def test_siteverify_requires_site_secret_config(cfg, clock, store):
    with pytest.raises(CapwxError):
        siteverify(cfg, "x", "t", site_secret="", token_store=store)


# ---------------------------------------------------------------- async variants


def test_async_issue_and_validate_once():
    cfg = CapConfig(secret=SECRET, token_ttl_ms=60_000)
    store = AsyncDictStore()

    async def scenario():
        token, expires = await aissue_token(cfg, "login", store)
        assert expires > 0
        assert (
            await avalidate_token(cfg, token, scope="login", token_store=store, consume=False)
            is True
        )
        assert await avalidate_token(cfg, token, scope="login", token_store=store) is True
        assert await avalidate_token(cfg, token, scope="login", token_store=store) is False
        return store.calls

    calls = asyncio.run(scenario())
    # AsyncDictStore has no peek(), so consume=False goes through take + put back.
    assert calls[0] == "put"
    assert calls.count("put") == 2
    assert calls.count("take") == 3


def test_async_stateless_round_trip():
    cfg = CapConfig(secret=SECRET, token_ttl_ms=60_000)

    async def scenario():
        token, _ = await aissue_token(cfg, "login")
        assert token.startswith("v1.")
        assert await avalidate_token(cfg, token, scope="login") is True
        assert await avalidate_token(cfg, token, scope="other") is False
        assert await avalidate_token(cfg, "garbage") is False
        assert await avalidate_token(cfg, None) is False

    asyncio.run(scenario())


def test_async_validate_accepts_sync_store(cfg, clock, store):
    token, _ = issue_token(cfg, "login", store)

    async def scenario():
        assert await avalidate_token(cfg, token, scope="login", token_store=store) is True
        assert await avalidate_token(cfg, token, scope="login", token_store=store) is False

    asyncio.run(scenario())


def test_async_expired_and_tampered():
    cfg = CapConfig(secret=SECRET, token_ttl_ms=60_000)
    state = {"ms": NOW}
    original = tokens._now_ms
    tokens._now_ms = lambda: state["ms"]
    try:
        store = AsyncDictStore()

        async def scenario():
            token, _ = await aissue_token(cfg, "login", store)
            site, token_id, secret_part = token.split(":")
            tampered = (
                f"{site}:{token_id}:{('0' if secret_part[0] != '0' else '1')}{secret_part[1:]}"
            )
            assert await avalidate_token(cfg, tampered, scope="login", token_store=store) is False
            state["ms"] += cfg.token_ttl_ms
            assert await avalidate_token(cfg, token, scope="login", token_store=store) is False

        asyncio.run(scenario())
    finally:
        tokens._now_ms = original


def test_asiteverify_success_and_failures():
    cfg = CapConfig(secret=SECRET, token_ttl_ms=60_000)
    store = AsyncDictStore()

    async def scenario():
        token, _ = await aissue_token(cfg, "site1", store)
        assert await asiteverify(
            cfg,
            "nope-nope-nope-nope",
            token,
            site_secret=SITE_SECRET,
            scope="site1",
            token_store=store,
        ) == {"success": False, "error": "invalid_secret"}
        assert await asiteverify(
            cfg, SITE_SECRET, token, site_secret=SITE_SECRET, scope="site1", token_store=store
        ) == {"success": True}
        assert await asiteverify(
            cfg, SITE_SECRET, token, site_secret=SITE_SECRET, scope="site1", token_store=store
        ) == {"success": False, "error": "invalid_token"}
        assert await asiteverify(
            cfg, SITE_SECRET, None, site_secret=SITE_SECRET, scope="site1", token_store=store
        ) == {"success": False, "error": "missing_parameters"}

    asyncio.run(scenario())


def test_asiteverify_consumes_only_with_valid_secret():
    cfg = CapConfig(secret=SECRET, token_ttl_ms=60_000)
    store = AsyncDictStore()

    async def scenario():
        token, _ = await aissue_token(cfg, "site1", store)
        await asiteverify(
            cfg,
            "bad-secret-xxxxxxxx",
            token,
            site_secret=SITE_SECRET,
            scope="site1",
            token_store=store,
        )
        assert (
            await avalidate_token(cfg, token, scope="site1", token_store=store, consume=False)
            is True
        )

    asyncio.run(scenario())
