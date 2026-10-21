"""capwx.tokens: verification tokens, validate_token() and siteverify().

Two token formats:

- Stored (when a TokenStore is given): ``"{site}:{token_id}:{secret_part}"`` where
  ``site = scope or "default"``. Only ``sha256(secret_part)`` is stored, under
  ``capwx:token:{site}:{token_id}:{hash}``. ``validate_token`` consumes the token with
  ``TokenStore.take``, so it is single-use. This is the same 3-part shape Cap Standalone's
  ``/siteverify`` expects.
- Stateless (no store): ``"v1." + HS256 JWT`` with ``{"t": "verify", "sk": scope, "exp", "n"}``.
  Stateless tokens are NOT single-use: they stay valid until ``exp``. Use them only with a short
  ``token_ttl_ms``, and not where replay matters. ``validate_token`` refuses stateless tokens when
  a store is passed, because they could not be consumed there.

Client input never raises: bad tokens yield ``False`` / ``{"success": False}``. Programmer errors
(bad scope, bad secret config, async store passed to a sync function) raise ``CapwxError``.
"""

from __future__ import annotations

import hmac
import inspect
import math
import re
import time
from typing import Any

from capwx._crypto import jwt_sign, jwt_verify, random_hex, sha256_hex
from capwx.config import CapConfig
from capwx.errors import CapwxError
from capwx.stores import is_async_store

STATELESS_PREFIX = "v1."
DEFAULT_SITE = "default"
_ID_RE = re.compile(r"[0-9a-f]{16}")  # random_hex(8)
_SECRET_PART_RE = re.compile(r"[0-9a-f]{30}")  # random_hex(15)


def _now_ms() -> int:
    return int(time.time() * 1000)


# --------------------------------------------------------------------------- helpers


def _norm_scope(scope: object) -> str | None:
    """None/'' mean no scope. Anything else must be a str without ':' (it is a token field)."""
    if scope is None or scope == "":
        return None
    if not isinstance(scope, str) or ":" in scope:
        raise CapwxError("scope must be a str without ':' (or None)")
    return scope


def _site(scope: str | None) -> str:
    return scope or DEFAULT_SITE


def _store_key(site: str, token_id: str, secret_part: str) -> str:
    return f"capwx:token:{site}:{token_id}:{sha256_hex(secret_part)}"


def _ttl_seconds(config: CapConfig) -> int:
    return max(1, math.ceil(config.token_ttl_ms / 1000))


def _remaining_ttl(expires_ms: int, now_ms: int) -> int:
    return max(1, math.ceil((expires_ms - now_ms) / 1000))


def _as_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _reject_async_store(store: object) -> None:
    if store is not None and is_async_store(store):
        raise CapwxError("async token store passed to a sync function; use the a* variant")


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _parse_stored(token: object) -> tuple[str, str, str] | None:
    """Split a stored token into (site, token_id, secret_part), or None if malformed."""
    if not isinstance(token, str):
        return None
    parts = token.split(":")
    if len(parts) != 3:
        return None
    site, token_id, secret_part = parts
    if not site or _ID_RE.fullmatch(token_id) is None:
        return None
    if _SECRET_PART_RE.fullmatch(secret_part) is None:
        return None
    return site, token_id, secret_part


def _stateless_payload_ok(config: CapConfig, token: str, scope: str | None, now: int) -> bool:
    payload = jwt_verify(token[len(STATELESS_PREFIX) :], config.secret)
    if payload is None or payload.get("t") != "verify":
        return False
    if payload.get("sk") != scope:
        return False
    exp = _as_int(payload.get("exp"))
    return exp is not None and exp > now


def _check_site_secret(given: object, expected: object) -> str | None:
    """Return an error code, or None if the request secret matches the site secret."""
    if not isinstance(expected, (str, bytes)) or not expected:
        raise CapwxError("site_secret must be a non-empty str or bytes")
    if given is None or (isinstance(given, (str, bytes)) and not given):
        return "missing_parameters"
    if isinstance(given, str):
        given_b = given.encode("utf-8")
    elif isinstance(given, bytes):
        given_b = given
    else:
        return "invalid_secret"
    expected_b = expected.encode("utf-8") if isinstance(expected, str) else expected
    if not hmac.compare_digest(given_b, expected_b):
        return "invalid_secret"
    return None


def _siteverify_result(error: str | None) -> dict[str, Any]:
    return {"success": True} if error is None else {"success": False, "error": error}


# --------------------------------------------------------------------------- issue


def _new_stored(config: CapConfig, scope: str | None) -> tuple[str, str, int]:
    """Return (token, store_key, expires_ms) for a stored token."""
    site = _site(scope)
    token_id = random_hex(8)
    secret_part = random_hex(15)
    expires = _now_ms() + config.token_ttl_ms
    return f"{site}:{token_id}:{secret_part}", _store_key(site, token_id, secret_part), expires


def _new_stateless(config: CapConfig, scope: str | None) -> tuple[str, int]:
    expires = _now_ms() + config.token_ttl_ms
    payload = {"t": "verify", "sk": scope, "exp": expires, "n": random_hex(8)}
    return STATELESS_PREFIX + jwt_sign(payload, config.secret), expires


def issue_token(
    config: CapConfig, scope: str | None = None, token_store: Any = None
) -> tuple[str, int]:
    """Issue a verification token. Returns ``(token, expires_ms)``.

    With a ``token_store`` the token is single-use and only its hash is stored. Without one, a
    stateless (replayable until expiry) token is returned.
    """
    _reject_async_store(token_store)
    scope = _norm_scope(scope)
    if token_store is None:
        return _new_stateless(config, scope)
    token, key, expires = _new_stored(config, scope)
    token_store.put(key, expires, _ttl_seconds(config))
    return token, expires


async def aissue_token(
    config: CapConfig, scope: str | None = None, token_store: Any = None
) -> tuple[str, int]:
    """Async twin of :func:`issue_token`; awaits the store when it is async."""
    scope = _norm_scope(scope)
    if token_store is None:
        return _new_stateless(config, scope)
    token, key, expires = _new_stored(config, scope)
    await _await(token_store.put(key, expires, _ttl_seconds(config)))
    return token, expires


# --------------------------------------------------------------------------- validate


def _read_stored(token_store: Any, key: str, consume: bool, now: int) -> int | None:
    """Read the expiry for a stored token, consuming it when ``consume`` is set (sync)."""
    if consume:
        return token_store.take(key)
    if hasattr(token_store, "peek"):
        return token_store.peek(key)
    # Store has no non-destructive read: take it, then put it back with the remaining TTL.
    value = token_store.take(key)
    if value is not None:
        token_store.put(key, value, _remaining_ttl(value, now))
    return value


def validate_token(
    config: CapConfig,
    token: object,
    *,
    scope: str | None = None,
    token_store: Any = None,
    consume: bool = True,
) -> bool:
    """True if ``token`` is a valid, unexpired verification token for ``scope``.

    With a store and ``consume=True`` (default) a valid token is single-use: the second call
    returns False. ``consume=False`` checks without consuming. Never raises on bad input.
    """
    _reject_async_store(token_store)
    try:
        scope = _norm_scope(scope)
    except CapwxError:
        return False
    if not isinstance(token, str) or not token:
        return False
    now = _now_ms()

    if token.startswith(STATELESS_PREFIX):
        if token_store is not None:
            return (
                False  # stateless tokens cannot be consumed; issue stored tokens when using a store
            )
        return _stateless_payload_ok(config, token, scope, now)

    if token_store is None:
        return False
    parsed = _parse_stored(token)
    if parsed is None:
        return False
    site, token_id, secret_part = parsed
    if site != _site(scope):
        return False
    key = _store_key(site, token_id, secret_part)
    expires = _as_int(_read_stored(token_store, key, consume, now))
    return expires is not None and expires > now


async def avalidate_token(
    config: CapConfig,
    token: object,
    *,
    scope: str | None = None,
    token_store: Any = None,
    consume: bool = True,
) -> bool:
    """Async twin of :func:`validate_token`; awaits the store when it is async."""
    try:
        scope = _norm_scope(scope)
    except CapwxError:
        return False
    if not isinstance(token, str) or not token:
        return False
    now = _now_ms()

    if token.startswith(STATELESS_PREFIX):
        if token_store is not None:
            return False
        return _stateless_payload_ok(config, token, scope, now)

    if token_store is None:
        return False
    parsed = _parse_stored(token)
    if parsed is None:
        return False
    site, token_id, secret_part = parsed
    if site != _site(scope):
        return False
    key = _store_key(site, token_id, secret_part)
    if consume:
        expires = await _await(token_store.take(key))
    elif hasattr(token_store, "peek"):
        expires = await _await(token_store.peek(key))
    else:
        expires = await _await(token_store.take(key))
        if expires is not None:
            await _await(token_store.put(key, expires, _remaining_ttl(expires, now)))
    expires = _as_int(expires)
    return expires is not None and expires > now


# --------------------------------------------------------------------------- siteverify


def siteverify(
    config: CapConfig,
    secret_from_request: object,
    response_token: object,
    *,
    site_secret: str | bytes,
    scope: str | None = None,
    token_store: Any = None,
) -> dict[str, Any]:
    """Standalone-style siteverify: check the site secret, then consume the token.

    Returns ``{"success": True}`` or ``{"success": False, "error": code}`` with code one of
    ``missing_parameters``, ``invalid_secret``, ``invalid_token``. The secret is checked first, so
    a caller without the secret cannot burn tokens.
    """
    error = _check_site_secret(secret_from_request, site_secret)
    if error is None and (response_token is None or response_token == ""):
        error = "missing_parameters"
    if error is None and not validate_token(
        config, response_token, scope=scope, token_store=token_store, consume=True
    ):
        error = "invalid_token"
    return _siteverify_result(error)


async def asiteverify(
    config: CapConfig,
    secret_from_request: object,
    response_token: object,
    *,
    site_secret: str | bytes,
    scope: str | None = None,
    token_store: Any = None,
) -> dict[str, Any]:
    """Async twin of :func:`siteverify`."""
    error = _check_site_secret(secret_from_request, site_secret)
    if error is None and (response_token is None or response_token == ""):
        error = "missing_parameters"
    if error is None and not await avalidate_token(
        config, response_token, scope=scope, token_store=token_store, consume=True
    ):
        error = "invalid_token"
    return _siteverify_result(error)


__all__ = [
    "STATELESS_PREFIX",
    "aissue_token",
    "asiteverify",
    "avalidate_token",
    "issue_token",
    "siteverify",
    "validate_token",
]
