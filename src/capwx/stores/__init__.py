"""capwx.stores: NonceStore / TokenStore protocols (sync and async) and helpers.

- ``NonceStore.claim`` provides replay protection for ``redeem``: the first claim of a key wins.
- ``TokenStore`` makes verification tokens single-use: ``put`` stores a token hash with its expiry,
  ``take`` atomically reads and deletes it.

Sync stores are used with the sync API (``create_challenge``, ``redeem``, ``validate_token``,
``siteverify``); async stores (methods are ``async def``) with the ``a*`` twins. Passing an async
store to a sync function raises ``CapwxError``.

Optional: a store may also implement ``peek(key) -> int | None`` (non-destructive read). Tokens
validated with ``consume=False`` use it when present.
"""

from __future__ import annotations

import inspect
from typing import Protocol, runtime_checkable


@runtime_checkable
class NonceStore(Protocol):
    def claim(self, key: str, ttl_seconds: int) -> bool: ...  # SET NX EX; True if newly set


@runtime_checkable
class TokenStore(Protocol):
    def put(self, key: str, expires_ms: int, ttl_seconds: int) -> None: ...
    def take(self, key: str) -> int | None: ...  # atomic get-and-delete; expires_ms or None


@runtime_checkable
class AsyncNonceStore(Protocol):
    async def claim(self, key: str, ttl_seconds: int) -> bool: ...


@runtime_checkable
class AsyncTokenStore(Protocol):
    async def put(self, key: str, expires_ms: int, ttl_seconds: int) -> None: ...
    async def take(self, key: str) -> int | None: ...


_STORE_METHODS = ("claim", "put", "take")


def is_async_store(store: object) -> bool:
    """True if the store's methods are coroutine functions (an async store)."""
    for name in _STORE_METHODS:
        method = getattr(store, name, None)
        if method is not None and inspect.iscoroutinefunction(method):
            return True
    return False


__all__ = [
    "AsyncNonceStore",
    "AsyncTokenStore",
    "NonceStore",
    "TokenStore",
    "is_async_store",
]
