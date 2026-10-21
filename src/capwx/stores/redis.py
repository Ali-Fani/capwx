"""capwx.stores.redis: RedisStore (sync) and AsyncRedisStore (redis.asyncio). Extra: ``redis``.

The client is injected (``redis.Redis`` / ``redis.asyncio.Redis``), so this module never imports
``redis`` and imports fine without it installed.

Key namespace: ``prefix`` is applied to keys that do not already start with it, so the keys
capwx builds (``capwx:nonce:...``, ``capwx:token:...``) are used as-is with the default prefix.

Operations:
- ``claim``  = ``SET key 1 NX EX ttl``
- ``put``    = ``SET key expires_ms EX ttl``
- ``take``   = ``GETDEL`` (Redis >= 6.2); falls back to ``MULTI/GET/DEL`` on servers or client
  versions without it.
- ``peek``   = ``GET``
"""

from __future__ import annotations

import inspect
from typing import Any


def _full_key(prefix: str, key: str) -> str:
    return key if key.startswith(prefix) else prefix + key


def _ttl(ttl_seconds: int) -> int:
    return max(1, int(ttl_seconds))


def _parse_int(raw: Any) -> int | None:
    if raw is None:
        return None
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("ascii")
        except UnicodeDecodeError:
            return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _getdel_unsupported(exc: BaseException) -> bool:
    """True if the error means GETDEL is unavailable (old server or old client)."""
    if isinstance(exc, AttributeError):
        return True
    return "unknown command" in str(exc).lower()


class RedisStore:
    """Sync store over a ``redis.Redis`` client (``decode_responses`` may be on or off)."""

    def __init__(self, client: Any, prefix: str = "capwx:") -> None:
        self._client = client
        self._prefix = prefix
        self._getdel_ok = True

    def _k(self, key: str) -> str:
        return _full_key(self._prefix, key)

    def claim(self, key: str, ttl_seconds: int) -> bool:
        return bool(self._client.set(self._k(key), 1, nx=True, ex=_ttl(ttl_seconds)))

    def put(self, key: str, expires_ms: int, ttl_seconds: int) -> None:
        self._client.set(self._k(key), int(expires_ms), ex=_ttl(ttl_seconds))

    def take(self, key: str) -> int | None:
        full = self._k(key)
        if self._getdel_ok:
            try:
                return _parse_int(self._client.getdel(full))
            except Exception as exc:
                if not _getdel_unsupported(exc):
                    raise
                self._getdel_ok = False
        pipe = self._client.pipeline(transaction=True)
        pipe.get(full)
        pipe.delete(full)
        raw, _ = pipe.execute()
        return _parse_int(raw)

    def peek(self, key: str) -> int | None:
        return _parse_int(self._client.get(self._k(key)))


class AsyncRedisStore:
    """Async store over a ``redis.asyncio.Redis`` client."""

    def __init__(self, client: Any, prefix: str = "capwx:") -> None:
        self._client = client
        self._prefix = prefix
        self._getdel_ok = True

    def _k(self, key: str) -> str:
        return _full_key(self._prefix, key)

    async def claim(self, key: str, ttl_seconds: int) -> bool:
        return bool(await self._client.set(self._k(key), 1, nx=True, ex=_ttl(ttl_seconds)))

    async def put(self, key: str, expires_ms: int, ttl_seconds: int) -> None:
        await self._client.set(self._k(key), int(expires_ms), ex=_ttl(ttl_seconds))

    async def take(self, key: str) -> int | None:
        full = self._k(key)
        if self._getdel_ok:
            try:
                return _parse_int(await self._client.getdel(full))
            except Exception as exc:
                if not _getdel_unsupported(exc):
                    raise
                self._getdel_ok = False
        pipe = self._client.pipeline(transaction=True)
        pipe.get(full)
        pipe.delete(full)
        raw, _ = await pipe.execute()
        return _parse_int(raw)

    async def peek(self, key: str) -> int | None:
        value = self._client.get(self._k(key))
        if inspect.isawaitable(value):
            value = await value
        return _parse_int(value)
