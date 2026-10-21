"""capwx.stores.django_cache: DjangoCacheStore (NonceStore and TokenStore). Extra: ``django``.

Backed by ``django.core.cache.caches[alias]``. Django is imported lazily, so this module imports
without Django installed.

Caveats:
- Django has no portable get-and-delete. ``take`` therefore wins a race with an atomic
  ``cache.add`` of a ``<key>:consumed`` marker: only the first consumer gets the value. That holds
  where ``add`` is atomic: Redis, Memcached and locmem. The database cache backend is not atomic
  there, so use RedisStore with it when single-use must hold under concurrency.
- ``claim`` uses ``cache.add`` (atomic on Redis, Memcached and locmem).
- Keys contain the site scope, so they must satisfy the backend's key rules (Memcached rejects
  spaces and keys over 250 characters).
"""

from __future__ import annotations

import math
import time
from typing import Any

_CONSUMED_SUFFIX = ":consumed"


def _parse_int(raw: Any) -> int | None:
    if raw is None or isinstance(raw, bool):
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


class DjangoCacheStore:
    def __init__(self, alias: str = "default") -> None:
        self._alias = alias

    def _cache(self) -> Any:
        from django.core.cache import caches  # lazy: Django is optional

        return caches[self._alias]  # pyright: ignore[reportUnknownVariableType]

    def claim(self, key: str, ttl_seconds: int) -> bool:
        return bool(self._cache().add(key, 1, timeout=max(1, int(ttl_seconds))))

    def put(self, key: str, expires_ms: int, ttl_seconds: int) -> None:
        self._cache().set(key, int(expires_ms), timeout=max(1, int(ttl_seconds)))

    def take(self, key: str) -> int | None:
        cache = self._cache()
        value = _parse_int(cache.get(key))
        if value is None:
            return None
        # The atomic add decides the winner. The marker lives as long as the token could.
        remaining = max(1, math.ceil(value / 1000 - time.time()))
        if not cache.add(key + _CONSUMED_SUFFIX, 1, timeout=remaining):
            return None
        cache.delete(key)
        return value

    def peek(self, key: str) -> int | None:
        return _parse_int(self._cache().get(key))
