"""capwx.stores.memory: in-process MemoryStore (NonceStore and TokenStore).

For tests and single-process development ONLY. State lives in this process: it is lost on
restart, is not shared between workers or servers, and offers no replay protection across
deployments. Use RedisStore or DjangoCacheStore (on a shared backend) in production.

Expired entries are purged lazily on every call (a min-heap keyed by expiry keeps this
cheap), so memory does not grow without bound for short-lived keys.
"""

from __future__ import annotations

import heapq
import threading
import time
from collections.abc import Callable
from typing import cast


def _expiry(entry: tuple[float, object] | None) -> int | None:
    """The stored ``expires_ms`` of a TokenStore entry (``take``/``peek``); None when absent."""
    return cast("int | None", entry[1]) if entry is not None else None


class MemoryStore:
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        """``clock`` returns seconds (like ``time.time``); inject a fake one in tests."""
        self._clock = clock
        self._lock = threading.Lock()
        self._data: dict[str, tuple[float, object]] = {}  # key -> (expires_at_s, value)
        self._heap: list[tuple[float, str]] = []  # (expires_at_s, key); may contain stale entries

    def _purge(self, now: float) -> None:
        heap = self._heap
        while heap and heap[0][0] <= now:
            _, key = heapq.heappop(heap)
            entry = self._data.get(key)
            if entry is not None and entry[0] <= now:
                del self._data[key]

    def _set(self, key: str, value: object, expires_at: float) -> None:
        self._data[key] = (expires_at, value)
        heapq.heappush(self._heap, (expires_at, key))

    def __len__(self) -> int:
        """Number of live (unexpired) entries."""
        with self._lock:
            self._purge(self._clock())
            return len(self._data)

    # NonceStore
    def claim(self, key: str, ttl_seconds: int) -> bool:
        with self._lock:
            now = self._clock()
            self._purge(now)
            if key in self._data:
                return False
            self._set(key, True, now + ttl_seconds)
            return True

    # TokenStore
    def put(self, key: str, expires_ms: int, ttl_seconds: int) -> None:
        with self._lock:
            now = self._clock()
            self._purge(now)
            self._set(key, expires_ms, now + ttl_seconds)

    def take(self, key: str) -> int | None:
        with self._lock:
            self._purge(self._clock())
            entry = self._data.pop(key, None)
            return _expiry(entry)

    def peek(self, key: str) -> int | None:
        """Non-destructive read (used by validate_token(consume=False))."""
        with self._lock:
            self._purge(self._clock())
            entry = self._data.get(key)
            return _expiry(entry)
