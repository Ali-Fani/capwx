"""Tests for capwx.stores (M9): shared NonceStore/TokenStore suite plus store-specific checks.

Backends in the shared suite:
- memory                    always
- redis_fake / redis_fake_nogetdel   always (in-test fake client, with and without GETDEL)
- redis                     needs env REDIS_URL and the ``redis`` package, otherwise skipped
- django                    needs the ``django`` package, otherwise skipped (locmem cache)
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import threading
import time
import uuid

import pytest

from capwx.stores import (
    AsyncNonceStore,
    AsyncTokenStore,
    NonceStore,
    TokenStore,
    is_async_store,
)
from capwx.stores.django_cache import DjangoCacheStore
from capwx.stores.memory import MemoryStore
from capwx.stores.redis import AsyncRedisStore, RedisStore

HAS_DJANGO = importlib.util.find_spec("django") is not None
HAS_REDIS = importlib.util.find_spec("redis") is not None


class FakeClock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# ---------------------------------------------------------------- fake Redis client


class FakeRedis:
    """Minimal in-memory stand-in for redis.Redis (strings + expiry + pipeline)."""

    def __init__(self, clock: FakeClock, *, getdel: bool = True) -> None:
        self._clock = clock
        self._data: dict[str, tuple[object, float | None]] = {}
        self._has_getdel = getdel
        if getdel:
            self.getdel = self._getdel  # type: ignore[method-assign]

    def _live(self, name: str):
        entry = self._data.get(name)
        if entry is None:
            return None
        _value, expires_at = entry
        if expires_at is not None and expires_at <= self._clock.now:
            del self._data[name]
            return None
        return entry

    def set(self, name, value, nx=False, ex=None):
        if nx and self._live(name) is not None:
            return None
        expires_at = None if ex is None else self._clock.now + ex
        self._data[name] = (value, expires_at)
        return True

    def get(self, name):
        entry = self._live(name)
        return None if entry is None else entry[0]

    def _getdel(self, name):
        value = self.get(name)
        self._data.pop(name, None)
        return value

    def delete(self, *names):
        for name in names:
            self._data.pop(name, None)

    def pipeline(self, transaction=True):
        return _FakePipeline(self)

    def keys(self):
        return list(self._data)


class _FakePipeline:
    def __init__(self, client: FakeRedis) -> None:
        self._client = client
        self._ops: list[tuple[str, str]] = []

    def get(self, name):
        self._ops.append(("get", name))
        return self

    def delete(self, name):
        self._ops.append(("delete", name))
        return self

    def execute(self):
        results = []
        for op, name in self._ops:
            if op == "get":
                results.append(self._client.get(name))
            else:
                self._client.delete(name)
                results.append(1)
        return results


class AsyncFakeRedis:
    """Async wrapper with the same surface as redis.asyncio.Redis."""

    def __init__(self, sync: FakeRedis) -> None:
        self._sync = sync

    async def set(self, name, value, nx=False, ex=None):
        return self._sync.set(name, value, nx=nx, ex=ex)

    async def get(self, name):
        return self._sync.get(name)

    async def getdel(self, name):
        if not self._sync._has_getdel:
            raise AttributeError("getdel")
        return self._sync._getdel(name)

    def pipeline(self, transaction=True):
        return _AsyncFakePipeline(self._sync)


class _AsyncFakePipeline(_FakePipeline):
    async def execute(self):  # type: ignore[override]
        return _FakePipeline.execute(self)


# ---------------------------------------------------------------- fixtures


class Kit:
    """A store under test plus how to let its TTLs elapse."""

    def __init__(self, store, advance, *, kind: str, is_async: bool = False) -> None:
        self.store = store
        self.advance = advance
        self.kind = kind
        self.is_async = is_async


def _django_settings() -> None:
    from django.conf import settings

    if not settings.configured:
        settings.configure(
            CACHES={
                "default": {
                    "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                    "LOCATION": "capwx-tests",
                }
            }
        )


@pytest.fixture(
    params=["memory", "redis_fake", "redis_fake_nogetdel", "redis", "django"],
)
def kit(request):
    kind = request.param
    clock = FakeClock()

    if kind == "memory":
        return Kit(MemoryStore(clock=clock), clock.advance, kind=kind)

    if kind in ("redis_fake", "redis_fake_nogetdel"):
        fake = FakeRedis(clock, getdel=(kind == "redis_fake"))
        return Kit(RedisStore(fake, prefix="capwx-test:"), clock.advance, kind=kind)

    if kind == "redis":
        url = os.environ.get("REDIS_URL")
        if not url or not HAS_REDIS:
            pytest.skip("needs REDIS_URL and the redis package")
        import redis  # pyright: ignore[reportMissingImports]

        client = redis.Redis.from_url(url)
        prefix = f"capwx-test:{uuid.uuid4().hex}:"
        request.addfinalizer(lambda: _drop_prefix(client, prefix))
        return Kit(RedisStore(client, prefix=prefix), time.sleep, kind=kind)

    # django
    if not HAS_DJANGO:
        pytest.skip("needs the django package")
    _django_settings()
    return Kit(DjangoCacheStore(), time.sleep, kind=kind)


def _drop_prefix(client, prefix: str) -> None:
    for key in client.scan_iter(match=f"{prefix}*"):
        client.delete(key)


def _unique(name: str) -> str:
    return f"{name}:{uuid.uuid4().hex}"


def _expiry_advance(kit: Kit, seconds: float) -> None:
    # Fake clocks move exactly; real backends need a little slack for the wall clock.
    kit.advance(seconds + 0.1)


# ---------------------------------------------------------------- shared suite


def test_protocols_are_satisfied(kit):
    assert isinstance(kit.store, NonceStore)
    assert isinstance(kit.store, TokenStore)


def test_claim_twice(kit):
    key = _unique("nonce")
    assert kit.store.claim(key, 30) is True
    assert kit.store.claim(key, 30) is False


def test_claim_different_keys_independent(kit):
    assert kit.store.claim(_unique("a"), 30) is True
    assert kit.store.claim(_unique("b"), 30) is True


def test_claim_expires_after_ttl(kit):
    key = _unique("nonce")
    assert kit.store.claim(key, 1) is True
    assert kit.store.claim(key, 1) is False
    _expiry_advance(kit, 1)
    assert kit.store.claim(key, 1) is True


def test_put_take_twice(kit):
    key = _unique("token")
    expires = 1_234_567_890_000
    kit.store.put(key, expires, 30)
    assert kit.store.take(key) == expires
    assert kit.store.take(key) is None


def test_take_missing_key(kit):
    assert kit.store.take(_unique("missing")) is None


def test_put_expires_after_ttl(kit):
    key = _unique("token")
    kit.store.put(key, 999, 1)
    _expiry_advance(kit, 1)
    assert kit.store.take(key) is None


def test_put_overwrites(kit):
    key = _unique("token")
    kit.store.put(key, 1, 30)
    kit.store.put(key, 2, 30)
    assert kit.store.take(key) == 2


def test_ttl_one_is_usable_immediately(kit):
    # ttl 1 is the smallest meaningful TTL: the entry is live immediately after writing.
    key = _unique("token")
    kit.store.put(key, 5, 1)
    assert kit.store.take(key) == 5


# ---------------------------------------------------------------- memory specifics


def test_memory_expiry_with_fake_clock():
    clock = FakeClock()
    store = MemoryStore(clock=clock)
    assert store.claim("k", 10) is True
    clock.advance(9.999)
    assert store.claim("k", 10) is False
    clock.advance(0.001)  # exactly at expiry: treated as expired
    assert store.claim("k", 10) is True


def test_memory_put_take_expired_clock():
    clock = FakeClock()
    store = MemoryStore(clock=clock)
    store.put("t", 42, 5)
    clock.advance(5)
    assert store.take("t") is None


def test_memory_peek_does_not_consume():
    store = MemoryStore(clock=FakeClock())
    store.put("t", 7, 30)
    assert store.peek("t") == 7
    assert store.peek("t") == 7
    assert store.take("t") == 7
    assert store.peek("t") is None


def test_memory_lazy_purge_bounds_memory():
    clock = FakeClock()
    store = MemoryStore(clock=clock)
    for i in range(1000):
        store.put(f"t{i}", i, 1)
    assert len(store) == 1000
    clock.advance(2)
    assert len(store) == 0
    # Writing after expiry purges the expired entries from the internal dict too.
    store.claim("fresh", 30)
    assert len(store._data) == 1


def test_memory_overwrite_keeps_latest_expiry():
    clock = FakeClock()
    store = MemoryStore(clock=clock)
    store.put("t", 1, 1)
    store.put("t", 2, 100)  # later expiry replaces the earlier one
    clock.advance(10)
    assert store.take("t") == 2


def test_memory_thread_safety_claim_once():
    store = MemoryStore(clock=FakeClock())
    results: list[bool] = []
    lock = threading.Lock()

    def worker():
        ok = store.claim("race", 30)
        with lock:
            results.append(ok)

    threads = [threading.Thread(target=worker) for _ in range(32)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1
    assert results.count(False) == 31


def test_memory_default_clock_is_real_time():
    store = MemoryStore()
    assert store.claim("real", 30) is True
    assert store.claim("real", 30) is False


# ---------------------------------------------------------------- redis specifics


def test_redis_applies_prefix_once():
    clock = FakeClock()
    fake = FakeRedis(clock)
    store = RedisStore(fake, prefix="myapp:")
    store.claim("x", 30)
    store.claim("myapp:already", 30)
    assert set(fake.keys()) == {"myapp:x", "myapp:already"}


def test_redis_default_prefix_keeps_capwx_keys():
    fake = FakeRedis(FakeClock())
    store = RedisStore(fake)
    store.put("capwx:token:default:abc:def", 5, 30)
    assert fake.keys() == ["capwx:token:default:abc:def"]


def test_redis_take_falls_back_without_getdel():
    clock = FakeClock()
    fake = FakeRedis(clock, getdel=False)
    store = RedisStore(fake, prefix="p:")
    store.put("t", 11, 30)
    assert store.take("t") == 11
    assert store.take("t") is None
    assert store._getdel_ok is False  # no getdel attribute: fallback path used


def test_redis_take_fallback_disables_getdel_after_unknown_command():
    class OldServer(FakeRedis):
        def getdel(self, name):
            raise RuntimeError("ERR unknown command 'GETDEL'")

    clock = FakeClock()
    fake = OldServer(clock, getdel=False)
    store = RedisStore(fake, prefix="p:")
    store.put("t", 3, 30)
    assert store.take("t") == 3
    assert store._getdel_ok is False


def test_redis_take_reraises_other_errors():
    class Broken(FakeRedis):
        def getdel(self, name):
            raise ConnectionError("down")

    store = RedisStore(Broken(FakeClock(), getdel=False), prefix="p:")
    with pytest.raises(ConnectionError):
        store.take("t")


def test_redis_claim_bytes_and_decoding():
    class BytesRedis(FakeRedis):
        def get(self, name):
            value = super().get(name)
            return value.encode() if isinstance(value, str) else value

    fake = BytesRedis(FakeClock())
    store = RedisStore(fake, prefix="p:")
    store.put("t", 123456, 30)
    assert store.peek("t") == 123456
    assert store.take("t") == 123456


# ---------------------------------------------------------------- async store


def test_is_async_store_detection():
    assert is_async_store(MemoryStore()) is False
    assert is_async_store(object()) is False
    assert is_async_store(AsyncRedisStore(AsyncFakeRedis(FakeRedis(FakeClock())))) is True


def test_async_store_satisfies_async_protocols():
    store = AsyncRedisStore(AsyncFakeRedis(FakeRedis(FakeClock())))
    assert isinstance(store, AsyncNonceStore)
    assert isinstance(store, AsyncTokenStore)


def test_async_redis_store_behaviour():
    clock = FakeClock()
    store = AsyncRedisStore(AsyncFakeRedis(FakeRedis(clock)), prefix="a:")

    async def scenario():
        assert await store.claim("n", 30) is True
        assert await store.claim("n", 30) is False
        await store.put("t", 77, 30)
        assert await store.peek("t") == 77
        assert await store.take("t") == 77
        assert await store.take("t") is None
        await store.put("gone", 1, 1)
        clock.advance(1.5)
        assert await store.take("gone") is None

    asyncio.run(scenario())


def test_async_redis_store_fallback_without_getdel():
    clock = FakeClock()
    store = AsyncRedisStore(AsyncFakeRedis(FakeRedis(clock, getdel=False)), prefix="a:")

    async def scenario():
        await store.put("t", 5, 30)
        assert await store.take("t") == 5
        assert await store.take("t") is None

    asyncio.run(scenario())


def test_async_memory_like_store_is_detected_via_coroutines():
    class AsyncOnly:
        async def claim(self, key, ttl_seconds):
            return True

    assert is_async_store(AsyncOnly()) is True


# ---------------------------------------------------------------- django cache


def test_django_store_constructs_without_django_import():
    # Constructing the store must not import Django (it is only imported on first use).
    store = DjangoCacheStore(alias="whatever")
    assert store._alias == "whatever"


@pytest.mark.skipif(not HAS_DJANGO, reason="needs the django package")
def test_django_store_claim_and_take_locmem():
    _django_settings()
    store = DjangoCacheStore()
    key = _unique("dj")
    assert store.claim(key, 30) is True
    assert store.claim(key, 30) is False
    store.put(key + ":t", 99, 30)
    assert store.peek(key + ":t") == 99
    assert store.take(key + ":t") == 99
    assert store.take(key + ":t") is None
