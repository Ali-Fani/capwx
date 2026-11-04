"""acreate_challenge / aredeem run CPU-bound work in a worker thread (asyncio.to_thread).

Results must match the sync twins, and the work must leave the event loop thread.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

import pytest
from _solver import body_for

from capwx import challenge
from capwx.challenge import acreate_challenge, aredeem, create_challenge, redeem
from capwx.config import CapConfig
from capwx.stores.memory import MemoryStore

SECRET = "test-secret-0123456789abcdef"
NOW = 1_700_000_000_000
TTL_MS = 60_000


def make_cfg() -> CapConfig:
    return CapConfig(
        secret=SECRET,
        protocols=("sha256-pow",),
        sha256_difficulty=1,
        sha256_count=2,
        challenge_ttl_ms=TTL_MS,
        token_ttl_ms=TTL_MS,
    )


def test_acreate_challenge_matches_sync_twin_and_runs_off_loop(monkeypatch: pytest.MonkeyPatch):
    cfg = make_cfg()
    real_create = challenge.create_challenge
    seen: list[int] = []

    def recording(*args: Any, **kwargs: Any) -> dict[str, Any]:
        seen.append(threading.get_ident())
        return real_create(*args, **kwargs)

    monkeypatch.setattr(challenge, "create_challenge", recording)

    async def scenario() -> tuple[int, dict[str, Any]]:
        loop_thread = threading.get_ident()
        resp = await acreate_challenge(cfg, scope="login", now_ms=NOW)
        return loop_thread, resp

    loop_thread, resp = asyncio.run(scenario())

    assert len(seen) == 1
    assert seen[0] != loop_thread
    sync = real_create(cfg, scope="login", now_ms=NOW)
    assert set(resp) == {"token", "format", "challenges", "expires"} == set(sync)
    assert resp["format"] == sync["format"] == 2
    assert resp["expires"] == sync["expires"] == NOW + TTL_MS
    assert [c["protocol"] for c in resp["challenges"]] == [
        c["protocol"] for c in sync["challenges"]
    ]


def test_aredeem_matches_sync_twin_and_verifies_off_loop(monkeypatch: pytest.MonkeyPatch):
    cfg = make_cfg()
    resp = create_challenge(cfg, scope="login", now_ms=NOW)
    body = body_for(SECRET, resp)
    seen: list[int] = []
    real_verify = challenge._verify_body

    def recording(*args: Any, **kwargs: Any) -> Any:
        seen.append(threading.get_ident())
        return real_verify(*args, **kwargs)

    monkeypatch.setattr(challenge, "_verify_body", recording)

    async def scenario() -> tuple[int, Any]:
        loop_thread = threading.get_ident()
        store = MemoryStore()
        result = await aredeem(
            cfg, body, scope="login", nonce_store=store, token_store=store, now_ms=NOW + 1
        )
        return loop_thread, result

    loop_thread, async_result = asyncio.run(scenario())

    assert len(seen) == 1
    assert seen[0] != loop_thread

    sync_store = MemoryStore()
    sync_result = redeem(
        cfg, body, scope="login", nonce_store=sync_store, token_store=sync_store, now_ms=NOW + 1
    )
    assert async_result.success is True and sync_result.success is True
    assert async_result.scope == sync_result.scope == "login"
    assert isinstance(async_result.expires, int) and isinstance(sync_result.expires, int)
    assert async_result.token is not None and async_result.token.startswith("login:")
    assert async_result.reason is None and sync_result.reason is None


def test_aredeem_failure_result_matches_sync(monkeypatch: pytest.MonkeyPatch):
    cfg = make_cfg()
    resp = create_challenge(cfg, scope="login", now_ms=NOW)
    body = body_for(SECRET, resp)
    body["solutions"] = []  # wrong number of solutions -> INVALID_SOLUTIONS

    async_result = asyncio.run(aredeem(cfg, body, scope="login", now_ms=NOW + 1))
    sync_result = redeem(cfg, body, scope="login", now_ms=NOW + 1)
    assert async_result.success is False and sync_result.success is False
    assert async_result.reason == sync_result.reason
