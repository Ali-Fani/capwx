"""Regression tests for the security checklist (docs/security-checklist.md, M13).

Each test pins one checklist item that the code must keep true.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest
from django.test import RequestFactory

from capwx._crypto import decrypt_gcm, jwt_verify
from capwx.challenge import create_challenge, redeem
from capwx.config import CapConfig
from capwx.contrib.django.conf import SiteConf
from capwx.errors import CapwxError
from capwx.protocols import hashwx, sha256_pow
from capwx.protocols.hashwx import MAX_HASHWX_DIFFICULTY

SECRET = "test-secret-0123456789abcdef"
NOW = 1_700_000_000_000  # ms


def test_config_repr_never_contains_the_secret() -> None:
    cfg = CapConfig(secret=SECRET)
    assert SECRET not in repr(cfg)
    assert SECRET.encode() not in repr(CapConfig(secret=SECRET.encode())).encode()


def test_site_conf_repr_never_contains_the_site_secret() -> None:
    site_secret = "site-secret-0123456789"
    site = SiteConf(name="login", config=CapConfig(secret=SECRET), site_secret=site_secret)
    assert site_secret not in repr(site)
    assert SECRET not in repr(site)


def test_sha256_verify_refuses_an_empty_or_oversized_target() -> None:
    # An empty target is a prefix of every digest, so without the bound any nonce would verify.
    assert sha256_pow.verify({"salt": "s", "target": ""}, {"nonce": 1}) is False
    assert sha256_pow.verify({"salt": "s", "target": "0" * 17}, {"nonce": 1}) is False
    assert sha256_pow.verify({"salt": "s", "target": "zz"}, {"nonce": 1}) is False


def test_sha256_verify_still_accepts_a_correct_solution() -> None:
    salt = "abcd"
    nonce = 0
    while not hashlib.sha256((salt + str(nonce)).encode()).hexdigest().startswith("00"):
        nonce += 1
    assert sha256_pow.verify({"salt": salt, "target": "00"}, {"nonce": nonce}) is True


class _EngineMustNotRun:
    def hash(self, seed: bytes, nonce: int) -> int:  # pragma: no cover - the test fails if called
        raise AssertionError("the bound must be checked before any wasm evaluation")


@pytest.mark.parametrize("difficulty", [MAX_HASHWX_DIFFICULTY + 1, 0, -1])
def test_hashwx_verify_bounds_difficulty_before_evaluating(difficulty: int) -> None:
    expected = {"protocol": "hashwx", "c": "ab" * 32, "d": difficulty, "n": 16}
    assert hashwx.verify(expected, {"nonce": 0}, engine=_EngineMustNotRun()) is False


def test_hashwx_mint_difficulty_range_matches_verify_bound() -> None:
    # The largest difficulty config accepts is the largest verify accepts, and no more.
    cfg = CapConfig(
        secret=SECRET, hashwx_difficulty=MAX_HASHWX_DIFFICULTY, hashwx_challenge_count=1
    )
    [(payload, _expected)] = hashwx.mint(cfg)
    assert payload["d"] == MAX_HASHWX_DIFFICULTY
    with pytest.raises(CapwxError, match="hashwx_difficulty"):
        CapConfig(secret=SECRET, hashwx_difficulty=MAX_HASHWX_DIFFICULTY + 1)


def _expected_entries(cfg: CapConfig, response: dict[str, Any]) -> list[dict[str, Any]]:
    payload = jwt_verify(response["token"], cfg.secret)
    assert payload is not None
    decrypted = decrypt_gcm(payload["ev"], cfg.secret, "cap:fmt2-v1")
    return list(decrypted["expected"])


HOSTILE_SOLUTIONS: list[Any] = [
    None,
    "nope",
    [1, [2, [3]]],
    {"nonce": "x" * 100},
    {"nonce": 10**30},
    {"nonce": float("nan")},
    {"nonce": True},
    {"nonce": "9" * 40},
    {"instr": {"i": float("nan"), "state": [1, {"a": None}], "p": [[1]], "vp": [1e308, -1e308]}},
    {"instr": {"i": "x", "state": {"": 1e400}, "p": {"webdriver": [None]}, "vp": "wide"}},
    {"blocked": None, "timeout": [], "instr": None},
]


def test_hostile_client_solutions_never_raise() -> None:
    cfg = CapConfig(
        secret=SECRET,
        protocols=("sha256-pow", "hashwx", "instrumentation"),
        sha256_difficulty=1,
        hashwx_difficulty=1000,
        hashwx_challenge_count=2,
    )
    response = create_challenge(cfg, now_ms=NOW)
    count = len(_expected_entries(cfg, response))
    solutions_per_entry = [HOSTILE_SOLUTIONS[i % len(HOSTILE_SOLUTIONS)] for i in range(count)]

    bodies: list[Any] = [
        {"token": response["token"], "solutions": solutions_per_entry},
        {"token": response["token"], "solutions": solutions_per_entry, "instr_blocked": "yes"},
        {"token": response["token"], "solutions": solutions_per_entry, "instr_timeout": [1]},
        {"token": response["token"], "solutions": "nope"},
        {"token": "x" * 10_000, "solutions": []},
        {"token": "a.b.c", "solutions": []},
        {"token": 7, "solutions": []},
        {"token": response["token"][:-3], "solutions": solutions_per_entry},
        json.loads('{"token": "t", "solutions": [{"nonce": NaN}], "token2": Infinity}'),
        [1, 2, 3],
        "not an object",
        None,
    ]
    for body in bodies:
        result = redeem(cfg, body, now_ms=NOW + 1)
        assert result.success is False, body
        assert result.token is None


def test_an_empty_field_name_disables_the_body_lookup() -> None:
    # CapRequired(field="") promises that only the header counts; an empty JSON key must not match.
    from capwx.contrib.django.decorators import extract_token

    request = RequestFactory().post(
        "/any", data=json.dumps({"": "forged"}), content_type="application/json"
    )
    assert extract_token(request, "", "X-Cap-Token") is None
    header_request = RequestFactory().post("/any", HTTP_X_CAP_TOKEN="from-header")
    assert extract_token(header_request, "", "X-Cap-Token") == "from-header"


class _StaleReadCache:
    """A cache whose ``get`` still sees a key after another caller deleted it.

    That is the race window between two concurrent consumers of one verification token.
    """

    def __init__(self) -> None:
        self.values: dict[str, object] = {}
        self.markers: set[str] = set()

    def set(self, key: str, value: object, timeout: int | None = None) -> None:
        self.values[key] = value

    def get(self, key: str, default: object = None) -> object:
        return self.values.get(key, default)  # deletes are not visible to this reader

    def delete(self, key: str) -> None:
        return None

    def add(self, key: str, value: object, timeout: int | None = None) -> bool:
        if key in self.markers:
            return False
        self.markers.add(key)
        return True


def test_a_verification_token_is_consumed_by_exactly_one_caller_under_a_race(monkeypatch) -> None:
    from capwx.stores.django_cache import DjangoCacheStore

    store = DjangoCacheStore()
    fake = _StaleReadCache()
    monkeypatch.setattr(store, "_cache", lambda: fake)
    expires_ms = 2_000_000_000_000  # far in the future, so the marker timeout is positive
    store.put("capwx:token:login:0123456789abcdef:h", expires_ms, 60)
    key = "capwx:token:login:0123456789abcdef:h"
    winners = [store.take(key), store.take(key)]
    assert winners == [expires_ms, None]
