"""Tests for capwx.challenge (M8): create_challenge / redeem and the async twins.

The solver in ``_solver.py`` is test-only. Tokens that exercise the instrumentation failure paths
are forged with the known secret, because the honest path cannot produce them.
"""

from __future__ import annotations

import asyncio
import logging
import math
import subprocess
import sys
from typing import Any

import pytest
from _solver import FORMAT_INFO, body_for, expected_entries, solve_instrumentation

import capwx
import capwx.config as config_module
from capwx import challenge
from capwx._crypto import encrypt_gcm, jwt_sig_hex, jwt_sign, jwt_verify, random_hex
from capwx.challenge import (
    RedeemResult,
    acreate_challenge,
    aredeem,
    create_challenge,
    redeem,
    set_event_callback,
)
from capwx.config import CapConfig, InstrumentationOptions
from capwx.errors import CapwxError, Reason
from capwx.protocols import hashwx as hashwx_mod
from capwx.protocols import instrumentation as instr_pkg
from capwx.protocols.instrumentation import InstrVerifyResult
from capwx.stores.memory import MemoryStore
from capwx.tokens import avalidate_token, validate_token

SECRET = "test-secret-0123456789abcdef"
NOW = 1_700_000_000_000  # ms
TTL_MS = 60_000
ALL = ("sha256-pow", "hashwx", "instrumentation")


def make_cfg(protocols: tuple[str, ...] = ALL, **overrides: Any) -> CapConfig:
    """Low difficulty so the suite stays fast."""
    base: dict[str, Any] = {
        "secret": SECRET,
        "protocols": protocols,
        "sha256_difficulty": 1,
        "sha256_count": 2,
        "hashwx_difficulty": 20,
        "hashwx_challenge_count": 2,
        "challenge_ttl_ms": TTL_MS,
        "token_ttl_ms": TTL_MS,
    }
    base.update(overrides)
    return CapConfig(**base)


def forge(
    expected: list[Any], *, exp: int = NOW + TTL_MS, f: int = 2, scope: str | None = None
) -> str:
    """A token signed with the real secret, for the paths honest minting cannot reach."""
    payload: dict[str, Any] = {
        "f": f,
        "n": random_hex(16),
        "exp": exp,
        "iat": NOW,
        "ev": encrypt_gcm({"expected": expected}, SECRET, FORMAT_INFO),
    }
    if scope is not None:
        payload["sk"] = scope
    return jwt_sign(payload, SECRET)


def fresh(
    cfg: CapConfig | None = None, **kwargs: Any
) -> tuple[CapConfig, dict[str, Any], dict[str, Any]]:
    """A created challenge plus its solved body."""
    cfg = cfg or make_cfg()
    resp = create_challenge(cfg, now_ms=NOW, **kwargs)
    return cfg, resp, body_for(SECRET, resp)


def failing_sha_nonce(payload: dict[str, Any]) -> int:
    nonce = 0
    while hashlib_ok(payload, nonce):
        nonce += 1
    return nonce


def hashlib_ok(payload: dict[str, Any], nonce: int) -> bool:
    import hashlib

    digest = hashlib.sha256((payload["salt"] + str(nonce)).encode()).hexdigest()
    return digest.startswith(payload["target"])


class RecordingNonceStore:
    def __init__(self) -> None:
        self.claims: list[tuple[str, int]] = []

    def claim(self, key: str, ttl_seconds: int) -> bool:
        self.claims.append((key, ttl_seconds))
        return True


class RaisingNonceStore:
    def claim(self, key: str, ttl_seconds: int) -> bool:
        raise ConnectionError("redis is down")


class AsyncStore:
    """Async NonceStore + TokenStore built on MemoryStore."""

    def __init__(self) -> None:
        self.inner = MemoryStore()

    async def claim(self, key: str, ttl_seconds: int) -> bool:
        return self.inner.claim(key, ttl_seconds)

    async def put(self, key: str, expires_ms: int, ttl_seconds: int) -> None:
        self.inner.put(key, expires_ms, ttl_seconds)

    async def take(self, key: str) -> int | None:
        return self.inner.take(key)


# --------------------------------------------------------------------------- full flow


@pytest.mark.parametrize("protocols", [("sha256-pow",), ("hashwx",), ("instrumentation",), ALL])
def test_full_flow_success_then_token_is_single_use(protocols: tuple[str, ...]) -> None:
    cfg = make_cfg(protocols)
    store = MemoryStore()
    resp = create_challenge(cfg, scope="login", now_ms=NOW)
    result = redeem(
        cfg,
        body_for(SECRET, resp),
        scope="login",
        nonce_store=store,
        token_store=store,
        now_ms=NOW + 1_000,
    )

    assert result.success, result.reason
    assert result.scope == "login"
    assert result.expires is not None and result.token is not None
    assert result.to_widget_json() == {
        "success": True,
        "token": result.token,
        "expires": result.expires,
    }
    assert validate_token(cfg, result.token, scope="login", token_store=store) is True
    assert validate_token(cfg, result.token, scope="login", token_store=store) is False


def test_replay_of_same_body_is_already_redeemed() -> None:
    cfg, _, body = fresh()
    store = MemoryStore()
    first = redeem(cfg, body, nonce_store=store, now_ms=NOW + 1)
    second = redeem(cfg, body, nonce_store=store, now_ms=NOW + 1)
    assert first.success
    assert not second.success
    assert second.reason == Reason.ALREADY_REDEEMED


def test_wrong_solution_does_not_burn_the_replay_claim() -> None:
    cfg, _resp, good = fresh(make_cfg(("sha256-pow",)))
    store = MemoryStore()
    bad = {"token": good["token"], "solutions": [{"nonce": "x"}, good["solutions"][1]]}

    failed = redeem(cfg, bad, nonce_store=store, now_ms=NOW + 1)
    assert failed.reason == Reason.INVALID_SOLUTION
    assert redeem(cfg, good, nonce_store=store, now_ms=NOW + 1).success


def test_nonce_is_claimed_only_after_all_verification() -> None:
    cfg, _, good = fresh(make_cfg(("sha256-pow",)))
    store = RecordingNonceStore()
    bad = {"token": good["token"], "solutions": [{"nonce": "x"}, {"nonce": "x"}]}

    assert redeem(cfg, bad, nonce_store=store, now_ms=NOW + 1).reason == Reason.INVALID_SOLUTION
    assert store.claims == []


def test_nonce_key_and_ttl_are_derived_from_token_signature() -> None:
    cfg, _, body = fresh(make_cfg(("sha256-pow",)))
    store = RecordingNonceStore()
    # exp - now = 59_999 ms, which rounds up to 60 s.
    assert redeem(cfg, body, nonce_store=store, now_ms=NOW + 1).success
    key, ttl = store.claims[0]
    assert key == "capwx:nonce:" + jwt_sig_hex(body["token"])
    assert ttl == math.ceil(59_999 / 1000) == 60


# --------------------------------------------------------------------------- body-level reasons


@pytest.mark.parametrize("body", [None, [], "token", 7])
def test_invalid_body(body: object) -> None:
    cfg = make_cfg()
    assert redeem(cfg, body, now_ms=NOW).reason == Reason.INVALID_BODY


@pytest.mark.parametrize("body", [{}, {"token": ""}, {"token": 5, "solutions": []}])
def test_missing_token(body: dict[str, Any]) -> None:
    assert redeem(make_cfg(), body, now_ms=NOW).reason == Reason.MISSING_TOKEN


def test_missing_solutions() -> None:
    _, resp, _ = fresh()
    assert (
        redeem(make_cfg(), {"token": resp["token"]}, now_ms=NOW).reason == Reason.MISSING_SOLUTIONS
    )
    body = {"token": resp["token"], "solutions": "not-a-list"}
    assert redeem(make_cfg(), body, now_ms=NOW).reason == Reason.MISSING_SOLUTIONS


def test_invalid_token_garbage_tampered_and_format_1() -> None:
    cfg, resp, body = fresh(make_cfg(("sha256-pow",)))
    assert (
        redeem(cfg, {"token": "garbage", "solutions": []}, now_ms=NOW).reason
        == Reason.INVALID_TOKEN
    )

    # Change the FIRST signature character: the last base64url char of a 32-byte signature holds
    # only 4 data bits, so editing it can leave the decoded bytes (and the signature) unchanged.
    head, _, sig = resp["token"].rpartition(".")
    tampered = f"{head}.{'A' if sig[0] != 'A' else 'B'}{sig[1:]}"
    result = redeem(cfg, {"token": tampered, "solutions": body["solutions"]}, now_ms=NOW)
    assert result.reason == Reason.INVALID_TOKEN

    # Correctly signed, but format 1: this library refuses it.
    f1 = forge([], f=1)
    assert redeem(cfg, {"token": f1, "solutions": []}, now_ms=NOW).reason == Reason.INVALID_TOKEN


def test_scope_mismatch_both_directions() -> None:
    cfg, _resp, body = fresh(scope="a")
    assert redeem(cfg, body, scope="b", now_ms=NOW + 1).reason == Reason.SCOPE_MISMATCH

    cfg2, _, body2 = fresh()  # no sk claim at all
    assert redeem(cfg2, body2, scope="a", now_ms=NOW + 1).reason == Reason.SCOPE_MISMATCH


def test_scope_matches_is_accepted() -> None:
    cfg, _, body = fresh(scope="a")
    result = redeem(cfg, body, scope="a", now_ms=NOW + 1)
    assert result.success and result.scope == "a"


def test_expired_with_now_ms_and_boundary() -> None:
    cfg, _, body = fresh(make_cfg(("sha256-pow",)))
    assert redeem(cfg, body, now_ms=NOW + TTL_MS + 1).reason == Reason.EXPIRED
    # exp < now is the rule, so exactly at exp the challenge is still valid.
    assert redeem(cfg, body, now_ms=NOW + TTL_MS).success


def test_invalid_solutions_length() -> None:
    cfg, _, body = fresh(make_cfg(("sha256-pow",)))
    assert redeem(cfg, {"token": body["token"], "solutions": []}, now_ms=NOW).reason == (
        Reason.INVALID_SOLUTIONS
    )
    extra = body["solutions"] + [{"nonce": 0}]
    assert redeem(cfg, {"token": body["token"], "solutions": extra}, now_ms=NOW).reason == (
        Reason.INVALID_SOLUTIONS
    )


@pytest.mark.parametrize("bad", [None, "x", 3, [1], []])
def test_non_dict_solution_is_invalid_solution(bad: object) -> None:
    cfg, _, body = fresh(make_cfg(("sha256-pow",)))
    result = redeem(cfg, {"token": body["token"], "solutions": [bad, bad]}, now_ms=NOW)
    assert result.reason == Reason.INVALID_SOLUTION
    assert result.instr_error is False


def test_wrong_nonce_is_invalid_solution_for_sha_and_hashwx() -> None:
    cfg, resp, body = fresh(make_cfg(("sha256-pow", "hashwx")))
    # challenges: [sha, sha, hashwx, hashwx]
    sha_bad = {"nonce": failing_sha_nonce(resp["challenges"][0]["payload"])}
    solutions = list(body["solutions"])
    solutions[0] = sha_bad
    result = redeem(cfg, {"token": resp["token"], "solutions": solutions}, now_ms=NOW)
    assert result.reason == Reason.INVALID_SOLUTION
    assert result.instr_error is False

    expected_hw = expected_entries(SECRET, resp["token"])[2]
    hw_bad_nonce = 0
    while hashwx_mod.verify(expected_hw, {"nonce": hw_bad_nonce}):
        hw_bad_nonce += 1
    solutions = list(body["solutions"])
    solutions[2] = {"nonce": hw_bad_nonce}
    result = redeem(cfg, {"token": resp["token"], "solutions": solutions}, now_ms=NOW)
    assert result.reason == Reason.INVALID_SOLUTION
    assert result.instr_error is False


# --------------------------------------------------------------------------- instrumentation reasons


def _instr_entry(cfg_block: bool = False) -> tuple[CapConfig, dict[str, Any], list[Any]]:
    cfg = make_cfg(
        ("instrumentation",),
        instrumentation=InstrumentationOptions(block_automated_browsers=cfg_block),
    )
    resp = create_challenge(cfg, now_ms=NOW)
    return cfg, resp, expected_entries(SECRET, resp["token"])


def test_instr_corrupted_when_expected_entry_has_no_meta() -> None:
    cfg = make_cfg(("instrumentation",))
    token = forge([{"protocol": "instrumentation"}])
    body = {"token": token, "solutions": [{"instr": {"i": "x", "state": {}}}]}
    result = redeem(cfg, body, now_ms=NOW)
    assert result.reason == Reason.INSTR_CORRUPTED
    assert result.instr_error is True


def test_instr_expired_when_meta_expiry_passed_but_token_is_not() -> None:
    cfg, _resp, entries = _instr_entry()
    entries[0]["instrMeta"]["expires"] = NOW - 1
    token = forge(entries)
    body = {"token": token, "solutions": [solve_instrumentation(entries[0])]}
    result = redeem(cfg, body, now_ms=NOW + 1)
    assert result.reason == Reason.INSTR_EXPIRED
    assert result.instr_error is True


def test_instr_timeout_inside_solution_and_legacy_flag() -> None:
    cfg, resp, entries = _instr_entry()
    result = redeem(cfg, {"token": resp["token"], "solutions": [{"timeout": True}]}, now_ms=NOW)
    assert result.reason == Reason.INSTR_TIMEOUT
    assert result.instr_error is True

    legacy = {
        "token": resp["token"],
        "solutions": [solve_instrumentation(entries[0])],
        "instr_timeout": True,
    }
    legacy_result = redeem(cfg, legacy, now_ms=NOW)
    assert legacy_result.reason == Reason.INSTR_TIMEOUT
    assert legacy_result.instr_error is True


def test_instr_missing_when_solution_has_no_instr() -> None:
    cfg, resp, _ = _instr_entry()
    result = redeem(cfg, {"token": resp["token"], "solutions": [{}]}, now_ms=NOW)
    assert result.reason == Reason.INSTR_MISSING
    assert result.instr_error is True


def test_instr_failed_when_blocked_and_blocking_is_off() -> None:
    cfg, resp, entries = _instr_entry(cfg_block=False)
    result = redeem(cfg, {"token": resp["token"], "solutions": [{"blocked": True}]}, now_ms=NOW)
    assert result.reason == Reason.INSTR_FAILED
    assert result.instr_error is True

    legacy = {
        "token": resp["token"],
        "solutions": [solve_instrumentation(entries[0])],
        "instr_blocked": True,
    }
    assert redeem(cfg, legacy, now_ms=NOW).reason == Reason.INSTR_FAILED


def test_instr_automated_browser_when_blocking_is_on() -> None:
    cfg, resp, entries = _instr_entry(cfg_block=True)
    result = redeem(cfg, {"token": resp["token"], "solutions": [{"blocked": True}]}, now_ms=NOW)
    assert result.reason == Reason.INSTR_AUTOMATED_BROWSER
    assert result.instr_error is True

    legacy = {
        "token": resp["token"],
        "solutions": [solve_instrumentation(entries[0])],
        "instr_blocked": True,
    }
    assert redeem(cfg, legacy, now_ms=NOW).reason == Reason.INSTR_AUTOMATED_BROWSER


def test_instr_probe_missing_when_blocking_is_on_and_no_probe_is_sent() -> None:
    cfg, resp, entries = _instr_entry(cfg_block=True)
    body = {"token": resp["token"], "solutions": [solve_instrumentation(entries[0])]}
    result = redeem(cfg, body, now_ms=NOW)
    assert result.reason == Reason.INSTR_PROBE_MISSING
    assert result.instr_error is True


def test_wrong_state_is_failed_challenge_with_instr_error() -> None:
    cfg, resp, entries = _instr_entry()
    meta = entries[0]["instrMeta"]
    state = dict(zip(meta["vars"], meta["expectedVals"]))
    first = meta["vars"][0]
    state[first] = state[first] + 1
    body = {"token": resp["token"], "solutions": [{"instr": {"i": meta["id"], "state": state}}]}
    result = redeem(cfg, body, now_ms=NOW)
    assert result.reason == Reason.FAILED_CHALLENGE
    assert result.instr_error is True


def test_risk_flags_propagate_from_instrumentation(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_verify(expected: Any, solution: Any, **kwargs: Any) -> InstrVerifyResult:
        return InstrVerifyResult(
            valid=True, reason=None, risk_flags=["native_tamper"], blocked_by=[]
        )

    monkeypatch.setattr(instr_pkg, "verify", fake_verify)
    cfg, _resp, body = fresh(make_cfg(("instrumentation",)))
    result = redeem(cfg, body, now_ms=NOW)
    assert result.success
    assert result.risk_flags == ["native_tamper"]


# --------------------------------------------------------------------------- stores


def test_nonce_store_error_is_a_reason_and_issues_no_token() -> None:
    cfg, _, body = fresh(make_cfg(("sha256-pow",)))
    result = redeem(cfg, body, nonce_store=RaisingNonceStore(), now_ms=NOW + 1)
    assert result.reason == Reason.NONCE_STORE_ERROR
    assert result.token is None
    assert result.to_widget_json() == {"success": False, "error": "nonce_store_error"}


def test_no_nonce_store_still_succeeds_and_warns_once(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(challenge, "_warned_no_nonce_store", False)
    caplog.set_level(logging.WARNING, logger="capwx")
    cfg = make_cfg(("sha256-pow",))
    _, _, first = fresh(cfg)
    _, _, second = fresh(cfg)
    assert redeem(cfg, first, now_ms=NOW + 1).success
    assert redeem(cfg, second, now_ms=NOW + 1).success
    warnings = [
        r
        for r in caplog.records
        if r.levelno == logging.WARNING and "nonce_store" in r.getMessage()
    ]
    assert len(warnings) == 1


def test_sync_redeem_rejects_async_store() -> None:
    cfg, _, body = fresh(make_cfg(("sha256-pow",)))
    with pytest.raises(CapwxError):
        redeem(cfg, body, nonce_store=AsyncStore(), now_ms=NOW + 1)
    with pytest.raises(CapwxError):
        redeem(cfg, body, token_store=AsyncStore(), now_ms=NOW + 1)


# --------------------------------------------------------------------------- create_challenge


def test_create_challenge_shape_is_exact() -> None:
    cfg = make_cfg(("sha256-pow", "hashwx"))
    resp = create_challenge(cfg, now_ms=NOW)
    assert set(resp) == {"token", "format", "challenges", "expires"}
    assert resp["format"] == 2
    assert resp["expires"] == NOW + TTL_MS
    assert [c["protocol"] for c in resp["challenges"]] == [
        "sha256-pow",
        "sha256-pow",
        "hashwx",
        "hashwx",
    ]
    assert all(set(c) == {"protocol", "payload"} for c in resp["challenges"])
    assert "salt" in resp["challenges"][0]["payload"]
    assert "c" in resp["challenges"][2]["payload"]


def test_token_payload_has_scope_extra_and_timestamps() -> None:
    cfg = make_cfg(("sha256-pow",))
    resp = create_challenge(cfg, scope="login", extra={"k": 1}, now_ms=NOW)
    payload = jwt_verify(resp["token"], SECRET)
    assert payload is not None
    assert payload["f"] == 2
    assert payload["sk"] == "login"
    assert payload["x"] == {"k": 1}
    assert payload["iat"] == NOW
    assert payload["exp"] == NOW + TTL_MS
    assert "ev" in payload


def test_extra_must_be_dict_and_scope_is_optional() -> None:
    cfg = make_cfg(("sha256-pow",))
    resp = create_challenge(cfg, extra="nope", now_ms=NOW)  # type: ignore[arg-type]
    payload = jwt_verify(resp["token"], SECRET)
    assert payload is not None
    assert "x" not in payload and "sk" not in payload


def test_scope_with_colon_is_a_programmer_error() -> None:
    with pytest.raises(CapwxError):
        create_challenge(make_cfg(("sha256-pow",)), scope="a:b", now_ms=NOW)


def test_overrides_are_applied_without_mutating_config() -> None:
    cfg = make_cfg(("hashwx",))
    resp = create_challenge(cfg, overrides={"hashwx_challenge_count": 3}, now_ms=NOW)
    assert len(resp["challenges"]) == 3
    assert cfg.hashwx_challenge_count == 2

    only_sha = create_challenge(make_cfg(ALL), overrides={"protocols": ("sha256-pow",)}, now_ms=NOW)
    assert [c["protocol"] for c in only_sha["challenges"]] == ["sha256-pow", "sha256-pow"]


@pytest.mark.parametrize("overrides", [{"hashwx_difficulty": 0}, {"no_such_field": 1}])
def test_invalid_overrides_raise_capwx_error(overrides: dict[str, Any]) -> None:
    with pytest.raises(CapwxError):
        create_challenge(make_cfg(("sha256-pow",)), overrides=overrides, now_ms=NOW)


def test_instrumentation_disabled_flag_skips_minting() -> None:
    cfg = make_cfg(
        ("instrumentation", "sha256-pow"),
        instrumentation=InstrumentationOptions(enabled=False),
    )
    resp = create_challenge(cfg, now_ms=NOW)
    assert [c["protocol"] for c in resp["challenges"]] == ["sha256-pow", "sha256-pow"]
    assert redeem(cfg, body_for(SECRET, resp), now_ms=NOW + 1).success


def test_only_disabled_instrumentation_is_a_config_error() -> None:
    cfg = make_cfg(("instrumentation",), instrumentation=InstrumentationOptions(enabled=False))
    with pytest.raises(CapwxError):
        create_challenge(cfg, now_ms=NOW)


def test_unknown_protocol_fails_at_mint_time(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_module, "KNOWN_PROTOCOLS", (*config_module.KNOWN_PROTOCOLS, "bogus"))
    cfg = CapConfig(secret=SECRET, protocols=("bogus",))
    with pytest.raises(CapwxError):
        create_challenge(cfg, now_ms=NOW)


# --------------------------------------------------------------------------- widget JSON


def test_to_widget_json_shapes() -> None:
    ok = RedeemResult(success=True, token="t", expires=5)
    assert ok.to_widget_json() == {"success": True, "token": "t", "expires": 5}
    bad = RedeemResult(success=False, reason=Reason.INVALID_BODY)
    assert bad.to_widget_json() == {"success": False, "error": "invalid_body"}


# --------------------------------------------------------------------------- async twins


def test_async_twins_with_async_store() -> None:
    async def scenario() -> tuple[RedeemResult, RedeemResult, bool, bool, dict[str, Any]]:
        cfg = make_cfg(ALL)
        store = AsyncStore()
        resp = await acreate_challenge(cfg, scope="login", now_ms=NOW)
        body = body_for(SECRET, resp)
        first = await aredeem(
            cfg, body, scope="login", nonce_store=store, token_store=store, now_ms=NOW + 1
        )
        second = await aredeem(
            cfg, body, scope="login", nonce_store=store, token_store=store, now_ms=NOW + 1
        )
        assert first.token is not None
        valid = await avalidate_token(cfg, first.token, scope="login", token_store=store)
        again = await avalidate_token(cfg, first.token, scope="login", token_store=store)
        return first, second, valid, again, resp

    first, second, valid, again, _ = asyncio.run(scenario())
    assert first.success
    assert second.reason == Reason.ALREADY_REDEEMED
    assert valid is True and again is False


def test_async_redeem_also_accepts_sync_store() -> None:
    async def scenario() -> RedeemResult:
        cfg, _, body = fresh(make_cfg(("sha256-pow",)))
        return await aredeem(
            cfg, body, nonce_store=MemoryStore(), token_store=MemoryStore(), now_ms=NOW + 1
        )

    assert asyncio.run(scenario()).success


# --------------------------------------------------------------------------- events and logs


@pytest.fixture
def events():
    seen: list[tuple[str, dict[str, str]]] = []
    set_event_callback(lambda name, **labels: seen.append((name, labels)))
    yield seen
    set_event_callback(None)


def test_event_callback_receives_low_cardinality_labels(events: list[Any]) -> None:
    cfg, _, body = fresh(make_cfg(("sha256-pow",)))
    assert redeem(cfg, body, nonce_store=MemoryStore(), now_ms=NOW + 1).success
    assert ("challenge_created", {"site": "default", "protocol": "sha256-pow"}) in events
    assert ("redeem", {"site": "default", "reason": "success"}) in events


def test_event_callback_errors_never_break_redeem(events: list[Any]) -> None:
    def boom(name: str, **labels: str) -> None:
        raise RuntimeError("metrics down")

    set_event_callback(boom)
    cfg, _, body = fresh(make_cfg(("sha256-pow",)))
    assert redeem(cfg, body, nonce_store=MemoryStore(), now_ms=NOW + 1).success


def test_one_info_line_per_redeem_without_tokens_or_solutions(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="capwx")
    cfg, resp, body = fresh(make_cfg(("sha256-pow",)))
    store = MemoryStore()
    redeem(cfg, body, nonce_store=store, now_ms=NOW + 1)
    redeem(cfg, {"token": "garbage", "solutions": []}, nonce_store=store, now_ms=NOW + 1)

    infos = [r for r in caplog.records if r.name == "capwx" and r.levelno == logging.INFO]
    assert len(infos) == 2
    assert "success=True" in infos[0].getMessage()
    assert "reason=invalid_token" in infos[1].getMessage()
    assert all("duration_ms=" in r.getMessage() for r in infos)
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert resp["token"] not in text
    assert body["token"] not in text
    assert "nonce" not in text


# --------------------------------------------------------------------------- import isolation


def _run_python(code: str) -> str:
    done = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, timeout=120
    )
    return done.stdout.strip()


def test_import_capwx_does_not_load_wasmtime() -> None:
    out = _run_python(
        "import sys, capwx; print('wasmtime' in sys.modules, 'capwx.protocols.hashwx' in sys.modules)"
    )
    assert out == "False False"


def test_sha256_only_flow_never_loads_wasmtime() -> None:
    out = _run_python(
        """
import hashlib, sys
from capwx import CapConfig, MemoryStore, create_challenge, redeem
cfg = CapConfig(secret='test-secret-0123456789abcdef', protocols=('sha256-pow',),
                sha256_difficulty=1, sha256_count=2)
resp = create_challenge(cfg)
sols = []
for c in resp['challenges']:
    n = 0
    while not hashlib.sha256((c['payload']['salt'] + str(n)).encode()).hexdigest().startswith(c['payload']['target']):
        n += 1
    sols.append({'nonce': n})
store = MemoryStore()
r = redeem(cfg, {'token': resp['token'], 'solutions': sols}, nonce_store=store, token_store=store)
print(r.success, 'wasmtime' in sys.modules, 'capwx.protocols.hashwx' in sys.modules)
"""
    )
    assert out == "True False False"


def test_package_exports() -> None:
    for name in capwx.__all__:
        assert hasattr(capwx, name), name
    assert capwx.__version__ == "0.1.0"
