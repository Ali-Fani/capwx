"""Tests for capwx.protocols.hashwx (M5)."""

from __future__ import annotations

import hashlib
import shutil
import threading
from importlib import resources

import pytest

from capwx.config import CapConfig
from capwx.errors import CapwxError
from capwx.protocols import hashwx
from capwx.protocols.hashwx import (
    U64_MAX,
    HashwxEngine,
    get_engine,
    hashwx_ready,
    mint,
    verify,
)

SECRET = "test-secret-0123456789abcdef"


def _seed(text: bytes) -> bytes:
    return text.ljust(32, b"\0")


def _solve(engine: HashwxEngine, c: str, d: int, n: int, limit: int = 100_000) -> int:
    """Test-only: first nonce (from 0) whose hash is within ``U64_MAX // d``."""
    c_bytes = bytes.fromhex(c)
    target = U64_MAX // d
    for nonce in range(limit):
        seed = hashlib.sha256(c_bytes + (nonce // n).to_bytes(8, "little")).digest()
        if engine.hash(seed, nonce) <= target:
            return nonce
    raise AssertionError("no solution found")


def _flip_byte(data: bytes, index: int) -> bytes:
    buf = bytearray(data)
    buf[index] ^= 0xFF
    return bytes(buf)


# --- tevador's official vectors -------------------------------------------------------------

VECTORS = [
    (b"This is a test seed for hashwx", 0, 0x973684176F8EE362),
    (b"This is a test seed for hashwx", 123456, 0x401983BB07D69B07),
    (b"Lorem ipsum dolor sit amet", 123456, 0x4AF38D834A9A8D3D),
    (b"Lorem ipsum dolor sit amet", 987654321123456789, 0x6A8A5514432E17A3),
]


@pytest.mark.parametrize(("text", "nonce", "expected"), VECTORS)
def test_official_vectors(text: bytes, nonce: int, expected: int) -> None:
    assert get_engine().hash(_seed(text), nonce) == expected


def test_vectors_match_custom_copy_of_vendored_wasm(tmp_path) -> None:
    src = resources.files("capwx._vendor.hashwx").joinpath("hashwx.wasm")
    copy = tmp_path / "hashwx-copy.wasm"
    shutil.copyfile(str(src), copy)
    engine = get_engine(str(copy))
    assert engine is not get_engine()
    assert get_engine(str(copy)) is engine  # cached per path
    for text, nonce, expected in VECTORS:
        assert engine.hash(_seed(text), nonce) == expected


# --- verify: solving and neighbours ---------------------------------------------------------


def test_solve_then_verify_and_neighbour_rejected() -> None:
    engine = get_engine()
    n, d = 1024, 50
    c = "ab" * 32
    expected = {"c": c, "d": d, "n": n}
    nonce = _solve(engine, c, d, n)
    assert verify(expected, {"nonce": nonce}) is True

    # Find a later nonce that fails the target, recomputed independently of verify().
    target = U64_MAX // d
    c_bytes = bytes.fromhex(c)
    neighbour = nonce + 1
    while True:
        seed = hashlib.sha256(c_bytes + (neighbour // n).to_bytes(8, "little")).digest()
        if engine.hash(seed, neighbour) > target:
            break
        neighbour += 1
    assert verify(expected, {"nonce": neighbour}) is False


def test_large_nonce_as_string_does_not_crash() -> None:
    c = "5e" * 32
    d = 2**40
    engine = get_engine()
    target = U64_MAX // d
    c_bytes = bytes.fromhex(c)
    for nonce in (2**63 + 12345, U64_MAX):
        seed = hashlib.sha256(c_bytes + nonce.to_bytes(8, "little")).digest()
        want = engine.hash(seed, nonce) <= target
        assert verify({"c": c, "d": d, "n": 1}, {"nonce": str(nonce)}) is want
    assert verify({"c": c, "d": d, "n": 1}, {"nonce": str(2**64)}) is False  # above U64_MAX


def test_missing_nonce_and_non_dict_solution() -> None:
    expected = {"c": "00" * 32, "d": 1, "n": 1}
    assert verify(expected, {}) is False
    assert verify(expected, None) is False
    assert verify(expected, "0") is False
    assert verify(None, {"nonce": 0}) is False


# --- verify: concurrency --------------------------------------------------------------------


def test_concurrent_verify_from_eight_threads() -> None:
    engine = get_engine()
    n, d = 1024, 50
    c = "cd" * 32
    expected = {"c": c, "d": d, "n": n}
    good = _solve(engine, c, d, n)
    cases = [{"nonce": good}, {"nonce": good + 1}, {"nonce": "0"}, {"nonce": 2**63 + 7}]
    reference = [verify(expected, s) for s in cases]

    errors: list[BaseException] = []
    mismatches: list[int] = []
    barrier = threading.Barrier(8)

    def worker() -> None:
        try:
            barrier.wait()
            for _ in range(200):
                for i, solution in enumerate(cases):
                    if verify(expected, solution) != reference[i]:
                        mismatches.append(i)
        except BaseException as exc:  # noqa: BLE001 - collected for the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert mismatches == []
    assert reference[0] is True


# --- verify: bad input -> False -------------------------------------------------------------


@pytest.mark.parametrize(
    "expected",
    [
        {"c": "ab" * 31 + "a", "d": 50, "n": 1024},  # 63 hex chars
        {"c": "zz" * 32, "d": 50, "n": 1024},  # not hex
        {"c": "ab" * 32, "d": 50, "n": 0},  # n below range
        {"c": "ab" * 32, "d": 50, "n": 1_048_577},  # n above range
        {"c": "ab" * 32, "d": 50, "n": True},  # bool n
        {"c": "ab" * 32, "d": 0, "n": 1024},  # d below range
        {"c": "ab" * 32, "d": True, "n": 1024},  # bool d
        {"c": "ab" * 32, "d": 50.0, "n": 1024},  # float d
    ],
)
def test_bad_expected_is_false(expected: dict) -> None:
    assert verify(expected, {"nonce": 0}) is False


@pytest.mark.parametrize(
    "nonce",
    [True, False, "-1", "0" * 21, "1" * 21, "12a", "1\n", -1, 2**53, 1.0, None],
)
def test_bad_nonce_is_false(nonce: object) -> None:
    expected = {"c": "ab" * 32, "d": 1, "n": 1}
    assert verify(expected, {"nonce": nonce}) is False


def test_engine_failure_returns_false_not_raise() -> None:
    class Broken:
        def hash(self, seed: bytes, nonce: int) -> int:
            raise RuntimeError("boom")

    assert verify({"c": "ab" * 32, "d": 1, "n": 1}, {"nonce": 0}, engine=Broken()) is False  # type: ignore[arg-type]


# --- mint -----------------------------------------------------------------------------------


def test_mint_rounding_uses_js_half_up() -> None:
    cfg = CapConfig(secret=SECRET, hashwx_difficulty=10, hashwx_challenge_count=4)
    out = mint(cfg)
    assert len(out) == 4
    assert all(expected["d"] == 3 for _, expected in out)  # floor(2.5 + 0.5)


def test_mint_rounding_not_bankers() -> None:
    # Python round(2.5) == 2; JS Math.round(2.5) == 3.
    cfg = CapConfig(secret=SECRET, hashwx_difficulty=5, hashwx_challenge_count=2)
    assert all(expected["d"] == 3 for _, expected in mint(cfg))


def test_mint_floor_is_at_least_one() -> None:
    cfg = CapConfig(secret=SECRET, hashwx_difficulty=1, hashwx_challenge_count=64)
    assert all(expected["d"] == 1 for _, expected in mint(cfg))


def test_mint_shapes() -> None:
    cfg = CapConfig(
        secret=SECRET,
        hashwx_difficulty=1_000_000,
        hashwx_challenge_count=3,
        hashwx_nonces_per_hash=4096,
    )
    out = mint(cfg)
    assert len(out) == 3
    cs = set()
    for payload, expected in out:
        assert set(payload) == {"c", "d", "n"}
        assert expected == {"protocol": "hashwx", **payload}
        assert len(payload["c"]) == 64
        int(payload["c"], 16)
        assert payload["d"] == 333_333  # floor(333333.33 + 0.5)
        assert payload["n"] == 4096
        cs.add(payload["c"])
    assert len(cs) == 3  # challenges are random, not repeated


def test_minted_challenge_is_solvable_and_verifies() -> None:
    cfg = CapConfig(
        secret=SECRET,
        hashwx_difficulty=50,
        hashwx_challenge_count=1,
        hashwx_nonces_per_hash=1024,
    )
    [(payload, expected)] = mint(cfg)
    nonce = _solve(get_engine(), payload["c"], payload["d"], payload["n"])
    assert verify(expected, {"nonce": nonce}) is True


# --- wasm integrity and paths ---------------------------------------------------------------


def test_vendored_wasm_tamper_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    original = hashwx._read_vendored_wasm()
    monkeypatch.setattr(hashwx, "_read_vendored_wasm", lambda: _flip_byte(original, 100))
    with pytest.raises(CapwxError):
        HashwxEngine()


def test_vendored_wasm_untampered_loads(monkeypatch: pytest.MonkeyPatch) -> None:
    original = hashwx._read_vendored_wasm()
    monkeypatch.setattr(hashwx, "_read_vendored_wasm", lambda: original)
    HashwxEngine()  # no error


def test_hashwx_ready_returns_none() -> None:
    assert hashwx_ready() is None


def test_missing_custom_wasm_path_raises(tmp_path) -> None:
    with pytest.raises(CapwxError):
        get_engine(str(tmp_path / "nope.wasm"))
