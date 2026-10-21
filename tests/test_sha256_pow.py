"""Tests for capwx.protocols.sha256_pow (M4)."""

import hashlib

import pytest

from capwx.config import CapConfig
from capwx.protocols import sha256_pow

VECTORS = [
    ("0", "salt", 13),
    ("00", "salt", 194),
    ("000a", "salt", 13834),
    ("f", "salt", 38),
]

SECRET = "x" * 16


def _expected(target: str, salt: str) -> dict:
    return {"protocol": "sha256-pow", "salt": salt, "target": target}


@pytest.mark.parametrize(("target", "salt", "nonce"), VECTORS)
def test_vector_smallest_nonce_valid_as_int(target, salt, nonce):
    assert sha256_pow.verify(_expected(target, salt), {"nonce": nonce}) is True


@pytest.mark.parametrize(("target", "salt", "nonce"), VECTORS)
def test_vector_smallest_nonce_valid_as_str(target, salt, nonce):
    assert sha256_pow.verify(_expected(target, salt), {"nonce": str(nonce)}) is True


@pytest.mark.parametrize(("target", "salt", "nonce"), VECTORS)
def test_vector_every_smaller_nonce_invalid(target, salt, nonce):
    exp = _expected(target, salt)
    for smaller in range(nonce):
        assert sha256_pow.verify(exp, {"nonce": smaller}) is False, smaller
        assert sha256_pow.verify(exp, {"nonce": str(smaller)}) is False, smaller


@pytest.mark.parametrize("bad", [True, False, 1.0, 13.0, -1, None, "-1", "1e3", "", "1 ", "13\n"])
def test_bad_nonce_rejected(bad):
    assert sha256_pow.verify(_expected("0", "salt"), {"nonce": bad}) is False


def test_unicode_digits_rejected():
    # Arabic-Indic digit one: not ASCII, must not match [0-9].
    assert sha256_pow.verify(_expected("0", "salt"), {"nonce": "١٣"}) is False


def test_int_above_safe_range_rejected():
    assert sha256_pow.verify(_expected("0", "salt"), {"nonce": 2**53}) is False


def test_str_longer_than_16_digits_rejected():
    assert sha256_pow.verify(_expected("0", "salt"), {"nonce": "1" * 17}) is False


def test_leading_zero_string_accepted_and_hashed_as_written():
    # sha256("salt" + "0123") starts with "8"; sha256("salt" + "123") does not.
    exp = _expected("8", "salt")
    assert sha256_pow.verify(exp, {"nonce": "0123"}) is True
    assert sha256_pow.verify(exp, {"nonce": 123}) is False


@pytest.mark.parametrize("solution", [None, "13", 13, [13], {"nonce_": 13}, {}])
def test_bad_solution_shape_rejected(solution):
    assert sha256_pow.verify(_expected("0", "salt"), solution) is False


@pytest.mark.parametrize(
    "expected",
    [
        None,
        "salt",
        [],
        {},
        {"salt": "salt"},
        {"target": "0"},
        {"salt": None, "target": "0"},
        {"salt": "salt", "target": None},
        {"salt": 1, "target": "0"},
    ],
)
def test_bad_expected_rejected_without_raising(expected):
    assert sha256_pow.verify(expected, {"nonce": 13}) is False


def test_mint_shape_and_contents():
    config = CapConfig(
        secret=SECRET,
        sha256_count=7,
        sha256_size=8,
        sha256_difficulty=3,
    )
    pairs = sha256_pow.mint(config)
    assert len(pairs) == 7
    for payload, expected in pairs:
        assert set(payload) == {"salt", "target"}
        assert len(payload["salt"]) == 2 * 8
        int(payload["salt"], 16)  # hex
        assert payload["target"] == "0" * 3
        assert expected == {
            "protocol": "sha256-pow",
            "salt": payload["salt"],
            "target": "0" * 3,
        }
    assert len({p["salt"] for p, _ in pairs}) == 7


def test_mint_then_solve_round_trip():
    config = CapConfig(secret=SECRET, sha256_count=2, sha256_size=16, sha256_difficulty=2)
    for payload, expected in sha256_pow.mint(config):
        nonce = 0
        while (
            not hashlib.sha256((payload["salt"] + str(nonce)).encode())
            .hexdigest()
            .startswith(payload["target"])
        ):
            nonce += 1
        assert sha256_pow.verify(expected, {"nonce": nonce}) is True


def test_default_salt_keeps_browser_wasm_solver_working():
    # The widget's wasm sha256 solver only matches messages shorter than 56 bytes. A longer salt
    # plus the decimal nonce makes it spin forever (found by the browser e2e tests, §13.3).
    config = CapConfig(secret=SECRET)
    (payload, _expected) = sha256_pow.mint(config)[0]
    assert len(payload["salt"]) + 9 < 56
