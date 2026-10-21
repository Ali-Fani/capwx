"""Tests for capwx._jsint: every helper against hand-checked JavaScript results."""

import math

import pytest

from capwx._jsint import (
    is_js_number,
    js_and,
    js_not,
    js_number_str,
    js_or,
    js_rem,
    js_sar,
    js_shl,
    js_shr,
    js_xor,
    to_int32,
    to_uint32,
    utf16_units,
)

I32_MIN = -(2**31)
I32_MAX = 2**31 - 1


@pytest.mark.parametrize(
    ("n", "expected"),
    [
        (0, 0),
        (1, 1),
        (-1, -1),
        (I32_MAX, I32_MAX),
        (I32_MIN, I32_MIN),
        (2**31, I32_MIN),  # JS: 2147483648 | 0 === -2147483648
        (2**32, 0),
        (2**32 + 5, 5),
        (-(2**31) - 1, I32_MAX),
        (2**53 - 1, -1),  # low 32 bits all set
        (-(2**53), 0),
    ],
)
def test_to_int32(n, expected):
    assert to_int32(n) == expected


@pytest.mark.parametrize(
    ("n", "expected"),
    [
        (0, 0),
        (-1, 0xFFFFFFFF),
        (2**32, 0),
        (2**32 + 5, 5),
        (-(2**31), 2**31),
        (I32_MAX, I32_MAX),
    ],
)
def test_to_uint32(n, expected):
    assert to_uint32(n) == expected


@pytest.mark.parametrize(
    ("a", "k", "expected"),
    [
        (1, 0, 1),
        (1, 31, I32_MIN),  # JS: 1 << 31 === -2147483648
        (1, 32, 1),  # shift count is masked to 5 bits
        (1, 33, 2),
        (3, 30, -(2**30)),
        (-1, 1, -2),
        (0x40000000, 1, I32_MIN),
        (5, 33, 10),
        (2**32 + 1, 0, 1),  # operand is wrapped to int32 first
        (2**31, 1, 0),  # 2**31 wraps to -2**31, shifted left 1 -> 0 in 32 bits
    ],
)
def test_js_shl(a, k, expected):
    assert js_shl(a, k) == expected


@pytest.mark.parametrize(
    ("a", "k", "expected"),
    [
        (-8, 1, -4),
        (-7, 1, -4),  # arithmetic shift floors toward -inf
        (-1, 5, -1),
        (-1, 32, -1),  # count masked to 0
        (I32_MIN, 31, -1),
        (I32_MAX, 31, 0),
        (2**31, 1, -(2**30)),  # 2**31 is -2**31 as int32
        (2**32 + 8, 2, 2),
        (12, 2, 3),
    ],
)
def test_js_sar(a, k, expected):
    assert js_sar(a, k) == expected


@pytest.mark.parametrize(
    ("a", "k", "expected"),
    [
        (-1, 0, 0xFFFFFFFF),  # JS: -1 >>> 0 === 4294967295
        (-1, 1, I32_MAX),
        (-1, 31, 1),
        (-1, 32, 0xFFFFFFFF),  # count masked to 0
        (-8, 1, 2147483644),  # (2**32 - 8) >> 1
        (-2, 28, 15),
        (2**32 + 5, 0, 5),
        (I32_MIN, 31, 1),
        (16, 2, 4),
    ],
)
def test_js_shr(a, k, expected):
    assert js_shr(a, k) == expected


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        (0, 0, 0),
        (-1, -1, 0),
        (-1, 0, -1),
        (2**31, 0, I32_MIN),
        (0xFFFFFFFF, 0, -1),
        (2**32 + 1, 1, 0),  # 2**32+1 wraps to 1
        (2**33 + 3, 2**32 + 5, 6),  # 3 ^ 5
        (0b1010, 0b0110, 0b1100),
    ],
)
def test_js_xor(a, b, expected):
    assert js_xor(a, b) == expected


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        (2**32 + 3, 7, 3),
        (-1, 0xFF, 0xFF),
        (2**31, -1, I32_MIN),
        (2**40 + 0xF0, 0xFF, 0xF0),
        (-1, -1, -1),
        (0, -1, 0),
    ],
)
def test_js_and(a, b, expected):
    assert js_and(a, b) == expected


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        (2**32 + 1, 2, 3),
        (2**31, 0, I32_MIN),
        (2**33, 1, 1),
        (-2, 1, -1),
        (0, 0, 0),
        (0x0F, 0xF0, 0xFF),
        (2**32 + 0x10, 2**33 + 0x01, 0x11),
    ],
)
def test_js_or(a, b, expected):
    assert js_or(a, b) == expected


@pytest.mark.parametrize(
    ("a", "expected"),
    [
        (0, -1),
        (-1, 0),
        (I32_MAX, I32_MIN),
        (I32_MIN, I32_MAX),
        (2**32, -1),  # ~0 after wrap
        (5, -6),
        (-6, 5),
    ],
)
def test_js_not(a, expected):
    assert js_not(a) == expected


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        (-7, 3, -1),  # JS: -7 % 3 === -1 (sign follows dividend)
        (7, -3, 1),
        (-7, -3, -1),
        (7, 3, 1),
        (-6, 3, 0),
        (5, 2, 1),
        (-1, 256, -1),
        (0, 5, 0),
        (-0, 5, 0),
    ],
)
def test_js_rem(a, b, expected):
    assert js_rem(a, b) == expected
    assert isinstance(js_rem(a, b), int)


def test_js_rem_differs_from_python_modulo_on_negatives():
    assert js_rem(-7, 3) == -1
    assert -7 % 3 == 2  # the trap this helper exists for


@pytest.mark.parametrize(
    ("s", "expected"),
    [
        ("", []),
        ("A", [65]),
        ("abc", [97, 98, 99]),
        ("é", [0xE9]),
        ("￿", [0xFFFF]),
        ("\U0001f600", [0xD83D, 0xDE00]),  # 😀 is two UTF-16 code units
        ("a\U0001f600b", [97, 0xD83D, 0xDE00, 98]),
    ],
)
def test_utf16_units(s, expected):
    assert utf16_units(s) == expected


@pytest.mark.parametrize(
    ("n", "expected"),
    [
        (0, "0"),
        (-5, "-5"),
        (2**53 - 1, "9007199254740991"),
    ],
)
def test_js_number_str(n, expected):
    assert js_number_str(n) == expected


@pytest.mark.parametrize("x", [0, -1, 1, 2**53, 1.5, -0.0, 1e300])
def test_is_js_number_accepts_finite_numbers(x):
    assert is_js_number(x) is True


@pytest.mark.parametrize(
    "x",
    [
        True,
        False,
        math.nan,
        math.inf,
        -math.inf,
        "1",
        None,
        [1],
        {"a": 1},
    ],
)
def test_is_js_number_rejects_non_numbers(x):
    assert is_js_number(x) is False


def test_int32_helpers_agree_with_modular_definition():
    # Cross-check the bit tricks against the arithmetic definition over a range.
    for n in range(-(2**20), 2**20, 4099):
        for m in (n, n * 4096 + 17, n + 2**32):
            assert to_int32(m) == ((m + 2**31) % 2**32) - 2**31
            assert js_shr(m, 0) == to_uint32(m)
