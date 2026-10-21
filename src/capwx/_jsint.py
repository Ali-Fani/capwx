"""JavaScript integer semantics. Every function here mirrors a JS operator.

Pitfall list:
- Python ``%`` on negatives differs from JS -> always ``js_rem``.
- Python ``bool`` is an ``int`` -> every "is this a number" check must exclude ``bool``.
- ``charCodeAt`` is UTF-16 code units, not code points -> ``utf16_units``.
"""

import math


def to_int32(n: int) -> int:  # JS: n | 0   (for integer n)
    n &= 0xFFFFFFFF
    return n - (1 << 32) if n & 0x80000000 else n


def to_uint32(n: int) -> int:  # JS: n >>> 0
    return n & 0xFFFFFFFF


def js_shl(a: int, k: int) -> int:  # JS: a << k
    return to_int32(to_int32(a) << (k & 31))


def js_sar(a: int, k: int) -> int:  # JS: a >> k  (arithmetic)
    return to_int32(a) >> (k & 31)


def js_shr(a: int, k: int) -> int:  # JS: a >>> k (logical)
    return to_uint32(a) >> (k & 31)


def js_xor(a: int, b: int) -> int:  # JS: a ^ b
    return to_int32(to_int32(a) ^ to_int32(b))


def js_and(a: int, b: int) -> int:
    return to_int32(to_int32(a) & to_int32(b))


def js_or(a: int, b: int) -> int:
    return to_int32(to_int32(a) | to_int32(b))


def js_not(a: int) -> int:  # JS: ~a
    return to_int32(~to_int32(a))


def js_rem(a: int, b: int) -> int:  # JS: a % b  (sign follows dividend!)
    return int(math.fmod(a, b))


def utf16_units(s: str) -> list[int]:  # JS: s.charCodeAt(i) for each i
    b = s.encode("utf-16-le")
    return [int.from_bytes(b[i : i + 2], "little") for i in range(0, len(b), 2)]


def js_number_str(n: int) -> str:  # JS: String(n) for safe integers
    return str(n)


def is_js_number(x: object) -> bool:  # JS: typeof x === "number" && isFinite(x)
    if not isinstance(x, (int, float)) or isinstance(x, bool):
        return False
    try:
        return math.isfinite(x)
    except OverflowError:  # int beyond double range acts as Infinity in JS
        return False
