"""capwx.protocols.instrumentation.detect: port of upstream ``core/src/detect.js`` (M7).

Upstream is the spec. Function and constant names are snake_case versions of the
upstream names; logic is line-for-line. Differences that exist only because Python
has no ``undefined``, no UTF-16 strings and no JS number formatting are handled
explicitly:

- JS ``undefined`` (a missing key) is the sentinel ``UNDEF``. JSON ``null`` is
  Python ``None``. The two are different, as in JS (``S.webdriver === undefined``).
- ``bool`` is never a number (``_is_num``), as with ``typeof x === "number"``.
- Numbers are converted to IEEE doubles (``_to_f``) before any comparison, Set
  membership or string conversion, so ints beyond 2**53 or beyond the double range
  behave as they do in JavaScript (the latter as ``Infinity``).
- ``String(x)`` / template literals use the ECMAScript Number-to-string rules
  (``_js_num_str``) and the ``Array.prototype.join`` rules (``_js_str``).
- Regexes are ``re.ASCII | re.IGNORECASE``: JS non-unicode ``/i`` only folds ASCII.
- ``slice`` on strings counts UTF-16 code units (``_utf16_prefix``).
- Object key order follows ``Object.keys``: array-index keys first, ascending.

Output keys are snake_case (``blocked_by``, ``risk_flags``); upstream returns
``blockedBy`` / ``riskFlags``. Nothing else is renamed.
"""

from __future__ import annotations

import math
import re
from decimal import Decimal
from typing import Any, Final

from capwx._jsint import is_js_number
from capwx._types import as_json_dict, as_json_list

MAX_FONT_WIDTHS: Final = 64
MAX_TAMPER_KEYS: Final = 8
MAX_TAMPER_KEY_LENGTH: Final = 32
MAX_DETAIL_FIELDS: Final = 6
OUTER_HEIGHT_SLACK: Final = 16

MOBILE_UA: Final = re.compile(
    r"Android|iPhone|iPad|iPod|IEMobile|BlackBerry|Mobile Safari|; Mobile|Silk|Kindle|Tizen|Opera Mini",
    re.IGNORECASE | re.ASCII,
)
_HEADLESS_RE: Final = re.compile(r"headlesschrome", re.IGNORECASE | re.ASCII)

PROBE_FIELD_TYPES: Final[dict[str, str]] = {
    "ua": "string",
    "productSub": "string",
    "oscpu": "string",
    "uaDataPresent": "boolean",
    "uaData": "nullableObject",
    "plugins": "object",
    "engine": "object",
    "screen": "object",
    "outerWH": "array",
    "isExtended": "nullableBoolean",
    "fontWidths": "array",
    "tamper": "nullableObject",
}


class _Undefined:
    """JavaScript ``undefined``: the value of a missing property."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "undefined"


UNDEF: Final = _Undefined()


# --- JavaScript value semantics -------------------------------------------------


def _to_f(x: Any) -> float:
    """Number value as an IEEE double (ints outside the double range become +/-Infinity)."""
    if isinstance(x, int):
        try:
            return float(x)
        except OverflowError:
            return math.inf if x > 0 else -math.inf
    return float(x)


def _is_num(x: Any) -> bool:  # JS: typeof x === "number" && Number.isFinite(x)
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        return False
    return is_js_number(_to_f(x))


def _prop(obj: object, key: str) -> Any:  # JS: obj?.key (UNDEF for non-objects)
    mapping = as_json_dict(obj)
    return mapping.get(key, UNDEF) if mapping is not None else UNDEF


def _idx(arr: list[Any], i: int) -> Any:  # JS: arr[i]
    return arr[i] if i < len(arr) else UNDEF


def _js_num_str(x: Any) -> str:  # JS: String(number), ECMAScript Number::toString
    f = _to_f(x)
    if math.isnan(f):
        return "NaN"
    if math.isinf(f):
        return "Infinity" if f > 0 else "-Infinity"
    if f == 0:
        return "0"
    sign = "-" if f < 0 else ""
    _, digit_tuple, exp_raw = Decimal(repr(abs(f))).as_tuple()
    digits = list(digit_tuple)
    exp = int(exp_raw)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exp += 1
    ds = "".join(str(d) for d in digits)
    k = len(ds)
    n = exp + k
    if k <= n <= 21:
        body = ds + "0" * (n - k)
    elif 0 < n <= 21:
        body = ds[:n] + "." + ds[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + ds
    else:
        e = n - 1
        body = (
            ds[0] + ("." + ds[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
        )
    return sign + body


def _js_truthy(v: Any) -> bool:  # JS: !!v
    if v is UNDEF or v is None or v is False:
        return False
    if v is True:
        return True
    if isinstance(v, str):
        return v != ""
    if isinstance(v, (int, float)):
        f = _to_f(v)
        return f != 0 and not math.isnan(f)
    return True


def _js_str(v: Any) -> str:  # JS: String(v) for JSON-shaped values
    if v is UNDEF:
        return "undefined"
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return v
    if isinstance(v, (int, float)):
        return _js_num_str(v)
    items = as_json_list(v)
    if items is not None:
        return _js_join(items, ",")
    return "[object Object]"


def _js_join(arr: list[Any], sep: str) -> str:  # JS: arr.join(sep)
    return sep.join("" if e is None or e is UNDEF else _js_str(e) for e in arr)


def _utf16_prefix(s: str, n: int) -> str:  # JS: s.slice(0, n) (counts UTF-16 units)
    return s.encode("utf-16-le", "surrogatepass")[: 2 * n].decode("utf-16-le", "surrogatepass")


def _is_array_index(k: str) -> bool:
    return (
        k.isascii() and k.isdigit() and (k == "0" or not k.startswith("0")) and int(k) < 2**32 - 1
    )


def _own_keys(d: dict[str, Any]) -> list[str]:  # JS: Object.keys(d)
    index_keys = sorted((k for k in d if _is_array_index(k)), key=int)
    return index_keys + [k for k in d if not _is_array_index(k)]


def _type_ok(value: Any, kind: str) -> bool:
    if kind == "string":
        return isinstance(value, str)
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "object":
        return isinstance(value, dict)
    if kind == "array":
        return isinstance(value, list)
    if kind == "nullableObject":
        return value is None or isinstance(value, dict)
    if kind == "nullableBoolean":
        return value is None or isinstance(value, bool)
    return False


# --- detect.js ------------------------------------------------------------------


def is_mobile_vector(S: object) -> bool:
    if _prop(_prop(S, "uaData"), "mobile") is True:
        return True
    ua = _prop(S, "ua")
    ua_str = _js_str(ua) if _js_truthy(ua) else ""
    return MOBILE_UA.search(ua_str) is not None


def probe_completeness(S: object, font_stack_count: object = None) -> list[str]:
    if as_json_dict(S) is None:
        return ["probe"]
    bad: list[str] = []
    for field, kind in PROBE_FIELD_TYPES.items():
        if not _type_ok(_prop(S, field), kind):
            bad.append(field)
    font_widths = as_json_list(_prop(S, "fontWidths"))
    if (
        font_widths is not None
        and _is_num(font_stack_count)
        and len(font_widths) != _to_f(font_stack_count)
    ):
        bad.append("fontWidths.length")
    return bad


def geometry_stats(font_widths: object) -> dict[str, int] | None:
    widths = as_json_list(font_widths) or []
    w = [x for x in widths[:MAX_FONT_WIDTHS] if _is_num(x)]
    if len(w) < 6:
        return None
    count = 0
    distinct: set[float] = set()
    for x in w:
        f = _to_f(x)
        if f.is_integer():  # JS: Math.trunc(x) === x
            count += 1
            distinct.add(f)
    return {"count": count, "distinct": len(distinct), "n": len(w)}


def _check(
    checks: list[dict[str, Any]], check_id: str, passed: bool, detail: str, gating: bool = True
) -> None:
    checks.append(
        {"id": check_id, "passed": passed is not False, "detail": detail, "gating": gating}
    )


def detect_automation(S: object, *, font_stack_count: object = None) -> dict[str, Any]:
    if as_json_dict(S) is None and as_json_list(S) is None:  # JS: !S || typeof S !== "object"
        return {"pass": False, "checks": [], "blocked_by": ["probe_missing"], "risk_flags": []}

    checks: list[dict[str, Any]] = []

    incomplete = probe_completeness(S, font_stack_count)
    _check(
        checks,
        "probe_incomplete",
        len(incomplete) == 0,
        f"missing or malformed: {', '.join(incomplete[:MAX_DETAIL_FIELDS])}"
        if incomplete
        else "all fields present",
    )

    engine = _prop(S, "engine")
    product_sub = _prop(S, "productSub")
    oscpu = _prop(S, "oscpu")
    ua_data_present = _prop(S, "uaDataPresent")
    gecko = (
        _prop(engine, "hasMozInnerScreenX") is True
        or (product_sub == "20100101" and ua_data_present is False)
        or (isinstance(oscpu, str) and oscpu != "__undefined")
    )
    chromium = ua_data_present is True or _prop(engine, "hasChrome") is True
    mobile = is_mobile_vector(S)

    geo = geometry_stats(_prop(S, "fontWidths"))
    quantized = geo is not None and geo["count"] >= 5 and geo["distinct"] >= 3
    _check(
        checks,
        "geometry_quantized",
        not quantized,
        f"{geo['count']}/{geo['n']} whole-px, {geo['distinct']} distinct"
        if geo
        else "not measured",
    )

    webdriver = _prop(S, "webdriver")
    _check(checks, "webdriver_true", webdriver is not True, f"webdriver={_js_str(webdriver)}")

    stripped = chromium and webdriver is UNDEF
    _check(
        checks,
        "webdriver_stripped",
        not stripped,
        ("removed" if stripped else "ok") if chromium else "not a chromium engine",
    )

    contradiction = gecko and (_is_num(_prop(S, "deviceMemory")) or ua_data_present is True)
    _check(checks, "gecko_contradiction", not contradiction, "gecko engine" if gecko else "n/a")

    sc_raw = _prop(S, "screen")
    sc: object = sc_raw if _js_truthy(sc_raw) else {}
    ow: list[Any] = as_json_list(_prop(S, "outerWH")) or []
    iw: list[Any] = as_json_list(_prop(S, "innerWH")) or []
    sc_height = _prop(sc, "height")
    sc_width = _prop(sc, "width")
    ow1 = _idx(ow, 1)
    iw0 = _idx(iw, 0)
    iw1 = _idx(iw, 1)

    single_monitor = _prop(S, "isExtended") is False
    outer_taller = (
        _is_num(ow1) and _is_num(sc_height) and _to_f(ow1) > _to_f(sc_height) + OUTER_HEIGHT_SLACK
    )
    exceeds = outer_taller and single_monitor
    if not single_monitor:
        window_detail = "monitor layout unknown"
    elif exceeds:
        window_detail = f"outerHeight {_js_num_str(ow1)} > screen.height {_js_num_str(sc_height)}"
    else:
        window_detail = "ok"
    _check(checks, "window_exceeds_screen", not exceeds, window_detail)

    viewport_is_screen = (
        not mobile
        and _is_num(iw0)
        and _is_num(iw1)
        and _is_num(sc_width)
        and _to_f(iw0) == _to_f(sc_width)
        and _is_num(sc_height)
        and _to_f(iw1) == _to_f(sc_height)
        and _is_num(ow1)
        and _to_f(ow1) > _to_f(iw1)
    )
    _check(
        checks,
        "viewport_override",
        not viewport_is_screen,
        f"viewport {_js_num_str(iw0)}x{_js_num_str(iw1)} == screen, window {_js_num_str(ow1)} tall"
        if viewport_is_screen
        else "ok",
    )

    ua_data = _prop(S, "uaData")
    brands_v = _prop(ua_data, "brands")
    brands_list = as_json_list(brands_v)
    brands = _js_join(brands_list, " ") if brands_list is not None else ""
    ua = _prop(S, "ua")
    ua_str = _js_str(ua) if _js_truthy(ua) else ""
    headless = _HEADLESS_RE.search(brands) is not None or _HEADLESS_RE.search(ua_str) is not None
    _check(
        checks, "headless_token", not headless, "HeadlessChrome present" if headless else "absent"
    )

    tamper = _prop(S, "tamper")
    t: dict[str, Any] = as_json_dict(tamper) or {}
    tampered = [k for k in _own_keys(t) if t[k] is False]
    _check(
        checks,
        "native_tamper",
        len(tampered) == 0,
        "JS-overridden: "
        + ", ".join(_utf16_prefix(k, MAX_TAMPER_KEY_LENGTH) for k in tampered[:MAX_TAMPER_KEYS])
        if tampered
        else "native",
        gating=False,
    )

    failed = [c for c in checks if c["gating"] and not c["passed"]]
    return {
        "pass": len(failed) == 0,
        "checks": checks,
        "blocked_by": [c["id"] for c in failed],
        "risk_flags": [c["id"] for c in checks if not c["gating"] and not c["passed"]],
    }


__all__ = [
    "MAX_DETAIL_FIELDS",
    "MAX_FONT_WIDTHS",
    "MAX_TAMPER_KEYS",
    "MAX_TAMPER_KEY_LENGTH",
    "MOBILE_UA",
    "OUTER_HEIGHT_SLACK",
    "PROBE_FIELD_TYPES",
    "detect_automation",
    "geometry_stats",
    "is_mobile_vector",
    "probe_completeness",
]
