"""Tests for capwx.protocols.instrumentation.detect (M7).

Hand-written vectors per check id, edge cases, and (marker ``node``) a differential
test against the real upstream ``core/src/detect.js``.

Run the differential test with: ``uv run pytest -m node tests/test_detect.py``.
Set ``CAP_CHECKOUT`` to the Cap repository root to override the default checkout.
"""

from __future__ import annotations

import copy
import json
import math
import os
import random
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from capwx.protocols.instrumentation.detect import (
    MAX_DETAIL_FIELDS,
    MAX_FONT_WIDTHS,
    MAX_TAMPER_KEY_LENGTH,
    MAX_TAMPER_KEYS,
    OUTER_HEIGHT_SLACK,
    PROBE_FIELD_TYPES,
    detect_automation,
    geometry_stats,
    is_mobile_vector,
    probe_completeness,
)

ALL_IDS = {
    "probe_incomplete",
    "geometry_quantized",
    "webdriver_true",
    "webdriver_stripped",
    "gecko_contradiction",
    "window_exceeds_screen",
    "viewport_override",
    "headless_token",
    "native_tamper",
}
GATING_IDS = ALL_IDS - {"native_tamper"}
FONT_STACKS = 8
CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
FIREFOX_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0"


def chrome_desktop() -> dict[str, Any]:
    return {
        "ua": CHROME_UA,
        "productSub": "20030107",
        "oscpu": "__undefined",
        "uaDataPresent": True,
        "uaData": {"mobile": False, "brands": ["Google Chrome/124", "Chromium/124"]},
        "plugins": {"PDF Viewer": True},
        "engine": {"hasChrome": True, "hasMozInnerScreenX": False},
        "screen": {"width": 1920, "height": 1080},
        "outerWH": [1920, 1040],
        "innerWH": [1903, 955],
        "isExtended": False,
        "fontWidths": [121.45, 133.02, 118.7, 140.11, 129.6, 119.33, 131.9, 124.08],
        "tamper": {"getParameterWebGL": True, "toDataURL": True},
        "webdriver": False,
        "deviceMemory": 8,
    }


def chrome_mobile() -> dict[str, Any]:
    return {
        "ua": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
        "productSub": "20030107",
        "oscpu": "__undefined",
        "uaDataPresent": True,
        "uaData": {"mobile": True, "brands": ["Google Chrome/124"]},
        "plugins": {},
        "engine": {"hasChrome": True},
        "screen": {"width": 412, "height": 915},
        # Viewport equals the screen and the window is taller than it: only a
        # desktop-shaped vector would be flagged by viewport_override.
        "outerWH": [412, 930],
        "innerWH": [412, 915],
        "isExtended": False,
        "fontWidths": [96.5, 110.25, 101.1, 99.9, 120.4, 88.75, 105.6, 97.3],
        "tamper": {"fnToString": True},
        "webdriver": False,
        "deviceMemory": 4,
    }


def firefox_desktop() -> dict[str, Any]:
    return {
        "ua": FIREFOX_UA,
        "productSub": "20100101",
        "oscpu": "Windows NT 10.0; Win64; x64",
        "uaDataPresent": False,
        "uaData": None,
        "plugins": {},
        "engine": {"hasChrome": False, "hasMozInnerScreenX": True},
        "screen": {"width": 1920, "height": 1080},
        "outerWH": [1920, 1040],
        "innerWH": [1903, 955],
        "isExtended": False,
        "fontWidths": [121.45, 133.02, 118.7, 140.11, 129.6, 119.33, 131.9, 124.08],
        "tamper": {},
        "webdriver": False,
    }


def _with(**changes: Any) -> dict[str, Any]:
    S = chrome_desktop()
    S.update(changes)
    return S


def _check(result: dict[str, Any], check_id: str) -> dict[str, Any]:
    matches = [c for c in result["checks"] if c["id"] == check_id]
    assert len(matches) == 1, check_id
    return matches[0]


def _run(S: Any, font_stack_count: Any = FONT_STACKS) -> dict[str, Any]:
    return detect_automation(S, font_stack_count=font_stack_count)


def _assert_blocked(S: Any, check_id: str, detail: str | None = None) -> dict[str, Any]:
    result = _run(S)
    assert result["pass"] is False
    assert check_id in result["blocked_by"]
    check = _check(result, check_id)
    assert check["passed"] is False
    if detail is not None:
        assert check["detail"] == detail
    return result


# --- shape and baseline ----------------------------------------------------------


def test_result_shape_is_snake_case_and_complete() -> None:
    result = _run(chrome_desktop())
    assert set(result) == {"pass", "checks", "blocked_by", "risk_flags"}
    assert [c["id"] for c in result["checks"]] == [
        "probe_incomplete",
        "geometry_quantized",
        "webdriver_true",
        "webdriver_stripped",
        "gecko_contradiction",
        "window_exceeds_screen",
        "viewport_override",
        "headless_token",
        "native_tamper",
    ]
    for c in result["checks"]:
        assert set(c) == {"id", "passed", "detail", "gating"}
        assert c["gating"] is (c["id"] in GATING_IDS)
    assert set(result["blocked_by"]) == set()


def test_normal_chrome_desktop_passes() -> None:
    result = _run(chrome_desktop())
    assert result == {
        "pass": True,
        "checks": result["checks"],
        "blocked_by": [],
        "risk_flags": [],
    }
    assert all(c["passed"] for c in result["checks"])
    assert _check(result, "probe_incomplete")["detail"] == "all fields present"
    assert _check(result, "geometry_quantized")["detail"] == "0/8 whole-px, 0 distinct"
    assert _check(result, "webdriver_stripped")["detail"] == "ok"
    assert _check(result, "window_exceeds_screen")["detail"] == "ok"
    assert _check(result, "native_tamper")["detail"] == "native"


def test_normal_chrome_mobile_passes_including_viewport_equal_screen() -> None:
    assert is_mobile_vector(chrome_mobile()) is True
    result = _run(chrome_mobile())
    assert result["pass"] is True
    assert result["blocked_by"] == []
    assert _check(result, "viewport_override")["detail"] == "ok"


def test_firefox_desktop_passes() -> None:
    result = _run(firefox_desktop())
    assert result["pass"] is True
    assert _check(result, "gecko_contradiction")["detail"] == "gecko engine"
    assert _check(result, "webdriver_stripped")["detail"] == "not a chromium engine"


# --- one vector per check id ---------------------------------------------------------


def test_probe_incomplete_missing_field() -> None:
    S = chrome_desktop()
    del S["ua"]
    result = _assert_blocked(S, "probe_incomplete", "missing or malformed: ua")
    assert result["blocked_by"] == ["probe_incomplete"]


def test_probe_incomplete_malformed_type() -> None:
    _assert_blocked(
        _with(uaDataPresent="yes"), "probe_incomplete", "missing or malformed: uaDataPresent"
    )


def test_probe_incomplete_detail_is_capped() -> None:
    result = _run({})
    check = _check(result, "probe_incomplete")
    names = list(PROBE_FIELD_TYPES)[:MAX_DETAIL_FIELDS]
    assert check["detail"] == "missing or malformed: " + ", ".join(names)


def test_probe_incomplete_fontwidths_length_mismatch() -> None:
    S = _with(fontWidths=[121.5] * (FONT_STACKS - 1))
    _assert_blocked(S, "probe_incomplete", "missing or malformed: fontWidths.length")


def test_geometry_quantized_whole_pixel_widths() -> None:
    S = _with(fontWidths=[120, 135, 150, 160, 170, 180, 200, 210])
    _assert_blocked(S, "geometry_quantized", "8/8 whole-px, 8 distinct")


def test_geometry_not_quantized_when_only_two_distinct_values() -> None:
    S = _with(fontWidths=[120, 120, 121, 121, 120, 121, 120, 121])
    result = _run(S)
    assert _check(result, "geometry_quantized")["passed"] is True


def test_webdriver_true() -> None:
    _assert_blocked(_with(webdriver=True), "webdriver_true", "webdriver=true")


def test_webdriver_stripped_on_chromium() -> None:
    S = chrome_desktop()
    del S["webdriver"]
    _assert_blocked(S, "webdriver_stripped", "removed")


def test_webdriver_null_is_not_stripped() -> None:
    result = _run(_with(webdriver=None))
    assert _check(result, "webdriver_stripped")["passed"] is True
    assert _check(result, "webdriver_true")["detail"] == "webdriver=null"


def test_gecko_contradiction_with_device_memory() -> None:
    S = firefox_desktop()
    S["deviceMemory"] = 8
    _assert_blocked(S, "gecko_contradiction", "gecko engine")


def test_window_exceeds_screen() -> None:
    S = _with(outerWH=[1920, 1200])
    _assert_blocked(S, "window_exceeds_screen", "outerHeight 1200 > screen.height 1080")


def test_window_slack_is_inclusive_of_sixteen_pixels() -> None:
    S = _with(outerWH=[1920, 1080 + OUTER_HEIGHT_SLACK])
    result = _run(S)
    assert _check(result, "window_exceeds_screen")["passed"] is True


def test_viewport_override() -> None:
    S = _with(innerWH=[1920, 1080], outerWH=[1920, 1090])
    _assert_blocked(S, "viewport_override", "viewport 1920x1080 == screen, window 1090 tall")


def test_headless_token_in_brands() -> None:
    S = _with(uaData={"mobile": False, "brands": ["HeadlessChrome/124"]})
    _assert_blocked(S, "headless_token", "HeadlessChrome present")


def test_headless_token_in_user_agent_is_case_insensitive() -> None:
    S = _with(ua=CHROME_UA.replace("Chrome/124", "HEADLESSCHROME/124"))
    _assert_blocked(S, "headless_token", "HeadlessChrome present")


def test_native_tamper_is_risk_flag_not_blocker() -> None:
    S = _with(tamper={"getParameterWebGL": False, "toDataURL": True})
    result = _run(S)
    assert result["pass"] is True
    assert result["blocked_by"] == []
    assert result["risk_flags"] == ["native_tamper"]
    check = _check(result, "native_tamper")
    assert check == {
        "id": "native_tamper",
        "passed": False,
        "detail": "JS-overridden: getParameterWebGL",
        "gating": False,
    }


# --- edge cases ------------------------------------------------------------------


@pytest.mark.parametrize("S", [None, 0, 1.5, "", "x", True, False])
def test_non_container_probe_is_missing(S: Any) -> None:
    result = _run(S)
    assert result == {
        "pass": False,
        "checks": [],
        "blocked_by": ["probe_missing"],
        "risk_flags": [],
    }


def test_array_probe_is_incomplete_not_an_exception() -> None:
    result = _run([1, 2, 3])
    assert result["pass"] is False
    assert _check(result, "probe_incomplete")["detail"] == "missing or malformed: probe"


def test_bool_is_not_a_number() -> None:
    # screen/innerWH entries that are booleans must not be compared as numbers.
    S = _with(screen={"width": True, "height": True}, innerWH=[True, True], outerWH=[1920, 1200])
    result = _run(S)
    assert _check(result, "window_exceeds_screen")["passed"] is True
    assert _check(result, "viewport_override")["passed"] is True


def test_bool_device_memory_is_not_a_number() -> None:
    S = firefox_desktop()
    S["deviceMemory"] = True
    result = _run(S)
    assert _check(result, "gecko_contradiction")["passed"] is True


def test_bool_font_stack_count_disables_length_check() -> None:
    S = _with(fontWidths=[121.5] * 7)
    assert _run(S, font_stack_count=True)["pass"] is True


def test_bool_font_widths_are_not_measured() -> None:
    result = _run(_with(fontWidths=[True] * 10))
    assert _check(result, "geometry_quantized")["detail"] == "not measured"


def test_nan_and_infinity_are_not_numbers() -> None:
    S = _with(outerWH=[1920, math.nan], screen={"width": 1920, "height": math.inf})
    result = _run(S)
    assert _check(result, "window_exceeds_screen")["passed"] is True
    S = _with(outerWH=[1920, math.inf])
    assert _run(S)["pass"] is True


def test_huge_integers_do_not_raise() -> None:
    huge = 10**400
    S = _with(webdriver=huge, outerWH=[1920, huge], screen={"width": 1920, "height": 1080})
    result = _run(S)
    assert _check(result, "webdriver_true")["detail"] == "webdriver=Infinity"
    assert _check(result, "window_exceeds_screen")["passed"] is True


def test_missing_fields_do_not_raise() -> None:
    result = _run({})
    assert result["pass"] is False
    assert "probe_incomplete" in result["blocked_by"]
    assert _check(result, "webdriver_true")["passed"] is True
    assert _check(result, "window_exceeds_screen")["detail"] == "monitor layout unknown"
    assert _check(result, "webdriver_stripped")["detail"] == "not a chromium engine"


def test_null_sub_objects_do_not_raise() -> None:
    S = _with(engine=None, screen=None, uaData=None, tamper=None, outerWH=None)
    result = _run(S)
    assert _check(result, "window_exceeds_screen")["passed"] is True


def test_geometry_stats_uses_only_first_64_entries() -> None:
    widths: list[Any] = [1.5] * 60 + [100] * 100_000
    assert geometry_stats(widths) == {"count": 4, "distinct": 1, "n": 64}
    whole: list[Any] = [100 + i for i in range(100_000)]
    assert geometry_stats(whole) == {"count": 64, "distinct": 64, "n": 64}


def test_geometry_stats_thresholds() -> None:
    assert geometry_stats(None) is None
    assert geometry_stats("abc") is None
    assert geometry_stats([1, 2, 3, 4, 5]) is None
    assert geometry_stats([1, 2, 3, 4, 5, 6.5]) == {"count": 5, "distinct": 5, "n": 6}


def test_probe_completeness_direct() -> None:
    assert probe_completeness([1]) == ["probe"]
    assert probe_completeness(chrome_desktop(), FONT_STACKS) == []
    assert probe_completeness(chrome_desktop(), None) == []


@pytest.mark.parametrize(
    ("ua", "expected"),
    [
        ("Mozilla/5.0 (Linux; Android 14)", True),
        ("MOZILLA ANDROID", True),
        ("Mozilla/5.0 (iPhone; CPU iPhone OS 17)", True),
        ("Mozilla/5.0 (Linux) Kindle/3.0", True),
        ("Mozilla/5.0 (X11; Linux x86_64) Firefox/126.0", False),
        ("", False),
    ],
)
def test_is_mobile_by_user_agent(ua: str, expected: bool) -> None:
    assert is_mobile_vector({"ua": ua}) is expected


def test_is_mobile_by_ua_data_flag() -> None:
    assert is_mobile_vector({"uaData": {"mobile": True}, "ua": CHROME_UA}) is True
    assert is_mobile_vector({"uaData": {"mobile": "true"}, "ua": CHROME_UA}) is False


def test_is_mobile_coerces_ua_like_js() -> None:
    assert is_mobile_vector({"ua": ["iPhone"]}) is True  # String(["iPhone"]) === "iPhone"
    assert is_mobile_vector({"ua": 5}) is False
    assert is_mobile_vector(None) is False


def test_headless_ignores_non_ascii_case_folding() -> None:
    # JS /headlesschrome/i does not match the long s (U+017F); Python re would.
    S = _with(ua=CHROME_UA.replace("Chrome/124", "HEADLESſCHROME/124"))
    assert _run(S)["pass"] is True


def test_headless_brands_objects_stringify_like_js() -> None:
    S = _with(uaData={"mobile": False, "brands": [{"brand": "HeadlessChrome"}]})
    assert _run(S)["pass"] is True  # join() gives "[object Object]"


def test_number_detail_uses_js_number_formatting() -> None:
    S = _with(outerWH=[1920, 1e21], screen={"width": 1920, "height": 1000})
    _assert_blocked(S, "window_exceeds_screen", "outerHeight 1e+21 > screen.height 1000")
    S = _with(outerWH=[1920, 1100.5], screen={"width": 1920, "height": 1000})
    _assert_blocked(S, "window_exceeds_screen", "outerHeight 1100.5 > screen.height 1000")
    S = _with(outerWH=[1920, 17], screen={"width": 1920, "height": 1e-7})
    _assert_blocked(S, "window_exceeds_screen", "outerHeight 17 > screen.height 1e-7")


def test_tamper_keys_follow_object_keys_order_and_are_capped() -> None:
    S = _with(tamper={"b": False, "10": False, "2": False, "a": False})
    result = _run(S)
    assert _check(result, "native_tamper")["detail"] == "JS-overridden: 2, 10, b, a"

    many = {f"k{i}_" + "x" * 50: False for i in range(1000)}
    detail = _check(_run(_with(tamper=many)), "native_tamper")["detail"]
    pieces = detail.removeprefix("JS-overridden: ").split(", ")
    assert len(pieces) == MAX_TAMPER_KEYS
    assert all(len(p) <= MAX_TAMPER_KEY_LENGTH for p in pieces)


def test_tamper_key_truncation_counts_utf16_units() -> None:
    emoji_key = "\U0001f600" * 20  # 2 UTF-16 units each -> 40 units
    detail = _check(_run(_with(tamper={emoji_key: False})), "native_tamper")["detail"]
    assert detail == "JS-overridden: " + "\U0001f600" * (MAX_TAMPER_KEY_LENGTH // 2)


def test_long_user_agent_and_huge_lists_do_not_raise() -> None:
    S = _with(ua="x" * 1_000_000, plugins={str(i): i for i in range(10_000)})
    assert _run(S)["pass"] is True
    S = _with(fontWidths=[1] * 500_000)
    result = _run(S, font_stack_count=None)
    assert _check(result, "geometry_quantized")["detail"] == "64/64 whole-px, 1 distinct"


def test_constants_match_upstream() -> None:
    assert MAX_FONT_WIDTHS == 64
    assert MAX_TAMPER_KEYS == 8
    assert MAX_TAMPER_KEY_LENGTH == 32
    assert MAX_DETAIL_FIELDS == 6
    assert OUTER_HEIGHT_SLACK == 16


# --- Node differential ------------------------------------------------------------

_NODE_RUNNER = r"""
import { readFileSync, writeFileSync } from "node:fs";

const [detectUrl, inPath, outPath] = process.argv.slice(2);
const { isMobileVector, probeCompleteness, geometryStats, detectAutomation } =
  await import(detectUrl);

const revive = (_k, v) =>
  v && typeof v === "object" && !Array.isArray(v) &&
  Object.keys(v).length === 1 && "$num" in v
    ? Number(v.$num)
    : v;

const rename = (r) => ({
  pass: r.pass,
  checks: r.checks,
  blocked_by: r.blockedBy,
  risk_flags: r.riskFlags,
});

const cases = JSON.parse(readFileSync(inPath, "utf8"), revive);
const out = cases.map((c) => ({
  mobile: isMobileVector(c.S),
  probe: probeCompleteness(c.S, c.fontStackCount),
  geom: geometryStats(c.gw),
  auto: rename(detectAutomation(c.S, { fontStackCount: c.fontStackCount })),
}));
writeFileSync(outPath, JSON.stringify(out));
"""

_STRINGS = [
    "",
    "Mozilla/5.0",
    "HeadlessChrome/120",
    "headlesschrome",
    "HEADLESSCHROME",
    "HeadlesſChrome",
    "Android 14",
    "iPhone",
    "Opera Mini",
    "Kindle",
    "; Mobile",
    "Mobile Safari",
    "__undefined",
    "20100101",
    "\ud800lone",
    "\U0001f600 emoji",
    "x" * 40,
    "true",
    "null",
    "Google Chrome/124",
    "Chromium/124",
    "20030107",
    "Tizen Silk",
]
_KEYS = [
    "mobile",
    "brands",
    "height",
    "width",
    "hasChrome",
    "hasMozInnerScreenX",
    "a",
    "b",
    "0",
    "12",
    "10",
    "2",
]
_NUMS_COMMON = [1080, 1096, 1097, 1024, 768, 1200, 0, -1, 1920, 412, 915]
_NUMS_ODD = [
    1e21,
    1e20,
    1e-7,
    1e-6,
    5e-324,
    1.7976931348623157e308,
    -0.0,
    0.0,
    1e300,
    2**53 + 1,
    2**60 + 1,
    10**400,
    -(10**400),
    math.nan,
    math.inf,
    -math.inf,
]


def _rnd_num(rng: random.Random) -> Any:
    c = rng.randrange(10)
    if c <= 2:
        return rng.choice(_NUMS_COMMON)
    if c == 3:
        return rng.randint(0, 4000)
    if c == 4:
        return round(rng.uniform(-5000, 5000), rng.randint(0, 6))
    if c == 5:
        return rng.choice(_NUMS_ODD)
    if c == 6:
        return rng.choice([True, False])  # bools are never numbers
    if c == 7:
        return rng.choice(["1920", "", "x"])
    return rng.randint(1, 2000)


def _rnd_any(rng: random.Random, depth: int = 0) -> Any:
    c = rng.randrange(10 if depth < 2 else 6)
    if c == 0:
        return None
    if c == 1:
        return rng.random() < 0.5
    if c in (2, 3):
        return _rnd_num(rng)
    if c == 4:
        return rng.choice(_STRINGS)
    if c == 5:
        return rng.choice(_NUMS_COMMON)
    if c in (6, 7):
        return [_rnd_any(rng, depth + 1) for _ in range(rng.randrange(4))]
    return {rng.choice(_KEYS): _rnd_any(rng, depth + 1) for _ in range(rng.randrange(4))}


def _rnd_font_widths(rng: random.Random) -> list[Any]:
    n = rng.choice([0, 3, 6, 7, 8, 8, 8, 16, 64, 70])
    mode = rng.randrange(4)
    out: list[Any] = []
    for _ in range(n):
        if mode == 0:
            out.append(rng.randint(100, 103))  # few distinct whole-px
        elif mode == 1:
            out.append(round(rng.uniform(80, 160), 2))  # fractional
        elif mode == 2:
            out.append(_rnd_num(rng))
        else:
            out.append(rng.choice([rng.randint(90, 200), round(rng.uniform(90, 200), 2)]))
    return out


def _rnd_probe(rng: random.Random) -> dict[str, Any]:
    S: dict[str, Any] = {}
    complete = rng.random() < 0.5  # half the vectors carry every probe field
    coherent = complete or rng.random() < 0.6
    screen_w = rng.choice([1920, 412, 1366, 2560])
    screen_h = rng.choice([1080, 915, 768, 1440])
    for field, kind in PROBE_FIELD_TYPES.items():
        if complete or rng.random() < (0.97 if coherent else 0.75):
            S[field] = _rnd_typed(rng, kind, coherent, field)
    if rng.random() < 0.9 or coherent:
        S["screen"] = (
            {"width": screen_w, "height": screen_h} if rng.random() < 0.8 else _rnd_any(rng)
        )
    if rng.random() < 0.85:
        S["outerWH"] = (
            [screen_w, screen_h + rng.choice([-30, 0, 10, 40, 1200])]
            if coherent or rng.random() < 0.5
            else _rnd_any(rng)
        )
    if rng.random() < 0.7:
        S["innerWH"] = (
            [screen_w, screen_h] if rng.random() < 0.3 else [screen_w - 17, screen_h - 120]
        )
    if rng.random() < 0.85:
        S["isExtended"] = rng.choice([True, False, None, False])
    if rng.random() < 0.8:
        S["webdriver"] = (
            rng.choice([True, False, None, "x", 1, 0, 10**400])
            if rng.random() < 0.9
            else _rnd_any(rng)
        )
    if rng.random() < 0.6:
        S["deviceMemory"] = _rnd_num(rng)
    if rng.random() < 0.6:
        S["engine"] = {
            "hasChrome": rng.choice([True, False, None]),
            "hasMozInnerScreenX": rng.choice([True, False, None]),
        }
    if rng.random() < 0.6:
        S["tamper"] = {
            rng.choice(_KEYS + ["fnToString", "getImageData"]): rng.choice([True, False, None, 1])
            for _ in range(rng.randrange(4))
        }
    if rng.random() < 0.5:
        S["fontWidths"] = _rnd_font_widths(rng)
    return S


def _rnd_typed(rng: random.Random, kind: str, coherent: bool, field: str = "") -> Any:
    if field == "oscpu" and coherent:
        return rng.choice(["__undefined", "__undefined", "Windows NT 10.0; Win64; x64"])
    if kind == "string":
        if coherent and rng.random() < 0.7:
            return rng.choice(
                [CHROME_UA, FIREFOX_UA, "Mozilla/5.0 (Linux; Android 14) Mobile Safari"]
            )
        return rng.choice(_STRINGS)
    if kind == "boolean":
        return rng.random() < 0.5
    if kind == "object":
        return {rng.choice(_KEYS): _rnd_any(rng, 1) for _ in range(rng.randrange(3))}
    if kind == "array":
        return _rnd_font_widths(rng) if rng.random() < 0.5 else [_rnd_num(rng) for _ in range(2)]
    if kind == "nullableObject":
        if rng.random() < 0.4:
            return None
        if rng.random() < 0.5:
            return {"mobile": rng.choice([True, False, "true"]), "brands": _rnd_any(rng, 1)}
        return {rng.choice(_KEYS): _rnd_any(rng, 1) for _ in range(rng.randrange(3))}
    return rng.choice([None, True, False])


def _rnd_case(rng: random.Random) -> dict[str, Any]:
    c = rng.randrange(20)
    if c == 0:
        S: Any = rng.choice([None, [], [1, 2], "x", 0, True, 3.5])
    elif c == 1:
        S = {}
    else:
        S = _rnd_probe(rng)
    font_stack_count = rng.choice([FONT_STACKS, FONT_STACKS, None, 7, 8.0, True, "8", 0, math.nan])
    gw = (
        S.get("fontWidths", _rnd_any(rng))
        if isinstance(S, dict) and rng.random() < 0.7
        else _rnd_any(rng)
    )
    if rng.random() < 0.3:
        gw = _rnd_font_widths(rng)
    return {"S": S, "fontStackCount": font_stack_count, "gw": gw}


def _encode(v: Any) -> Any:
    """Make Python values JSON-safe for Node; non-finite floats travel as {"$num": ...}."""
    if isinstance(v, float) and not math.isfinite(v):
        return {"$num": "NaN" if math.isnan(v) else ("Infinity" if v > 0 else "-Infinity")}
    if isinstance(v, dict):
        return {k: _encode(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_encode(x) for x in v]
    return v


def _python_result(case: dict[str, Any]) -> dict[str, Any]:
    S = case["S"]
    n = case["fontStackCount"]
    return {
        "mobile": is_mobile_vector(S),
        "probe": probe_completeness(S, n),
        "geom": geometry_stats(case["gw"]),
        "auto": detect_automation(S, font_stack_count=n),
    }


def _upstream_detect_js() -> Path | None:
    root = Path(
        os.environ.get("CAP_CHECKOUT", "C:/Users/ALIFA/AppData/Local/Temp/capwx-upstream/cap")
    )
    path = root / "core" / "src" / "detect.js"
    return path if path.is_file() else None


def _node() -> str | None:
    return shutil.which("node")


def _random_vectors(count: int, seed: int) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    cases = [_rnd_case(rng) for _ in range(count)]
    extra: list[dict[str, Any]] = [
        {
            "S": chrome_desktop(),
            "fontStackCount": FONT_STACKS,
            "gw": chrome_desktop()["fontWidths"],
        },
        {"S": chrome_mobile(), "fontStackCount": FONT_STACKS, "gw": None},
        {"S": firefox_desktop(), "fontStackCount": None, "gw": [1, 2, 3, 4, 5, 6]},
        {
            "S": _with(webdriver=True, tamper={"b": False, "10": False, "2": False}),
            "fontStackCount": 8,
            "gw": [],
        },
        {"S": None, "fontStackCount": None, "gw": None},
        {"S": [], "fontStackCount": 8, "gw": [100] * 200},
        {"S": {}, "fontStackCount": math.inf, "gw": [math.nan] * 10},
    ]
    return cases + extra


@pytest.mark.node
def test_differential_against_upstream_detect_js(tmp_path: Path) -> None:
    node = _node()
    if node is None:
        pytest.skip("node is not on PATH")
    upstream = _upstream_detect_js()
    if upstream is None:
        pytest.skip("upstream core/src/detect.js not found (set CAP_CHECKOUT)")

    cases = _random_vectors(200, seed=20260421)
    assert len(cases) >= 200

    runner = tmp_path / "detect_runner.mjs"
    runner.write_text(_NODE_RUNNER, encoding="utf-8")
    inp = tmp_path / "vectors.json"
    inp.write_text(json.dumps([_encode(c) for c in cases], allow_nan=False), encoding="utf-8")
    out = tmp_path / "node_out.json"

    proc = subprocess.run(
        [node, str(runner), upstream.as_uri(), str(inp), str(out)],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    node_results = json.loads(out.read_text(encoding="utf-8"))
    assert len(node_results) == len(cases)

    mismatches = []
    for i, (case, js) in enumerate(zip(cases, node_results, strict=True)):
        py = json.loads(json.dumps(_python_result(case), allow_nan=False))
        if py != js:
            mismatches.append(i)
    assert not mismatches, (
        f"{len(mismatches)} of {len(cases)} vectors differ; first index {mismatches[0]}:\n"
        f"python={json.dumps(_python_result(cases[mismatches[0]]), ensure_ascii=False)[:800]}\n"
        f"node  ={json.dumps(node_results[mismatches[0]], ensure_ascii=False)[:800]}"
    )


def test_python_port_does_not_mutate_input() -> None:
    S = chrome_desktop()
    before = copy.deepcopy(S)
    detect_automation(S, font_stack_count=FONT_STACKS)
    assert S == before
