"""Tests for capwx.protocols.instrumentation mint() and verify() (M7, no browser).

The "client" here computes the correct answer from the generated meta: the state is
``{var: expectedVal}``. Probes are hand-written vectors in the shape the browser sends.
"""

from __future__ import annotations

import base64
import random
import re
import time
import zlib
from typing import Any

import pytest

from capwx.config import CapConfig, InstrumentationOptions
from capwx.errors import CapwxError, Reason
from capwx.protocols.instrumentation import mint, verify, verify_instrumentation_result
from capwx.protocols.instrumentation.generator import PROBE_FONT_STACKS

SECRET = "s" * 32
CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
VP = [1903, 955]
FONT_COUNT = len(PROBE_FONT_STACKS)


def _config(block: bool = False, level: int = 3) -> CapConfig:
    return CapConfig(
        secret=SECRET,
        protocols=("instrumentation",),
        instrumentation=InstrumentationOptions(
            block_automated_browsers=block, obfuscation_level=level
        ),
    )


def _mint_one(block: bool = False, **kwargs: Any) -> tuple[dict, dict]:
    [(payload, expected)] = mint(_config(block=block), **kwargs)
    return payload, expected


def _probe() -> dict[str, Any]:
    """A normal desktop Chrome probe (passes every gating check)."""
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
        "isExtended": False,
        "fontWidths": [121.45 + i * 0.37 for i in range(FONT_COUNT)],
        "tamper": {"getParameterWebGL": True},
        "webdriver": False,
        "deviceMemory": 8,
    }


def _answer(expected: dict, *, probe: Any = None, vp: Any = VP, **extra: Any) -> dict:
    """The payload a correct client sends: state from the expected values, plus the probe."""
    meta = expected["instrMeta"]
    state = dict(zip(meta["vars"], meta["expectedVals"]))
    payload: dict[str, Any] = {"i": meta["id"], "state": state, "ts": 0}
    if probe is not None:
        payload["p"] = probe
        payload["vp"] = vp
    payload.update(extra)
    return payload


def _meta(expected: dict) -> dict:
    return expected["instrMeta"]


def _with_meta(expected: dict, **changes: Any) -> dict:
    meta = {**expected["instrMeta"], **changes}
    return {**expected, "instrMeta": meta}


# --- mint -----------------------------------------------------------------------


def test_mint_returns_one_pair_with_public_blob_only() -> None:
    [(payload, expected)] = mint(_config())
    assert set(payload) == {"blob"}
    assert isinstance(payload["blob"], str) and payload["blob"]
    assert set(expected) == {"protocol", "instrMeta"}
    assert expected["protocol"] == "instrumentation"


def test_mint_instr_meta_has_camel_case_keys_and_shapes() -> None:
    _, expected = _mint_one()
    meta = expected["instrMeta"]
    assert set(meta) == {"id", "expectedVals", "vars", "blockAutomatedBrowsers", "expires"}
    assert re.fullmatch(r"[0-9a-f]{32}", meta["id"])
    assert len(meta["vars"]) == 4
    assert all(isinstance(v, str) and re.fullmatch(r"[a-z][a-z0-9]{11}", v) for v in meta["vars"])
    assert len(set(meta["vars"])) == 4
    assert len(meta["expectedVals"]) == 4
    assert all(type(v) is int and 100_000 <= v <= 999_999 for v in meta["expectedVals"])
    assert meta["blockAutomatedBrowsers"] is False


def test_mint_block_flag_follows_config() -> None:
    _, expected = _mint_one(block=True)
    assert expected["instrMeta"]["blockAutomatedBrowsers"] is True


def test_mint_default_expires_is_now_plus_challenge_ttl() -> None:
    before = int(time.time() * 1000)
    _, expected = _mint_one()
    after = int(time.time() * 1000)
    ttl = _config().challenge_ttl_ms
    assert before + ttl <= expected["instrMeta"]["expires"] <= after + ttl


def test_mint_expires_ms_sets_expiry_exactly() -> None:
    _, expected = _mint_one(expires_ms=1_700_000_000_000)
    assert expected["instrMeta"]["expires"] == 1_700_000_000_000


@pytest.mark.parametrize("bad", [True, 1.5, "1"])
def test_mint_rejects_non_int_expires_ms(bad: Any) -> None:
    with pytest.raises(CapwxError):
        mint(_config(), expires_ms=bad)


def test_mint_blob_inflates_to_non_empty_utf8_script() -> None:
    payload, _ = _mint_one()
    raw = zlib.decompress(base64.b64decode(payload["blob"], validate=True), -15)
    script = raw.decode("utf-8")
    assert script
    assert "window.onload" in script


@pytest.mark.parametrize("level", [1, 4, 7])
def test_mint_blob_is_valid_for_every_obfuscation_level(level: int) -> None:
    [(payload, _)] = mint(_config(level=level))
    script = zlib.decompress(base64.b64decode(payload["blob"]), -15).decode("utf-8")
    assert script


# --- verify: happy paths --------------------------------------------------------


def test_correct_answer_without_probe_and_block_off_is_valid() -> None:
    _, expected = _mint_one()
    result = verify(expected, {"instr": _answer(expected)}, now_ms=0)
    assert result.valid is True
    assert result.reason is None
    assert result.risk_flags == []
    assert result.blocked_by == []


def test_correct_answer_with_normal_probe_and_block_on_is_valid() -> None:
    _, expected = _mint_one(block=True)
    result = verify(expected, {"instr": _answer(expected, probe=_probe())}, now_ms=0)
    assert result.valid is True
    assert result.reason is None
    assert result.blocked_by == []


def test_probe_vector_uses_vp_as_inner_wh() -> None:
    # A viewport equal to the screen with a taller window is flagged only when innerWH
    # comes from vp: the probe itself carries no innerWH.
    _, expected = _mint_one(block=True)
    probe = _probe()
    probe["screen"] = {"width": 1920, "height": 1080}
    probe["outerWH"] = [1920, 1100]
    result = verify(expected, {"instr": _answer(expected, probe=probe, vp=[1920, 1080])}, now_ms=0)
    assert result.valid is False
    assert result.reason == Reason.INSTR_AUTOMATED_BROWSER
    assert "viewport_override" in result.blocked_by


def test_bad_vp_shape_falls_back_to_probe_without_inner_wh() -> None:
    _, expected = _mint_one(block=True)
    probe = _probe()
    result = verify(expected, {"instr": _answer(expected, probe=probe, vp=[1920])}, now_ms=0)
    assert result.valid is True


def test_native_tamper_is_a_risk_flag_passed_through() -> None:
    _, expected = _mint_one(block=True)
    probe = _probe()
    probe["tamper"] = {"toDataURL": False, "getParameterWebGL": True}
    result = verify(expected, {"instr": _answer(expected, probe=probe)}, now_ms=0)
    assert result.valid is True
    assert result.risk_flags == ["native_tamper"]
    assert result.blocked_by == []


def test_gating_failure_with_block_off_is_valid_with_blocked_by() -> None:
    _, expected = _mint_one(block=False)
    probe = _probe()
    probe["webdriver"] = True
    result = verify(expected, {"instr": _answer(expected, probe=probe)}, now_ms=0)
    assert result.valid is True
    assert result.blocked_by == ["webdriver_true"]


# --- verify: probe reasons ------------------------------------------------------


def test_headless_probe_with_block_on_is_automated_browser_with_blocked_by() -> None:
    _, expected = _mint_one(block=True)
    probe = _probe()
    probe["webdriver"] = True
    result = verify(expected, {"instr": _answer(expected, probe=probe)}, now_ms=0)
    assert result.valid is False
    assert result.reason == Reason.INSTR_AUTOMATED_BROWSER
    assert result.blocked_by == ["webdriver_true"]


def test_probe_missing_with_block_on_is_probe_missing() -> None:
    _, expected = _mint_one(block=True)
    result = verify(expected, {"instr": _answer(expected)}, now_ms=0)
    assert result.valid is False
    assert result.reason == Reason.INSTR_PROBE_MISSING
    assert result.blocked_by == []


def test_incomplete_probe_is_gating_under_block_on() -> None:
    _, expected = _mint_one(block=True)
    probe = _probe()
    del probe["ua"]
    result = verify(expected, {"instr": _answer(expected, probe=probe)}, now_ms=0)
    assert result.reason == Reason.INSTR_AUTOMATED_BROWSER
    assert result.blocked_by == ["probe_incomplete"]


def test_font_width_count_must_match_probe_font_stacks() -> None:
    _, expected = _mint_one(block=True)
    probe = _probe()
    probe["fontWidths"] = probe["fontWidths"][:-1]
    result = verify(expected, {"instr": _answer(expected, probe=probe)}, now_ms=0)
    assert result.reason == Reason.INSTR_AUTOMATED_BROWSER
    assert "probe_incomplete" in result.blocked_by


def test_list_probe_is_treated_as_object_like_upstream() -> None:
    # Upstream: typeof [] === "object", so the array goes to detectAutomation and fails
    # probe_completeness rather than being ignored.
    _, expected = _mint_one(block=True)
    result = verify(expected, {"instr": _answer(expected, probe=[1, 2, 3])}, now_ms=0)
    assert result.reason == Reason.INSTR_AUTOMATED_BROWSER
    assert result.blocked_by == ["probe_incomplete"]


# --- verify_instrumentation_result: failure reasons -----------------------------


def test_id_mismatch() -> None:
    _, expected = _mint_one()
    payload = _answer(expected)
    payload["i"] = "0" * 32
    valid, reason, flags, blocked = verify_instrumentation_result(_meta(expected), payload)
    assert (valid, reason, flags, blocked) == (False, Reason.ID_MISMATCH, [], [])


def test_id_missing_is_mismatch() -> None:
    _, expected = _mint_one()
    payload = _answer(expected)
    del payload["i"]
    assert verify_instrumentation_result(_meta(expected), payload)[1] == Reason.ID_MISMATCH


@pytest.mark.parametrize("state", [None, "state", 5, True])
def test_invalid_state_for_non_object(state: Any) -> None:
    _, expected = _mint_one()
    payload = _answer(expected)
    payload["state"] = state
    assert verify_instrumentation_result(_meta(expected), payload)[1] == Reason.INVALID_STATE


def test_list_state_is_failed_challenge_like_upstream() -> None:
    # Upstream: an array is typeof "object", so it passes the state check and fails the value
    # check (arr["abcd..."] is undefined).
    _, expected = _mint_one()
    payload = _answer(expected)
    payload["state"] = [100000, 100001]
    assert verify_instrumentation_result(_meta(expected), payload)[1] == Reason.FAILED_CHALLENGE


def test_missing_state_is_invalid_state() -> None:
    _, expected = _mint_one()
    payload = _answer(expected)
    del payload["state"]
    assert verify_instrumentation_result(_meta(expected), payload)[1] == Reason.INVALID_STATE


def test_wrong_value_is_failed_challenge() -> None:
    _, expected = _mint_one()
    payload = _answer(expected)
    var = expected["instrMeta"]["vars"][2]
    payload["state"][var] += 1
    result = verify(expected, {"instr": payload}, now_ms=0)
    assert result.valid is False
    assert result.reason == Reason.FAILED_CHALLENGE


def test_missing_var_is_failed_challenge() -> None:
    _, expected = _mint_one()
    payload = _answer(expected)
    del payload["state"][expected["instrMeta"]["vars"][0]]
    assert verify_instrumentation_result(_meta(expected), payload)[1] == Reason.FAILED_CHALLENGE


def test_extra_state_keys_are_ignored() -> None:
    _, expected = _mint_one()
    payload = _answer(expected)
    payload["state"]["unrelated"] = 1
    assert verify_instrumentation_result(_meta(expected), payload)[0] is True


def test_bool_values_are_rejected_even_when_numerically_equal() -> None:
    _, expected = _mint_one()
    meta = {**_meta(expected), "expectedVals": [1, 1, 1, 1]}
    payload = _answer({"instrMeta": meta})
    for var in meta["vars"]:
        payload["state"][var] = True
    valid, reason, _, _ = verify_instrumentation_result(meta, payload)
    assert (valid, reason) == (False, Reason.FAILED_CHALLENGE)


def test_integral_float_matches_like_javascript_number() -> None:
    # Upstream uses ===; JSON 42.0 is the number 42 in JavaScript.
    _, expected = _mint_one()
    payload = _answer(expected)
    var = expected["instrMeta"]["vars"][0]
    payload["state"][var] = float(payload["state"][var])
    assert verify_instrumentation_result(_meta(expected), payload)[0] is True


def test_string_value_does_not_match_number() -> None:
    _, expected = _mint_one()
    payload = _answer(expected)
    var = expected["instrMeta"]["vars"][0]
    payload["state"][var] = str(payload["state"][var])
    assert verify_instrumentation_result(_meta(expected), payload)[1] == Reason.FAILED_CHALLENGE


def test_non_list_vars_or_expected_is_invalid_meta() -> None:
    _, expected = _mint_one()
    payload = _answer(expected)
    meta = {**_meta(expected), "vars": "abcd"}
    assert verify_instrumentation_result(meta, payload)[1] == "invalid_meta"
    meta = {**_meta(expected), "expectedVals": None}
    assert verify_instrumentation_result(meta, payload)[1] == "invalid_meta"


def test_non_object_meta_and_payload_reasons() -> None:
    _, expected = _mint_one()
    assert verify_instrumentation_result(None, _answer(expected))[1] == "missing_meta"
    assert verify_instrumentation_result(_meta(expected), None)[1] == "missing_output"


# --- verify(): instrumentation branch of validateChallengeV2 --------------------


def test_valid_solution_end_to_end_without_browser() -> None:
    payload, expected = _mint_one(block=True)
    assert "blob" in payload  # the public part is only a blob; the client runs it
    solution = {"instr": _answer(expected, probe=_probe())}
    result = verify(expected, solution, now_ms=expected["instrMeta"]["expires"])
    assert result.valid is True


def test_missing_meta_is_corrupted() -> None:
    _, expected = _mint_one()
    for bad in ({}, {"instrMeta": None}, {"protocol": "instrumentation"}):
        assert verify(bad, {"instr": _answer(expected)}, now_ms=0).reason == (
            Reason.INSTR_CORRUPTED
        )


def test_expired_before_checking_anything_else() -> None:
    _, expected = _mint_one(block=True, expires_ms=1000)
    result = verify(expected, {"blocked": True}, now_ms=1001)
    assert result.valid is False
    assert result.reason == Reason.INSTR_EXPIRED


def test_expiry_boundary_is_inclusive_of_expires() -> None:
    _, expected = _mint_one(expires_ms=1000)
    assert verify(expected, {"instr": _answer(expected)}, now_ms=1000).valid is True
    assert verify(expected, {"instr": _answer(expected)}, now_ms=1001).reason == (
        Reason.INSTR_EXPIRED
    )


def test_missing_expires_never_expires_like_upstream() -> None:
    _, expected = _mint_one()
    meta = {k: v for k, v in _meta(expected).items() if k != "expires"}
    exp = {"protocol": "instrumentation", "instrMeta": meta}
    assert verify(exp, {"instr": _answer(exp)}, now_ms=10**15).valid is True


def test_blocked_flag_with_block_on_is_automated_browser() -> None:
    _, expected = _mint_one(block=True)
    result = verify(expected, {"blocked": True}, now_ms=0)
    assert result.reason == Reason.INSTR_AUTOMATED_BROWSER


def test_blocked_flag_with_block_off_is_instr_failed() -> None:
    _, expected = _mint_one(block=False)
    result = verify(expected, {"blocked": True}, now_ms=0)
    assert result.reason == Reason.INSTR_FAILED


def test_blocked_keyword_is_ored_with_solution_flag() -> None:
    _, expected = _mint_one(block=True)
    assert verify(expected, {}, blocked=True, now_ms=0).reason == Reason.INSTR_AUTOMATED_BROWSER
    assert verify(expected, {}, blocked=False, now_ms=0).reason == Reason.INSTR_MISSING


def test_blocked_truthy_but_not_true_is_ignored() -> None:
    _, expected = _mint_one(block=True)
    assert verify(expected, {"blocked": 1}, now_ms=0).reason == Reason.INSTR_MISSING


def test_timeout_flag_is_instr_timeout() -> None:
    _, expected = _mint_one()
    assert verify(expected, {"timeout": True}, now_ms=0).reason == Reason.INSTR_TIMEOUT
    assert verify(expected, {}, timeout=True, now_ms=0).reason == Reason.INSTR_TIMEOUT


def test_blocked_wins_over_timeout() -> None:
    _, expected = _mint_one(block=True)
    result = verify(expected, {"blocked": True, "timeout": True}, now_ms=0)
    assert result.reason == Reason.INSTR_AUTOMATED_BROWSER


@pytest.mark.parametrize("instr", [None, False, 0, ""])
def test_falsy_instr_is_missing(instr: Any) -> None:
    _, expected = _mint_one()
    assert verify(expected, {"instr": instr}, now_ms=0).reason == Reason.INSTR_MISSING


def test_no_solution_key_is_missing() -> None:
    _, expected = _mint_one()
    assert verify(expected, {}, now_ms=0).reason == Reason.INSTR_MISSING


def test_truthy_non_object_instr_is_failed_not_missing() -> None:
    _, expected = _mint_one()
    result = verify(expected, {"instr": 5}, now_ms=0)
    assert result.valid is False
    assert result.reason == "missing_output"


def test_failed_verification_reports_no_risk_flags() -> None:
    _, expected = _mint_one()
    payload = _answer(expected)
    payload["state"] = {}
    result = verify(expected, {"instr": payload}, now_ms=0)
    assert result.valid is False
    assert result.risk_flags == []
    assert result.blocked_by == []


def test_valid_result_is_frozen_dataclass() -> None:
    _, expected = _mint_one()
    result = verify(expected, {"instr": _answer(expected)}, now_ms=0)
    with pytest.raises(AttributeError):
        result.valid = False  # type: ignore[misc]


# --- never raises ---------------------------------------------------------------

GARBAGE: list[Any] = [
    None,
    True,
    False,
    0,
    -1,
    2**80,
    1.5,
    float("nan"),
    float("inf"),
    "",
    "abc",
    [],
    [None],
    [1, 2, 3],
    {},
    {"i": None},
    {"state": 5, "i": "x"},
]


@pytest.mark.parametrize("expected", GARBAGE)
@pytest.mark.parametrize("solution", GARBAGE)
def test_verify_never_raises_on_garbage(expected: Any, solution: Any) -> None:
    result = verify(expected, solution, now_ms=0)
    assert result.valid is False
    assert result.reason is not None


@pytest.mark.parametrize("meta", GARBAGE)
@pytest.mark.parametrize("payload", GARBAGE)
def test_verify_result_never_raises_on_garbage(meta: Any, payload: Any) -> None:
    valid, reason, flags, blocked = verify_instrumentation_result(meta, payload)
    assert valid is False
    assert reason is not None
    assert flags == [] and blocked == []


def test_verify_never_raises_on_random_json_shapes() -> None:
    rng = random.Random(7)

    def rnd(depth: int = 0) -> Any:
        kind = rng.randrange(8 if depth < 3 else 5)
        if kind == 0:
            return None
        if kind == 1:
            return rng.choice([True, False])
        if kind == 2:
            return rng.randint(-(2**60), 2**60)
        if kind == 3:
            return rng.choice([0.0, 1e308, -0.0, 3.5])
        if kind == 4:
            return rng.choice(["", "x", "vars", "i", "p"])
        if kind == 5:
            return [rnd(depth + 1) for _ in range(rng.randrange(4))]
        return {
            rng.choice(["i", "state", "p", "vp", "instr", "blocked", "timeout"]): rnd(depth + 1)
            for _ in range(rng.randrange(4))
        }

    _, base = _mint_one(block=True)
    for _ in range(400):
        solution = rnd()
        if rng.random() < 0.5 and isinstance(solution, dict):
            solution["instr"] = rnd()
        verify(base, solution, now_ms=rng.randint(0, 2**53))
        verify(_with_meta(base, expires=rnd()), solution, now_ms=0)
        verify(_with_meta(base, vars=rnd(), expectedVals=rnd()), {"instr": rnd()}, now_ms=0)
