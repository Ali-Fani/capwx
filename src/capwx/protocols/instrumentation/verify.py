"""capwx.protocols.instrumentation.verify: port of upstream ``verifyInstrumentationResult``
(``core/src/instrumentation.js``) and of the instrumentation branch of ``validateChallengeV2``
(``core/src/index.js``, plan §8.2 step 7).

Upstream is the spec. Where the upstream code and the plan differ, upstream is followed:

- Arrays are objects in JavaScript (``typeof [] === "object"``), so a list ``state`` or a list
  ``p`` is handled like a dict here (a list ``state`` finds no variables and yields
  ``failed_challenge``; a list ``p`` is passed to ``detect_automation``).
- State values are compared with ``===`` semantics: a bool never matches, an integral float
  such as ``42.0`` matches ``42`` (JSON has no int/float distinction in JavaScript).
- The expiry check is ``expires && now > expires``: a missing or zero ``expires`` never expires.
- Non-object meta / payload give upstream's reasons ``missing_meta`` / ``missing_output``.
  These are not members of ``Reason`` and are returned as plain strings, like ``invalid_meta``.

capwx deviates from upstream in one place: the probe reports ``ce: true`` when the page CSP has no
``'unsafe-eval'`` (it then skips its eval-based environment checks instead of timing out). Such a
result fails with ``instr_csp_eval_blocked`` unless ``instrMeta.allowCspEvalBlocked`` is truthy, in
which case it is accepted with the risk flag ``csp_eval_blocked``. Meta minted by capjs-core lacks the
key, so it stays strict. Only a JSON ``true`` counts as ``ce``.

Nothing in this module raises on client input.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any

from capwx._types import as_json_dict, as_json_list
from capwx.errors import Reason
from capwx.protocols.instrumentation.detect import UNDEF, detect_automation
from capwx.protocols.instrumentation.generator import PROBE_FONT_STACKS

# --- JavaScript value helpers ---------------------------------------------------


def _truthy(v: Any) -> bool:  # JS: !!v
    if v is UNDEF or v is None or v is False:
        return False
    if v is True:
        return True
    if isinstance(v, str):
        return v != ""
    if isinstance(v, (int, float)):
        return v != 0 and not math.isnan(v)  # NaN is falsy
    return True  # objects and arrays


def _is_num(v: Any) -> bool:  # JS: typeof v === "number" (bool is not a number)
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _as_double(v: Any) -> float:  # the IEEE double JavaScript would hold
    try:
        return float(v)
    except OverflowError:
        return float("inf") if v > 0 else float("-inf")


def _strict_eq(a: Any, b: Any) -> bool:  # JS: a === b for JSON-shaped values
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if _is_num(a) and _is_num(b):
        return _as_double(a) == _as_double(b)
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return a is b  # None / UNDEF / object identity


def _get(obj: object, key: str) -> Any:  # JS: obj[key] for a string key
    mapping = as_json_dict(obj)
    if mapping is None:
        return UNDEF
    return mapping.get(key, UNDEF)


def _idx(arr: list[Any], i: int) -> Any:  # JS: arr[i]
    return arr[i] if i < len(arr) else UNDEF


def _is_object(v: Any) -> bool:  # JS: typeof v === "object" && v !== null
    return isinstance(v, (dict, list))


# --- verifyInstrumentationResult ------------------------------------------------

VerifyTuple = tuple[bool, "Reason | str | None", list[str], list[str]]


def verify_instrumentation_result(meta: Any, payload: Any) -> VerifyTuple:
    """Return ``(valid, reason, risk_flags, blocked_by)``; see module docstring for the spec."""
    if not _truthy(meta) or not _is_object(meta):
        return False, "missing_meta", [], []
    if not _truthy(payload) or not _is_object(payload):
        return False, "missing_output", [], []

    if not _strict_eq(_get(payload, "i"), _get(meta, "id")):
        return False, Reason.ID_MISMATCH, [], []

    state = _get(payload, "state")
    if not _is_object(state):
        return False, Reason.INVALID_STATE, [], []

    variables = as_json_list(_get(meta, "vars"))
    expected = as_json_list(_get(meta, "expectedVals"))
    if variables is None or expected is None:
        return False, "invalid_meta", [], []

    matched = all(
        _strict_eq(_get(state, v) if isinstance(v, str) else UNDEF, _idx(expected, i))
        for i, v in enumerate(variables)
    )
    if not matched:
        return False, Reason.FAILED_CHALLENGE, [], []

    csp_flags: list[str] = []
    if _get(payload, "ce") is True:
        if not _truthy(_get(meta, "allowCspEvalBlocked")):
            return False, Reason.INSTR_CSP_EVAL_BLOCKED, [], []
        csp_flags = ["csp_eval_blocked"]

    block = _truthy(_get(meta, "blockAutomatedBrowsers"))
    probe = _get(payload, "p")
    if _is_object(probe):
        vp = _get(payload, "vp")
        vp_list = as_json_list(vp)
        if vp_list is not None and len(vp_list) == 2:
            base = as_json_dict(probe)
            if base is None:  # a JS array: its indices become the keys
                base = {str(i): v for i, v in enumerate(as_json_list(probe) or [])}
            vector: Any = {**base, "innerWH": vp}
        else:
            vector = probe
        d = detect_automation(vector, font_stack_count=len(PROBE_FONT_STACKS))
        blocked_by = list(d["blocked_by"])
        if block and not d["pass"]:
            return False, Reason.INSTR_AUTOMATED_BROWSER, [], blocked_by
        return True, None, [*d["risk_flags"], *csp_flags], blocked_by

    if block:
        return False, Reason.INSTR_PROBE_MISSING, [], []
    return True, None, csp_flags, []


# --- validateChallengeV2 instrumentation branch ---------------------------------


@dataclass(frozen=True)
class InstrVerifyResult:
    valid: bool
    reason: Reason | str | None = None
    risk_flags: list[str] = field(default_factory=list[str])
    blocked_by: list[str] = field(default_factory=list[str])


def verify(
    expected: Any,
    solution: Any,
    *,
    now_ms: int | None = None,
    blocked: bool = False,
    timeout: bool = False,
) -> InstrVerifyResult:
    """Verify one instrumentation solution against its expected entry. Never raises.

    ``expected`` is the decrypted expected entry ``{"protocol": "instrumentation", "instrMeta": {...}}``.
    ``solution`` is the client's solution object. Its ``blocked`` / ``timeout`` flags are OR-ed
    with the keyword flags, which challenge.py sets from the legacy body-level
    ``instr_blocked`` / ``instr_timeout``.
    """
    now = now_ms if _is_num(now_ms) else int(time.time() * 1000)
    meta = _get(expected, "instrMeta")

    if not _truthy(meta):
        return InstrVerifyResult(False, Reason.INSTR_CORRUPTED)

    expires = _get(meta, "expires")
    if _truthy(expires) and _is_num(expires) and now > expires:
        return InstrVerifyResult(False, Reason.INSTR_EXPIRED)

    is_blocked = blocked is True or _get(solution, "blocked") is True
    if is_blocked:
        if _truthy(_get(meta, "blockAutomatedBrowsers")):
            return InstrVerifyResult(False, Reason.INSTR_AUTOMATED_BROWSER)
        return InstrVerifyResult(False, Reason.INSTR_FAILED)

    if timeout is True or _get(solution, "timeout") is True:
        return InstrVerifyResult(False, Reason.INSTR_TIMEOUT)

    instr = _get(solution, "instr")
    if _truthy(instr):
        valid, reason, risk_flags, blocked_by = verify_instrumentation_result(meta, instr)
        if valid:
            return InstrVerifyResult(True, None, risk_flags, blocked_by)
        return InstrVerifyResult(False, reason or Reason.INSTR_FAILED, [], blocked_by)

    return InstrVerifyResult(False, Reason.INSTR_MISSING)


__all__ = ["InstrVerifyResult", "verify", "verify_instrumentation_result"]
