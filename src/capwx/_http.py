"""capwx._http: framework-neutral HTTP mapping shared by the Django, DRF, Ninja and Bolt adapters.

Django-free on purpose: nothing here imports a web framework.
"""

from __future__ import annotations

from capwx.errors import Reason

# Largest accepted request body. Also the default enforced by the Django and Bolt adapters.
MAX_BODY_BYTES = 64 * 1024

# Redeem failures that are instrumentation or session-state problems answer 403.
_FORBIDDEN_REASONS = frozenset(
    {
        Reason.EXPIRED.value,
        Reason.ALREADY_REDEEMED.value,
        Reason.SCOPE_MISMATCH.value,
        Reason.ID_MISMATCH.value,
        Reason.FAILED_CHALLENGE.value,
        "missing_meta",
        "invalid_meta",
    }
)
_SITEVERIFY_STATUS = {"missing_parameters": 400, "invalid_secret": 403, "invalid_token": 400}


def _reason_text(reason: object) -> str:
    return reason.value if isinstance(reason, Reason) else str(reason)


def redeem_status(reason: object) -> int:
    """HTTP status for a failed redeem: 403 for expired/replayed/instrumentation, 500 for store
    outages, 400 for everything else (malformed or invalid input)."""
    text = _reason_text(reason)
    if text == Reason.NONCE_STORE_ERROR.value:
        return 500
    if text in _FORBIDDEN_REASONS or text.startswith("instr_"):
        return 403
    return 400


def siteverify_status(error: str | None) -> int:
    """HTTP status for a failed siteverify, given its ``error`` code (None means unknown)."""
    return _SITEVERIFY_STATUS.get(error or "", 400)
