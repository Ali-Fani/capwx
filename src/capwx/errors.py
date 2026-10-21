"""capwx.errors: Reason enum and CapwxError.

Reasons are part of the public API (apps branch on them; logs/metrics use them).
Client input never raises: functions return result objects carrying a reason.
Only programmer/configuration errors raise CapwxError.
"""

import enum


class Reason(str, enum.Enum):
    INVALID_BODY = "invalid_body"
    MISSING_TOKEN = "missing_token"
    MISSING_SOLUTIONS = "missing_solutions"
    INVALID_TOKEN = "invalid_token"
    SCOPE_MISMATCH = "scope_mismatch"
    EXPIRED = "expired"
    INVALID_SOLUTIONS = "invalid_solutions"  # wrong length / shape
    INVALID_SOLUTION = "invalid_solution"  # a solution fails verification
    ALREADY_REDEEMED = "already_redeemed"
    NONCE_STORE_ERROR = "nonce_store_error"
    INSTR_CORRUPTED = "instr_corrupted"
    INSTR_EXPIRED = "instr_expired"
    INSTR_MISSING = "instr_missing"
    INSTR_TIMEOUT = "instr_timeout"
    INSTR_FAILED = "instr_failed"
    INSTR_AUTOMATED_BROWSER = "instr_automated_browser"
    INSTR_PROBE_MISSING = "instr_probe_missing"
    ID_MISMATCH = "id_mismatch"
    INVALID_STATE = "invalid_state"
    FAILED_CHALLENGE = "failed_challenge"


class CapwxError(Exception):
    """Raised only for programmer/config errors (bad secret, bad params). Never for bad client input."""
