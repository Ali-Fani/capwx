"""capwx.protocols.sha256_pow: sha256-pow mint/verify (port of upstream ``sha256-pow`` branch).

Upstream: ``generateChallengeV2`` / ``validateChallengeV2`` in ``core/src/index.js``.
``verify`` never raises on any input; bad input yields ``False``.
"""

from __future__ import annotations

import hashlib
import re

from capwx._crypto import random_hex
from capwx._types import JsonDict, as_json_dict
from capwx.config import CapConfig

PROTOCOL = "sha256-pow"
_MAX_SAFE_INT = 2**53 - 1
_NONCE_STR_RE = re.compile(r"[0-9]{1,16}")  # ASCII digits only; fullmatch rejects trailing "\n"
_TARGET_RE = re.compile(r"[0-9a-fA-F]{1,16}")  # the CapConfig.sha256_difficulty range, as hex


def mint(config: CapConfig) -> list[tuple[JsonDict, JsonDict]]:
    """Return ``[(public_payload, expected), ...]`` for ``config.sha256_count`` challenges."""
    target = "0" * config.sha256_difficulty
    out: list[tuple[JsonDict, JsonDict]] = []
    for _ in range(config.sha256_count):
        salt = random_hex(config.sha256_size)
        payload: JsonDict = {"salt": salt, "target": target}
        expected: JsonDict = {"protocol": PROTOCOL, "salt": salt, "target": target}
        out.append((payload, expected))
    return out


def _nonce_text(nonce: object) -> str | None:
    """Return the exact text that is hashed after the salt, or None if the nonce is invalid."""
    if isinstance(nonce, bool):
        return None
    if isinstance(nonce, int):
        if 0 <= nonce <= _MAX_SAFE_INT:
            return str(nonce)
        return None
    if isinstance(nonce, str) and _NONCE_STR_RE.fullmatch(nonce) is not None:
        return nonce
    return None


def verify(expected: object, solution: object) -> bool:
    """True iff ``solution["nonce"]`` makes ``sha256(salt + nonce)`` start with ``target``.

    Never raises: any malformed input (wrong types, missing keys, bad nonce) returns False.
    """
    try:
        exp = as_json_dict(expected)
        sol = as_json_dict(solution)
        if exp is None or sol is None:
            return False
        salt = exp["salt"]
        target = exp["target"]
        if not isinstance(salt, str) or not isinstance(target, str):
            return False
        if _TARGET_RE.fullmatch(target) is None:  # bounds the work a verify can ask for
            return False
        if "nonce" not in sol:
            return False
        nonce_text = _nonce_text(sol["nonce"])
        if nonce_text is None:
            return False
        digest_hex = hashlib.sha256((salt + nonce_text).encode("utf-8")).hexdigest()
        return digest_hex.startswith(target.lower())
    except Exception:  # noqa: BLE001 - verify must never raise on client input
        return False
