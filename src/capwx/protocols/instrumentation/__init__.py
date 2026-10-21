"""capwx.protocols.instrumentation: mint() (M6) and verify() / verify_instrumentation_result() (M7).

``mint`` produces the public payload ``{"blob": ...}`` and the expected entry
``{"protocol": "instrumentation", "instrMeta": {...}}`` with camelCase keys, so tokens
interoperate with ``capjs-core``.
"""

from __future__ import annotations

from capwx._types import JsonDict
from capwx.config import CapConfig
from capwx.errors import CapwxError
from capwx.protocols.instrumentation.generator import generate_instrumentation
from capwx.protocols.instrumentation.verify import (
    InstrVerifyResult,
    verify,
    verify_instrumentation_result,
)

__all__ = [
    "InstrVerifyResult",
    "mint",
    "verify",
    "verify_instrumentation_result",
]


def _check_expires_ms(value: object) -> None:
    if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
        raise CapwxError("expires_ms must be an int or None")


def mint(config: CapConfig, *, expires_ms: int | None = None) -> list[tuple[JsonDict, JsonDict]]:
    """Return ``[(public_payload, expected)]`` for one instrumentation challenge.

    Reads ``config.instrumentation.block_automated_browsers`` and ``.obfuscation_level``.
    ``config.instrumentation.enabled`` is not consulted here: the protocol list in
    ``config.protocols`` decides whether this runs. ``instrMeta.expires`` is a placeholder
    unless ``expires_ms`` is given; challenge.py overwrites it with the challenge expiry.
    """
    _check_expires_ms(expires_ms)

    opts = config.instrumentation
    gen = generate_instrumentation(
        {
            "block_automated_browsers": opts.block_automated_browsers,
            "obfuscation_level": opts.obfuscation_level,
            "ttl_ms": config.challenge_ttl_ms,
        }
    )
    expires = gen["expires"] if expires_ms is None else expires_ms
    meta = {
        "id": gen["id"],
        "expectedVals": gen["expected_vals"],
        "vars": gen["vars"],
        "blockAutomatedBrowsers": gen["block_automated_browsers"],
        "expires": expires,
    }
    return [({"blob": gen["blob"]}, {"protocol": "instrumentation", "instrMeta": meta})]
