"""capwx: a Python server for the Cap CAPTCHA widget (HashWX, sha256-pow, instrumentation).

Importing ``capwx`` never imports wasmtime. The HashWX engine loads on first use, or eagerly via
:func:`hashwx_ready` at application startup.
"""

from __future__ import annotations

from capwx.challenge import (
    RedeemResult,
    acreate_challenge,
    aredeem,
    create_challenge,
    redeem,
    set_event_callback,
)
from capwx.config import CapConfig, InstrumentationOptions
from capwx.errors import CapwxError, Reason
from capwx.stores.memory import MemoryStore
from capwx.tokens import avalidate_token, siteverify, validate_token

__version__ = "0.1.0"


def hashwx_ready(wasm_path: str | None = None) -> None:
    """Force HashWX engine initialisation (imports wasmtime). Call at application startup.

    Raises ``CapwxError`` if wasmtime is unavailable, the vendored wasm is missing, tampered with,
    or cannot be instantiated.
    """
    from capwx.protocols.hashwx import hashwx_ready as _ready

    _ready(wasm_path)


def hashwx_available() -> bool:
    """True iff the wasmtime package can be imported, so HashWX challenges can run here.

    Use it at startup to choose protocols, for example ``("sha256-pow", "instrumentation")`` when
    it returns False. Never raises, and it does not load the wasm.
    """
    from capwx.protocols.hashwx import hashwx_available as _available

    return _available()


__all__ = [
    "CapConfig",
    "CapwxError",
    "InstrumentationOptions",
    "MemoryStore",
    "Reason",
    "RedeemResult",
    "__version__",
    "acreate_challenge",
    "aredeem",
    "avalidate_token",
    "create_challenge",
    "hashwx_available",
    "hashwx_ready",
    "redeem",
    "set_event_callback",
    "siteverify",
    "validate_token",
]
