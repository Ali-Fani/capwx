"""capwx.config: CapConfig and InstrumentationOptions dataclasses.

All bounds are checked in ``__post_init__`` and raise ``CapwxError``. ``bool`` is
rejected wherever an int is expected (``True`` is an ``int`` in Python).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import cast

from capwx.errors import CapwxError

KNOWN_PROTOCOLS = ("hashwx", "sha256-pow", "instrumentation")
MIN_SECRET_BYTES = 16


def _check_int(name: str, value: object, lo: int, hi: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not (lo <= value <= hi):
        raise CapwxError(f"{name} must be an integer in [{lo}, {hi}]")


def _check_bool(name: str, value: object) -> None:
    if not isinstance(value, bool):
        raise CapwxError(f"{name} must be a bool")


def _check_secret(secret: object) -> None:
    if isinstance(secret, str):
        size = len(secret.encode("utf-8"))
    elif isinstance(secret, bytes):
        size = len(secret)
    else:
        raise CapwxError("secret must be a str or bytes")
    if size < MIN_SECRET_BYTES:
        raise CapwxError(f"secret must be at least {MIN_SECRET_BYTES} bytes")


def _check_instrumentation(value: object) -> None:
    if not isinstance(value, InstrumentationOptions):
        raise CapwxError("instrumentation must be an InstrumentationOptions instance")


def _check_wasm_path(value: object) -> None:
    if value is not None and not isinstance(value, str):
        raise CapwxError("hashwx_wasm_path must be a str or None")


def _protocol_names(value: object) -> tuple[str, ...] | None:
    """The protocol names if ``value`` is a non-empty tuple of unique known names, else None."""
    if not isinstance(value, tuple) or not value:
        return None
    items = cast("tuple[object, ...]", value)
    if not all(isinstance(p, str) and p in KNOWN_PROTOCOLS for p in items):
        return None
    if len(set(items)) != len(items):
        return None
    return cast("tuple[str, ...]", items)


@dataclass(frozen=True)
class InstrumentationOptions:
    enabled: bool = True
    block_automated_browsers: bool = False
    obfuscation_level: int = 3  # 1..10; >7 clamped to 7 with a warning
    # A page CSP without 'unsafe-eval' makes the probe skip its eval-based checks and report it.
    # Strict by default: the server then fails the challenge with ``instr_csp_eval_blocked``.
    allow_csp_eval_blocked: bool = False

    def __post_init__(self) -> None:
        _check_bool("instrumentation.enabled", self.enabled)
        _check_bool("instrumentation.block_automated_browsers", self.block_automated_browsers)
        _check_int("instrumentation.obfuscation_level", self.obfuscation_level, 1, 10)
        _check_bool("instrumentation.allow_csp_eval_blocked", self.allow_csp_eval_blocked)


@dataclass(frozen=True)
class CapConfig:
    secret: str | bytes = field(repr=False)  # >= 16 bytes, else CapwxError; never in repr()
    # The default stays HashWX. A platform without a wasmtime wheel must opt into
    # ("sha256-pow", "instrumentation") explicitly, because a silent fallback would weaken the
    # challenge without anyone noticing. See docs/platforms.md and ``capwx.hashwx_available()``.
    protocols: tuple[str, ...] = ("hashwx", "instrumentation")  # also "sha256-pow"
    hashwx_difficulty: int = 1_000_000  # 1..1_000_000_000
    hashwx_challenge_count: int = 4  # 1..64
    hashwx_nonces_per_hash: int = 65_536  # 1..1_048_576
    sha256_count: int = 50  # 1..1000
    # Salt bytes -> 2*size hex chars. The browser's wasm sha256 solver only matches messages under
    # 56 bytes (salt + decimal nonce), so a longer salt makes it spin forever. 16 bytes keeps
    # salt + a 9-digit nonce under that limit. Upstream's 32 bytes hangs in the widget's wasm path.
    sha256_size: int = 16  # 1..256
    sha256_difficulty: int = 4  # hex prefix length 1..16
    challenge_ttl_ms: int = 10 * 60 * 1000
    token_ttl_ms: int = 20 * 60 * 1000  # verification token lifetime
    instrumentation: InstrumentationOptions = InstrumentationOptions()
    hashwx_wasm_path: str | None = None  # override vendored LGPL wasm

    def __post_init__(self) -> None:
        _check_secret(self.secret)

        # The fields are typed, but these checks run on whatever the caller (often Django
        # settings, which are untyped) passed in, so the values are re-read as ``object``.
        raw_protocols: object = self.protocols
        if isinstance(raw_protocols, list):
            raw_protocols = tuple(raw_protocols)
            object.__setattr__(self, "protocols", raw_protocols)
        if _protocol_names(raw_protocols) is None:
            raise CapwxError(
                "protocols must be a non-empty tuple of unique names from "
                + ", ".join(KNOWN_PROTOCOLS)
            )

        _check_int("hashwx_difficulty", self.hashwx_difficulty, 1, 1_000_000_000)
        _check_int("hashwx_challenge_count", self.hashwx_challenge_count, 1, 64)
        _check_int("hashwx_nonces_per_hash", self.hashwx_nonces_per_hash, 1, 1_048_576)
        _check_int("sha256_count", self.sha256_count, 1, 1000)
        _check_int("sha256_size", self.sha256_size, 1, 256)
        _check_int("sha256_difficulty", self.sha256_difficulty, 1, 16)
        _check_int("challenge_ttl_ms", self.challenge_ttl_ms, 1, 2**53 - 1)
        _check_int("token_ttl_ms", self.token_ttl_ms, 1, 2**53 - 1)

        _check_instrumentation(self.instrumentation)
        _check_wasm_path(self.hashwx_wasm_path)
