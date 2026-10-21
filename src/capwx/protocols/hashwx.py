"""capwx.protocols.hashwx: HashWX mint/verify and wasmtime engine (M5).

Port of upstream ``core/src/hashwx.js`` (``mintHashwxChallenges``, ``verifyHashwxSolution``).
``verify`` never raises on any input; bad input yields ``False``.

The wasmtime import lives here only; other modules import this one lazily.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import TypeGuard, TypeVar

from wasmtime import Engine, Func, Instance, Memory, Module, Store

from capwx._types import JsonDict, as_json_dict
from capwx.config import CapConfig
from capwx.errors import CapwxError

PROTOCOL = "hashwx"
U64_MAX = (1 << 64) - 1
CHALLENGE_SIZE = 32  # bytes of the challenge ``c`` (64 hex chars)
SEED_SIZE = 32  # bytes written into wasm memory per evaluation
HASHWX_INTERPRETED = 0  # hashwx_alloc mode argument

MAX_NONCES_PER_HASH = 1_048_576
MAX_HASHWX_DIFFICULTY = 1_000_000_000  # same as CapConfig.hashwx_difficulty's upper bound
MAX_SAFE_INT = 2**53 - 1

_C_RE = re.compile(r"[0-9a-fA-F]{64}")
_NONCE_STR_RE = re.compile(r"[0-9]{1,20}")  # ASCII digits only; fullmatch rejects trailing "\n"

_VENDOR_PACKAGE = "capwx._vendor.hashwx"
_VENDOR_WASM = "hashwx.wasm"
_VENDOR_SHA256 = "SHA256"

_T = TypeVar("_T")


def _read_vendored_wasm() -> bytes:
    """Return the bytes of the vendored wasm (separate function so tests can tamper with it)."""
    return resources.files(_VENDOR_PACKAGE).joinpath(_VENDOR_WASM).read_bytes()


def _vendored_sha256() -> str:
    """Expected sha256 hex of the vendored wasm, from ``_vendor/hashwx/SHA256``."""
    text = resources.files(_VENDOR_PACKAGE).joinpath(_VENDOR_SHA256).read_text(encoding="ascii")
    return text.split()[0].lower()


def _load_wasm_bytes(wasm_path: str | None) -> bytes:
    if wasm_path is None:
        data = _read_vendored_wasm()
        if hashlib.sha256(data).hexdigest() != _vendored_sha256():
            raise CapwxError("vendored hashwx.wasm does not match _vendor/hashwx/SHA256")
        return data
    try:
        return Path(wasm_path).read_bytes()
    except OSError as exc:
        raise CapwxError(f"cannot read hashwx_wasm_path: {exc}") from exc


def _export(exports: Mapping[str, object], name: str, kind: type[_T]) -> _T:
    """Return the wasm export ``name`` if it has the expected wasmtime type, else raise."""
    item = exports.get(name)
    if not isinstance(item, kind):
        raise CapwxError(f"hashwx.wasm has no {kind.__name__} export named {name!r}")
    return item


@dataclass(frozen=True)
class _Instance:
    """One wasm instance and the context allocated in it (one per thread)."""

    store: Store
    memory: Memory
    make: Func
    exec_: Func
    ctx: int
    seed_ptr: int


class HashwxEngine:
    """Thread-safe: one compiled Module, one Store/Instance per thread."""

    def __init__(self, wasm_path: str | None = None) -> None:
        self._engine = Engine()
        self._module = Module(self._engine, _load_wasm_bytes(wasm_path))
        self._local = threading.local()

    def thread_instance(self) -> _Instance:
        """Return this thread's instance, creating and initialising it on first use."""
        inst: _Instance | None = getattr(self._local, "inst", None)
        if inst is None:
            store = Store(self._engine)
            exports = Instance(store, self._module, []).exports(store)
            init = exports.get("_initialize")
            if isinstance(init, Func):
                init(store)
            alloc = _export(exports, "hashwx_alloc", Func)
            ctx = int(alloc(store, HASHWX_INTERPRETED))
            if ctx <= 0:
                raise CapwxError("hashwx_alloc failed")
            seed = _export(exports, "hashwx_seed", Func)
            inst = _Instance(
                store=store,
                memory=_export(exports, "memory", Memory),
                make=_export(exports, "hashwx_make", Func),
                exec_=_export(exports, "hashwx_exec", Func),
                ctx=ctx,
                seed_ptr=int(seed(store, ctx)),
            )
            self._local.inst = inst
        return inst

    def hash(self, seed: bytes, nonce: int) -> int:
        """Return the 64-bit HashWX value for ``nonce`` under a 32-byte ``seed``."""
        if len(seed) != SEED_SIZE:
            raise CapwxError("hashwx seed must be 32 bytes")
        inst = self.thread_instance()
        inst.memory.write(inst.store, seed, inst.seed_ptr)
        inst.make(inst.store, inst.ctx, inst.seed_ptr)
        signed = nonce - (1 << 64) if nonce >= (1 << 63) else nonce  # wasm i64 is signed
        return int(inst.exec_(inst.store, inst.ctx, signed)) & U64_MAX


_engines: dict[str, HashwxEngine] = {}
_engines_lock = threading.Lock()
_VENDORED_KEY = ""


def get_engine(wasm_path: str | None = None) -> HashwxEngine:
    """Return the cached engine for the vendored wasm (or for ``wasm_path``, cached per path)."""
    key = _VENDORED_KEY if wasm_path is None else os.path.abspath(wasm_path)
    with _engines_lock:
        engine = _engines.get(key)
        if engine is None:
            engine = HashwxEngine(wasm_path)
            _engines[key] = engine
        return engine


def hashwx_ready(wasm_path: str | None = None) -> None:
    """Force engine construction and per-thread instance initialisation. Call at app startup.

    Raises ``CapwxError`` if the wasm is missing, tampered with, or cannot be instantiated.
    """
    get_engine(wasm_path).thread_instance()


def _js_round(x: float) -> int:
    """JavaScript ``Math.round`` for non-negative values: halves round up, not to even."""
    return math.floor(x + 0.5)


def mint(config: CapConfig) -> list[tuple[JsonDict, JsonDict]]:
    """Return ``[(public_payload, expected), ...]`` for ``config.hashwx_challenge_count`` challenges."""
    each = max(1, _js_round(config.hashwx_difficulty / config.hashwx_challenge_count))
    out: list[tuple[JsonDict, JsonDict]] = []
    for _ in range(config.hashwx_challenge_count):
        spec: JsonDict = {
            "c": os.urandom(CHALLENGE_SIZE).hex(),
            "d": each,
            "n": config.hashwx_nonces_per_hash,
        }
        payload = dict(spec)
        expected: JsonDict = {"protocol": PROTOCOL, **spec}
        out.append((payload, expected))
    return out


def _parse_nonce(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value <= MAX_SAFE_INT else None
    if isinstance(value, str) and _NONCE_STR_RE.fullmatch(value) is not None:
        parsed = int(value)
        return parsed if parsed <= U64_MAX else None
    return None


def _valid_int(value: object, lo: int, hi: int | None) -> TypeGuard[int]:
    if isinstance(value, bool) or not isinstance(value, int) or value < lo:
        return False
    return hi is None or value <= hi


def verify(expected: object, solution: object, *, engine: HashwxEngine | None = None) -> bool:
    """True iff ``solution["nonce"]`` hashes to at most ``U64_MAX // d`` for the challenge.

    Never raises: any malformed input or engine failure returns False. ``engine`` selects a
    specific wasm (e.g. ``get_engine(config.hashwx_wasm_path)``); default is the vendored one.
    """
    try:
        exp = as_json_dict(expected)
        sol = as_json_dict(solution)
        if exp is None or sol is None:
            return False
        c = exp.get("c")
        if not isinstance(c, str) or _C_RE.fullmatch(c) is None:
            return False
        n = exp.get("n")
        d = exp.get("d")
        if not _valid_int(n, 1, MAX_NONCES_PER_HASH) or not _valid_int(d, 1, MAX_HASHWX_DIFFICULTY):
            return False
        if "nonce" not in sol:
            return False
        nonce = _parse_nonce(sol["nonce"])
        if nonce is None:
            return False

        target = U64_MAX // d
        block = nonce // n
        seed = hashlib.sha256(bytes.fromhex(c) + block.to_bytes(8, "little")).digest()
        eng = engine if engine is not None else get_engine()
        return eng.hash(seed, nonce) <= target
    except Exception:  # noqa: BLE001 - verify must never raise on client input
        return False
