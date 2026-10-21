"""capwx.protocols.hashwx: HashWX mint/verify and wasmtime engine (M5).

Port of upstream ``core/src/hashwx.js`` (``mintHashwxChallenges``, ``verifyHashwxSolution``).
``verify`` never raises on bad client input; it yields ``False``.

The wasmtime package is imported lazily, on first use, by :func:`_wasmtime`. Importing this module
never loads it, so platforms without a wasmtime wheel can still import capwx and use sha256-pow.
When wasmtime is missing, :func:`mint` and :func:`verify` raise ``CapwxError`` with the fix
(see :func:`missing_wasmtime_message`). Other modules import this one lazily.
"""

from __future__ import annotations

import atexit
import gc
import hashlib
import importlib
import math
import os
import platform
import re
import threading
import weakref
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, TypeGuard, TypeVar

from capwx._types import JsonDict, as_json_dict
from capwx.config import CapConfig
from capwx.errors import CapwxError

if TYPE_CHECKING:  # annotations only; the runtime import is _wasmtime()
    from wasmtime import Engine, Func, Memory, Module, Store

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


def missing_wasmtime_message(cause: BaseException | None = None) -> str:
    """The actionable error text used whenever the wasmtime package cannot be loaded."""
    text = (
        "HashWX needs the `wasmtime` package, which has no wheel for this platform/arch "
        f"({platform.machine()}). Use protocols=('sha256-pow','instrumentation') or install "
        "wasmtime manually."
    )
    if cause is not None:
        text += f" (import failed: {cause})"
    return text


def _wasmtime() -> ModuleType:
    """Return the ``wasmtime`` module, or raise ``CapwxError`` if it cannot be imported.

    The result is not cached on purpose. A successful import is a ``sys.modules`` lookup, and a
    failed import must keep failing, so every call on an unsupported platform gets the same error.
    """
    try:
        return importlib.import_module("wasmtime")
    except Exception as exc:  # a broken native library counts as unavailable too
        raise CapwxError(missing_wasmtime_message(exc)) from exc


def hashwx_available() -> bool:
    """True iff the ``wasmtime`` package imports here, so HashWX can mint and verify.

    Never raises. It does not compile the vendored wasm; :func:`hashwx_ready` still does that.
    """
    try:
        _wasmtime()
    except CapwxError:
        return False
    return True


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


class _ThreadSlot:
    """One thread's instance, or ``None`` until that thread first uses the engine.

    The thread holds the only strong reference, through its ``threading.local``. The engine holds a
    weak one, so :meth:`HashwxEngine.release` can reach every thread's instance at exit without
    keeping a finished thread's instance alive.
    """

    __slots__ = ("__weakref__", "inst")

    def __init__(self) -> None:
        self.inst: _Instance | None = None


class HashwxEngine:
    """Thread-safe: one compiled Module, one Store/Instance per thread."""

    def __init__(self, wasm_path: str | None = None) -> None:
        wt = _wasmtime()
        self._engine: Engine | None = wt.Engine()
        self._module: Module | None = wt.Module(self._engine, _load_wasm_bytes(wasm_path))
        self._local = threading.local()
        self._slots: list[weakref.ref[_ThreadSlot]] = []
        self._slots_lock = threading.Lock()
        _track(self)

    def thread_instance(self) -> _Instance:
        """Return this thread's instance, creating and initialising it on first use."""
        slot: _ThreadSlot | None = getattr(self._local, "slot", None)
        if slot is None:
            slot = _ThreadSlot()
            self._local.slot = slot
            with self._slots_lock:
                self._slots = [ref for ref in self._slots if ref() is not None]
                self._slots.append(weakref.ref(slot))
        inst = slot.inst
        if inst is None:
            inst = self._instantiate()
            slot.inst = inst
        return inst

    def _instantiate(self) -> _Instance:
        wt = _wasmtime()
        engine, module = self._engine, self._module
        if engine is None or module is None:
            raise CapwxError("HashWX engine was released at interpreter exit")
        store: Store = wt.Store(engine)
        exports = wt.Instance(store, module, []).exports(store)
        init = exports.get("_initialize")
        if isinstance(init, wt.Func):
            init(store)
        alloc = _export(exports, "hashwx_alloc", wt.Func)
        ctx = int(alloc(store, HASHWX_INTERPRETED))
        if ctx <= 0:
            raise CapwxError("hashwx_alloc failed")
        seed = _export(exports, "hashwx_seed", wt.Func)
        return _Instance(
            store=store,
            memory=_export(exports, "memory", wt.Memory),
            make=_export(exports, "hashwx_make", wt.Func),
            exec_=_export(exports, "hashwx_exec", wt.Func),
            ctx=ctx,
            seed_ptr=int(seed(store, ctx)),
        )

    def release(self) -> None:
        """Close this engine's wasm objects now, in dependency order. Idempotent.

        The exit hook calls this; programs rarely need it. Stores go first because they reference
        the Engine, then the Module, then the Engine. ``close()`` is wasmtime's own destructor and
        clears its pointer, so a later ``__del__`` does nothing. Using the engine afterwards raises
        ``CapwxError``.
        """
        with self._slots_lock:
            refs = list(self._slots)
        for ref in refs:
            slot = ref()
            if slot is None:
                continue
            inst, slot.inst = slot.inst, None
            if inst is not None:
                inst.store.close()
        module, self._module = self._module, None
        engine, self._engine = self._engine, None
        if module is not None:
            module.close()
        if engine is not None:
            engine.close()

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

# Every engine, including ones built directly with HashwxEngine(), so the exit hook can release
# them all. Weak, so a discarded engine is still freed normally at runtime.
_live: weakref.WeakSet[HashwxEngine] = weakref.WeakSet()
_live_lock = threading.Lock()
_exit_hook_armed = False


def _track(engine: HashwxEngine) -> None:
    """Record ``engine`` for the exit hook. The first call registers the hook."""
    global _exit_hook_armed
    with _live_lock:
        _live.add(engine)
        if not _exit_hook_armed:
            atexit.register(_release_all)
            _exit_hook_armed = True


def _release_all() -> None:
    """atexit hook: free every engine's wasm state while wasmtime is still fully importable.

    Without this, wasmtime's ``Managed.__del__`` finalizers run during interpreter teardown, after
    its module globals are cleared, and print ``'NoneType' object is not callable``. After this
    hook each wasmtime object is closed, so a finalizer that runs later does nothing. Using an
    engine after this hook raises ``CapwxError``; ``get_engine`` then builds a fresh one.
    """
    with _live_lock:
        engines = list(_live)
    for engine in engines:
        engine.release()
    del engines
    with _engines_lock:
        _engines.clear()
    gc.collect()  # finalize any cyclic garbage now, while wasmtime is still importable


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
    """Return ``[(public_payload, expected), ...]`` for ``config.hashwx_challenge_count`` challenges.

    Raises ``CapwxError`` when wasmtime is unavailable. Config is server-controlled, so this is a
    deployment error, and minting challenges the server cannot verify would only fail later.
    """
    _wasmtime()
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

    Malformed input and wasm evaluation failures return False, so client input never raises.
    ``engine`` selects a specific wasm (e.g. ``get_engine(config.hashwx_wasm_path)``); the default
    is the vendored one.

    Raises ``CapwxError`` when wasmtime is unavailable, even for malformed input. The decision is
    deliberate. The check cannot come from client input: ``redeem`` only passes an ``expected``
    entry decrypted from a token the server signed, so a hashwx entry reaches here only if this
    server (or one sharing its secret) minted it. Returning False would reject a correct solution
    and hide the misconfiguration, so the error surfaces instead.
    """
    _wasmtime()
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
