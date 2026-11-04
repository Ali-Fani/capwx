"""Compare a native HashWX build with the vendored wasm, and time both.

Build the library first (from this directory):

    HASHWX_SRC=<checkout>/third_party/hashwx cargo build --release --manifest-path benchmarks/spikes/hashwx_native/Cargo.toml

Then run this script from the repository root, pointing at the built library:

    uv run python benchmarks/spikes/hashwx_native/compare.py --lib <path to capwx_hashwx.dll|.so>

The script checks equality against the wasm on random ``(seed, nonce)`` pairs, then reports
microseconds per call for: wasmtime (make + exec), native interpreted, native compiled, and
compiled exec-only. It prints no tokens or nonces.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import random
import statistics
import time
from collections.abc import Callable
from pathlib import Path

INTERPRETED = 0
COMPILED = 1
PAIRS = 200
CALLS = 20_000


def load(path: Path) -> ctypes.CDLL:
    lib = ctypes.CDLL(str(path))
    lib.capwx_hashwx_alloc.restype = ctypes.c_void_p
    lib.capwx_hashwx_alloc.argtypes = [ctypes.c_int32]
    lib.capwx_hashwx_make.restype = None
    lib.capwx_hashwx_make.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.capwx_hashwx_exec.restype = ctypes.c_uint64
    lib.capwx_hashwx_exec.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
    lib.capwx_hashwx_free.restype = None
    lib.capwx_hashwx_free.argtypes = [ctypes.c_void_p]
    return lib


def allocate(lib: ctypes.CDLL, kind: int) -> ctypes.c_void_p:
    ctx = lib.capwx_hashwx_alloc(kind)
    if not ctx or ctx == ctypes.c_void_p(-1).value:
        raise SystemExit(f"hashwx_alloc({kind}) failed: compiled mode may be unsupported here")
    return ctypes.c_void_p(ctx)


def median_us(fn, calls: int = CALLS) -> float:
    for i in range(200):  # warm-up
        fn(i)
    samples = []
    for _ in range(5):
        started = time.perf_counter()
        for i in range(calls):
            fn(i)
        samples.append((time.perf_counter() - started) / calls * 1e6)
    return statistics.median(samples)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lib", required=True, type=Path, help="built capwx_hashwx library")
    args = parser.parse_args()

    from capwx.protocols import hashwx  # imported late: needs the editable install

    lib = load(args.lib)
    interpreted = allocate(lib, INTERPRETED)
    compiled = allocate(lib, COMPILED)
    engine = hashwx.get_engine()
    rng = random.Random(4)

    for i in range(PAIRS):
        seed = hashlib.sha256(f"spike-{i}".encode()).digest()
        nonce = rng.randrange(0, 2**64)
        expected = engine.hash(seed, nonce)
        for ctx in (interpreted, compiled):
            lib.capwx_hashwx_make(ctx, ctypes.c_char_p(seed))
            assert lib.capwx_hashwx_exec(ctx, nonce) == expected, (i, ctx)
    print(f"{PAIRS} random (seed, nonce) pairs: native interpreted and compiled match the wasm")

    seed = hashlib.sha256(b"bench").digest()

    def wasm_call(i: int) -> int:
        return engine.hash(seed, i)

    def native_call(ctx: ctypes.c_void_p) -> Callable[[int], int]:
        def call(i: int) -> int:
            lib.capwx_hashwx_make(ctx, ctypes.c_char_p(seed))
            return lib.capwx_hashwx_exec(ctx, i)

        return call

    lib.capwx_hashwx_make(interpreted, ctypes.c_char_p(seed))
    lib.capwx_hashwx_make(compiled, ctypes.c_char_p(seed))
    results = {
        "wasmtime (make + exec)": median_us(wasm_call),
        "native interpreted (make + exec)": median_us(native_call(interpreted)),
        "native compiled (make + exec)": median_us(native_call(compiled)),
        "native compiled (exec only)": median_us(lambda i: lib.capwx_hashwx_exec(compiled, i)),
    }
    lib.capwx_hashwx_free(interpreted)
    lib.capwx_hashwx_free(compiled)

    print()
    print("| Call | us/call |")
    print("|---|---|")
    for name, us in results.items():
        print(f"| {name} | {us:.2f} |")


if __name__ == "__main__":
    main()
