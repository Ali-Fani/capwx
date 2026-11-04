# Native code for capwx: measured evaluation

Decision record for issue #4 ("evaluate Cython / mypyc / PyO3 for speed and portability"). It
records what the server actually spends time on, three spikes with numbers, and a recommendation.
Everything here was measured on one machine; the benchmark suite in `benchmarks/` reproduces the
Python numbers.

## Verdict

1. **Instrumentation generation was the hotspot, not HashWX.** It is now 2.2x faster in pure
   Python (`create_challenge`: 2.65 ms → 1.23 ms median, A/B in one process). No native code
   needed.
2. **mypyc: not worth it.** It compiles cleanly and is 1.5-1.75x faster than the optimized pure
   Python on the generator, but it needs a C toolchain, produces CPython-version-specific wheels
   (`cp314-win_amd64`, not abi3) for a gain that smaller pure-Python changes already matched.
3. **PyO3: works, but the wrong shape.** A PyO3 prototype reproducing HashWX from the vendored C
   sources matches the wasm output exactly and is ~9x faster per verify (18 µs vs 170 µs). The
   same speed is available with **no Python extension at all**: compile the vendored C into a
   standalone shared library and load it with `ctypes`. That keeps the `py3-none-any` wheel (the
   binary is data, per platform, not per Python), needs no abi3/free-threaded/PyPy matrix, and
   keeps the LGPL-3.0 HashWX component a separate, replaceable file.
4. **Recommendation:** keep pure Python as the only Python code path, keep wasmtime as the default
   HashWX engine for now, and open a follow-up for the `ctypes` native HashWX path. The per-call
   gain is real but only matters on hot redeem traffic; the packaging work (per-platform wheels,
   LGPL source offer, cibuildwheel) is the real cost.

## Method and caveats

- Windows 11 x64 (single VM), CPython 3.14.5, wasmtime 49.0.0, `pytest-benchmark` 5.3.1.
  `benchmarks/` uses lower proof-of-work difficulty than production: solving is the browser's job,
  and server-side verification does not depend on the difficulty.
- Numbers are medians. Run-to-run drift on this machine is roughly ±20% (a second full run
  reported 15-30% lower times on benchmarks that were not touched), so before/after claims use an
  interleaved A/B in one process, and cross-run comparisons are treated as indicative only.
- `create_challenge` and `redeem` include the instrumentation protocol where noted, which is the
  default `CAPWX` site (`hashwx` + `instrumentation`). A redeem checks 4 hashwx solutions
  (`hashwx_challenge_count=4`) plus one instrumentation result.
- The wasm engine is warmed up before timing: cold costs are measured separately in
  `benchmarks/cold_start.py`.

## Where the time went (before any change)

`cProfile` of `create_challenge` (30 calls) put the JS-semantics helpers at the top:
183,662 `to_int32` and 68,400 `js_shl` calls, i.e. 6,122 and 2,280 per mint, all from
`hash_with()` hashing the 95 detection markers. A single marker sweep cost 964 µs of the 3.06 ms
mint. Instrumentation assembly and deflate were secondary, and wasmtime was not involved in minting
at all.

Redeem was already cheap: 4 wasm calls at ~170 µs each dominated its 1.06 ms, with JWT/AES-GCM and
instrumentation verification in the remaining ~0.3 ms.

| Path | Before (µs) | After pure-Python work (µs) |
| --- | ---: | ---: |
| `create_challenge` default (hashwx + instrumentation, level 3) | 3,059 | 1,264 |
| `create_challenge` instrumentation only, level 3 | 3,348 | 1,233 |
| `create_challenge` instrumentation only, level 7 | 4,172 | 2,082 |
| `create_challenge` hashwx only | 54 | 52 |
| `create_challenge` sha256-pow only | 74 | 45 |
| `redeem` default (hashwx + instrumentation) | 1,060 | 832 |
| `redeem` hashwx only | 887 | 808 |
| `redeem` instrumentation only | 127 | 108 |
| `redeem` + nonce store + token store | 942 | 847 |
| `validate_token` stateless / stored | 12.7 / 9.4 | 12.5 / 9.9 |
| `siteverify` stateless | 14.1 | 13.8 |
| `generate_instrumentation` level 3 / level 7 | 3,023 / 4,328 | 1,304 / 1,850 |
| `build_client_script` (block checks on / off) | 6,628 / — | 1,398 / 570 |
| `apply_obfuscation` level 3 / level 7 | 76 / 1,377 | 88 / 841 |
| `custom_obfuscate_strings` | 1,294 | 605 |
| `hash_with`, all 95 markers | 964 | 144 |
| HashWX wasm call (warm) | 182 | 156 |
| `HashwxEngine()` cold (module compile) | 13,400 | 7,300 |

The drift caveat applies: the pre/post columns come from two full suite runs, so read the A/B
numbers below as the real speed-up.

## Spike A: pure-Python instrumentation (adopted)

Three changes in `src/capwx/protocols/instrumentation/`:

- `hash_with()` inlines the JS integer helpers and iterates UTF-16 code units directly. The JS
  shifts can be negative, but applying them to the unsigned value differs only by multiples of
  2**32, which the final `>>> 0` discards, so the loop stays in unsigned arithmetic: **6.7x** on a
  marker sweep.
- `custom_obfuscate_strings()` decodes each string literal once and splices replacements by hand,
  instead of running a second regex pass that decoded every literal again: **2.1x** on the level-7
  string table.
- `build_probe()` serialises the font list once instead of 15 times.

Output is unchanged: the 4 test vectors and 805 instrumentation tests pass, and a fixed-RNG
comparison against the old implementations is byte-identical (modulo the random table name, which
comes from `os.urandom`).

Interleaved A/B, 5 rounds, median of medians:

| Case | Before | After | Speed-up |
| --- | ---: | ---: | ---: |
| `create_challenge` (hashwx + instrumentation) | 2.65 ms | 1.23 ms | **2.15x** |
| `generate_instrumentation` level 3 | 2.51 ms | 1.09 ms | **2.30x** |
| `generate_instrumentation` level 7 | 3.80 ms | 1.73 ms | **2.19x** |

What is left in a 1.23 ms mint: about 0.5 ms of random draws (`secrets.SystemRandom` makes one
`os.urandom`-backed draw per character of every variable name and per shuffle), ~0.6 ms of script
assembly, and ~0.15 ms of deflate. The remaining big win would be batching the random draws, which
would change the order of draws the generator documents as matching upstream; that is a
maintainer decision, not a bug fix.

## Spike B: mypyc

Compiled `_jsint.py`, `generator.py` and `obfuscate.py` in a copy of `src/capwx`:

- **Build:** 22.5 s with MSVC Build Tools, one command (`python -m mypyc <modules>`). The full unit
  test set for those modules (805 tests) passes against the compiled build.
- **Artefacts:** 3 modules at 10 KB each plus a 198 KB shared mypyc runtime, tagged
  `cp314-win_amd64` (**not abi3**).
- **Speed vs the optimized pure Python:** `generate_instrumentation` level 3 1.30 ms → 0.74 ms
  (**1.75x**), level 7 1.85 ms → 1.23 ms (**1.5x**), `build_client_script` 1.40 ms → 0.62 ms
  (**2.2x**).
- **Caveat found:** module globals assigned from Python no longer reach compiled code. Setting
  `generator._rng = random.Random(42)` updated the attribute but not the compiled function's
  internal RNG, so two "seeded" runs produced different output. That breaks the documented
  deterministic-RNG hook and any test that patches a compiled module's globals.
- **Cost:** a C toolchain on every build host and in CI, one wheel per CPython version × platform
  (plus PyPy and free-threaded variants), and a second code path to keep in sync. For 1.5-1.75x on
  one protocol, after pure-Python changes already delivered 2.2x, it does not pay for itself.

## Spike C: native HashWX (PyO3 vs a plain shared library)

A PyO3 extension (`pyo3` 0.30.1, `extension-module`, abi3-capable) was built that ties
`hashwx_alloc`/`hashwx_make`/`hashwx_exec` from `third_party/hashwx` into a Python class. A second
build compiled the same C sources into a standalone `cdylib` with four `extern "C"` wrappers,
loaded through `ctypes`. Both were checked against the vendored wasm on 200 random
`(seed, nonce)` pairs; all three agree bit-for-bit.

| Call (make + exec, as `verify()` uses it) | µs/call | Relative |
| --- | ---: | ---: |
| wasmtime + `hashwx.wasm` | 161-172 | 1.0x |
| native, interpreted mode (ctypes) | 29-31 | 5.5x |
| native, compiled mode (PyO3) | 19.5 | ~8.5x |
| native, compiled mode (ctypes) | 18.0-18.5 | **~9x** |
| native, compiled, exec only (`make` hoisted) | 3.6-3.7 | ~48x |

Ranges are repeated runs; the committed spike (`benchmarks/spikes/hashwx_native`) reports the
lower end (160.5 / 28.9 / 18.5 / 3.7 µs). `make` is the expensive part of a compiled call (it JITs
the program from the seed: 18.5 − 3.7 µs). capwx derives a seed per nonce block, so a real verify
pays it per solution; hoisting would only help within one block.

Artefact and dependency size:

| Artefact | Size |
| --- | ---: |
| installed `wasmtime` package | 22.6 MB |
| `hashwx.wasm` | 12.5 KB |
| PyO3 extension (with bindings) | 254 KB |
| plain shared library (ctypes, stripped release build) | 21.5 KB |

Effect on redeem: four hashwx verifications fall from ~650-690 µs to ~75 µs, so a default redeem
goes from ~830 µs to roughly 260 µs. `create_challenge` does not use wasm at all and is unaffected.

## Portability and maintenance, option by option

| Option | Speed | Platforms | Packaging cost | Maintenance |
| --- | --- | --- | --- | --- |
| Pure Python (current) | baseline | every Python 3.10+ platform; HashWX only where wasmtime has a wheel | one `py3-none-any` wheel | lowest |
| mypyc | 1.5-1.75x on generator | CPython only, per version × platform; no PyPy; extra wheel for free-threaded | C toolchain, cibuildwheel matrix | high: compiled semantics differ subtly (globals) |
| PyO3 + vendored C | 9.5x on HashWX verify | abi3 covers 3.10+ on each platform; PyPy and free-threaded need separate builds | Rust + C toolchain, matrix, LGPL boundary inside the extension | high |
| ctypes + shared LGPL library | 9.5x on HashWX verify | one binary per platform, any Python on that platform (PyPy, free-threaded) | per-platform wheels for the binary; loader stays pure Python | medium: keep the LGPL source offer and a replaceable file, as with the wasm today |
| wasmtime (current) | 1.0x | x86-64/ARM64 only; elsewhere no HashWX | none beyond the dependency | lowest |

Platforms gained by the native path: 32-bit x86, armv7, ppc64le, s390x and riscv64 can run the C
in interpreted mode (and x86-64/aarch64 in compiled mode), so HashWX would work where wasmtime has
no wheel. Two wheels are needed per platform (the library plus the universal Python wheel), built
with cibuildwheel. The LGPL-3.0 obligation is the same one capwx already meets for `hashwx.wasm`:
ship the corresponding source (`third_party/hashwx`), keep the binary a separate replaceable file,
and allow the user to point capwx at their own build (`hashwx_wasm_path` today; an override path
for the native library would be the successor).

Cython was not built: the hotspots are string templating and integer loops that the
`hash_with`/obfuscation rewrites already fixed, and Cython has the same per-version wheel cost as
mypyc. Nothing in the measurements suggests a Cython build would beat what pure Python now does
without the packaging or free-threading cost.

## Throughput: is capwx the bottleneck?

In-process FastAPI (httpx ASGI transport, sequential, one worker):

| Route | µs/request | requests/s |
| --- | ---: | ---: |
| `/noop` | 923 | 1,084 |
| `/challenge` (`create_challenge`) | 2,523 | 396 |
| `/redeem` | 1,960 | 510 |

capwx accounts for 63% of a challenge request and 53% of a redeem request on this machine, so it is
a real cost inside a Python framework. In absolute terms ~1.2 ms per challenge is small next to a
network round-trip and far below the timeout budget; one worker still serves ~400 challenges/s.
The transport is in-process, so this measures framework + capwx, not socket or server overhead.

## Follow-ups proposed (not done here)

1. **Native HashWX via `ctypes`** (the recommended shape): build and vendor a per-platform
   `hashwx` shared library, load it lazily with a pure-Python fallback to wasmtime, keep the LGPL
   source offer and the "replaceable file" rule, add the vectors from `tests/vectors/hashwx.json`
   and the Node interop tests as acceptance, and wire the cibuildwheel matrix.
2. **Batch the generator's random draws** (~0.4-0.5 ms of a 1.2 ms mint): decide whether changing
   the draw order is acceptable, since the generator documents it as matching upstream.
3. **Cache/reuse probe fragments** (issue #4 question 3): the probe and environment-check strings
   are largely static; a pool of pre-generated fragments could cut the remaining assembly cost
   without touching upstream semantics.
4. **Track the benchmark baseline**: keep the CI job advisory but store `--benchmark-json` as a
   build artefact so regressions are visible over time.

## Reproducing

```bash
uv sync --group dev --group bench --extra django
uv run pytest benchmarks -q
uv run python benchmarks/profile_mint.py
uv run python benchmarks/cold_start.py
uv run python benchmarks/throughput.py
```

The native spike is in `benchmarks/spikes/hashwx_native/`; it needs a C toolchain and is not part
of the test suite or the wheel.
