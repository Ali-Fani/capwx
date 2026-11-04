# Benchmarks

Benchmarks for the server-side cost of capwx: mint, redeem, token validation, and the pieces they
are built from. They are **not** part of the unit suite (`testpaths = ["tests"]`); run them
explicitly.

```bash
uv sync --group dev --group bench --extra django
uv run pytest benchmarks -q
```

Useful flags: `--benchmark-columns=mean,median,stddev,ops` for calls per second (direct Python calls, no HTTP; see `throughput.py` for routes),
`--benchmark-max-time=2` to budget time per benchmark, `-k <name>` to run one case.

The bench configs use a much lower proof-of-work difficulty than production
(`hashwx_difficulty=400`, `sha256_difficulty=1`, fewer sha256 challenges). Solving is the
browser's job, and server-side verification cost does not depend on the difficulty, so a hard
challenge would only make the suite slow. Cold costs (imports, wasm compile, first hash) are
measured separately because a warm pytest process hides them.

## What is here

| File | Measures |
| --- | --- |
| `test_bench_challenge.py` | `create_challenge`, `redeem` (per protocol set, with and without stores), `issue_token`, `validate_token`, `siteverify` |
| `test_bench_internals.py` | instrumentation pipeline stages, obfuscation, JS-semantics helpers, one HashWX wasm call, HashWX verify, cold engine build |
| `profile_mint.py` | stage breakdown plus `cProfile` top functions for mint, redeem and instrumentation |
| `cold_start.py` | fresh-process import costs, wasm engine compile, first instance and first hash |
| `throughput.py` | per-request cost of `/challenge` and `/redeem` next to a no-op FastAPI route |
| `spikes/hashwx_native/` | Rust crate that builds the vendored HashWX C sources as a shared library, plus a `ctypes` comparison against the wasm |
| `conftest.py` | configs, solved bodies (via `tests/_solver.py`), warm-engine setup |

## Baseline

The recorded baseline, the profile attribution, the three native-code spikes and their numbers are
in [docs/native-code-evaluation.md](../docs/native-code-evaluation.md). Headline medians on
CPython 3.14 / Windows x64: `create_challenge` ~1.2 ms, `redeem` ~0.8 ms, `validate_token` ~13 µs.

Benchmarks on one machine are noisy (±20% run to run). Compare branches by running both in the
same session, and prefer medians over means.

## CI

`.github/workflows/ci.yml` runs this suite on Linux on every push and pull request, with
`continue-on-error: true`: it reports, it does not block. Nothing here needs a browser, a network
socket, Redis, or a Rust toolchain; the native spike is never built by CI.
