# Spike: native HashWX as a separate shared library

R&D artefact for [issue #4](https://github.com/Ali-Fani/capwx/issues/4), not shipped and not
imported by `capwx`. It compiles the vendored HashWX C sources (`third_party/hashwx`, the same
LGPL-3.0 snapshot that backs `hashwx.wasm`) into one shared library and exports four small
`extern "C"` wrappers so Python can load it with `ctypes`.

Why this shape: it keeps the LGPL component a separate, replaceable binary (as the wasm is today),
keeps the Python side dependency-free, and needs no CPython ABI, so there is no abi3 / free-threaded
/ PyPy wheel matrix. See the measured comparison in
[docs/native-code-evaluation.md](../../../docs/native-code-evaluation.md).

## Build

Needs a C toolchain (MSVC Build Tools on Windows, gcc/clang elsewhere) and Rust:

```bash
HASHWX_SRC="$PWD/third_party/hashwx" cargo build --release \
  --manifest-path benchmarks/spikes/hashwx_native/Cargo.toml
```

The output is in `benchmarks/spikes/hashwx_native/target/release/`: `capwx_hashwx.dll` on Windows,
`libcapwx_hashwx.so` on Linux, `libcapwx_hashwx.dylib` on macOS.

## Compare against the wasm

```bash
uv run python benchmarks/spikes/hashwx_native/compare.py \
  --lib benchmarks/spikes/hashwx_native/target/release/capwx_hashwx.dll
```

It checks 200 random `(seed, nonce)` pairs against the vendored wasm through wasmtime and prints
µs/call for `wasmtime`, native interpreted, native compiled, and compiled `exec`-only. It prints no
tokens or nonces.

## Licensing note

The library links LGPL-3.0 code. Anyone distributing a build must meet the same obligations capwx
already meets for `hashwx.wasm`: ship the corresponding source, keep the binary separate and
replaceable, and let the operator substitute their own build. A future production version would
need an override path (like `CapConfig.hashwx_wasm_path`) and a `NOTICE` update.
