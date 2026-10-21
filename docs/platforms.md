# Platforms

capwx has two challenge protocols that behave differently on different CPUs:

- **HashWX** (`hashwx`) runs a wasm engine through the `wasmtime` package. Its default for
  `CapConfig.protocols` is `("hashwx", "instrumentation")`.
- **sha256-pow** (`sha256-pow`) is plain Python on `hashlib`. It runs everywhere.

The `wasmtime` requirement in `pyproject.toml` is gated on the CPU type, so `pip install capwx`
succeeds on every platform. On a CPU without a wasmtime wheel, the package installs without
`wasmtime`, and you must choose protocols that do not need it.

## wasmtime wheel matrix

Checked against `https://pypi.org/pypi/wasmtime/49.0.0/json` (capwx pins `wasmtime>=49,<50`):

| Platform | wasmtime 49.0.0 wheel | HashWX available |
| --- | --- | --- |
| Linux x86_64, glibc | `manylinux1_x86_64` | yes |
| Linux x86_64, musl | `musllinux_1_2_x86_64` | yes |
| Linux aarch64, glibc | `manylinux2014_aarch64` | yes |
| Linux aarch64, musl | `musllinux_1_2_aarch64` | yes |
| macOS x86_64 | `macosx_10_13_x86_64` | yes |
| macOS arm64 | `macosx_11_0_arm64` | yes |
| Windows x64 | `win_amd64` | yes |
| Windows ARM64 | `win_arm64` | yes |
| Android arm64-v8a | `android_26_arm64_v8a` | yes |
| Android x86_64 | `android_26_x86_64` | yes |
| 32-bit x86 (i686), armv7, ppc64le, s390x, other | none listed | no |

PyPI also lists a `py3-none-any` wasmtime 49.0.0 wheel (about 8 MB). It is not a platform wheel
and was not installed or inspected for this document, so the table does not rely on it. On a
platform outside the table, `pip` may pick that wheel. capwx then reports the same
`CapwxError` if `import wasmtime` fails, but whether that wheel imports cleanly is unverified.

The CPU gate in `pyproject.toml` is
`platform_machine in 'x86_64 AMD64 arm64 ARM64 aarch64'`. It is a substring test on the
machine name, and it matches every row above.

## What works without wasmtime

| Feature | Without wasmtime |
| --- | --- |
| `import capwx`, `CapConfig`, `MemoryStore`, `Reason` | yes |
| `create_challenge` / `redeem` / `validate_token` with `sha256-pow` and `instrumentation` | yes |
| `siteverify`, tokens, nonce stores, Django views, Ninja and DRF integrations | yes, as long as no site uses HashWX |
| `create_challenge` with `hashwx` in the protocols | no: raises `CapwxError` |
| `redeem` of a token that carries a `hashwx` entry (minted by another server sharing the secret) | no: raises `CapwxError` |
| Django startup with a site that uses `hashwx` | no: raises `ImproperlyConfigured` |
| `manage.py capwx_check` | HashWX checks are reported as `[skip]` when no site uses HashWX; they fail if one does |

## Choosing protocols

Check at startup with `capwx.hashwx_available()`, which never raises and does not load the wasm:

```python
import capwx

PROTOCOLS = (
    ("hashwx", "instrumentation") if capwx.hashwx_available() else ("sha256-pow", "instrumentation")
)
```

Django settings take the same names in upper case:

```python
CAPWX = {
    "SECRET": env("CAPWX_SECRET"),
    "PROTOCOLS": ["sha256-pow", "instrumentation"],  # no wasmtime on this platform
}
```

The default in `CapConfig` stays HashWX on purpose. A silent fallback to sha256-pow on
unsupported platforms would weaken the challenge without anyone noticing. Opting in is explicit.

If you install wasmtime yourself on a platform without a wheel (for example, built from source),
`hashwx_available()` returns True and HashWX works. capwx does not test that setup.

## Why capwx ships one universal wheel

capwx is pure Python: it has no compiled extension, and the wasm module is data that the Python
code reads at runtime. Its wheel is therefore `py3-none-any`, one file for every platform.

Packages that contain compiled code, such as django-cap, ship one wheel per platform. (That claim
about django-cap was not checked for this document.)
capwx does not need that, because the native code lives in the separate `wasmtime` dependency,
which provides its own platform wheels. That is why the marker above is needed: it controls
whether the native dependency is installed at all.
