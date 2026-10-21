# `capwx` — a Python server for the Cap CAPTCHA widget (HashWX + instrumentation)

Build plan for a **standalone, pip-publishable** Python library that lets any
Python web app (Django first, framework-agnostic core) serve and verify
[Cap](https://github.com/tiagozip/cap) challenges **in-process**, with the two
features no existing Python package supports: **HashWX** (GPU-resistant
proof-of-work) and **instrumentation challenges** (headless-browser detection).

Written so that a less capable model can implement it step by step: every
milestone has exact file names, function signatures, byte layouts, test
vectors and a "done when" check. **Do the milestones in order. Do not skip
the tests.** When this plan and your intuition disagree, this plan wins; when
this plan and the upstream source disagree, upstream wins — stop and report.

---

## 0. Background and decisions (read once)

### 0.1 What Cap is

Cap = a browser **widget** (`<cap-widget>`, npm `cap-widget`) + a **server**
that issues challenges and verifies solutions. The official server is
JavaScript (`capjs-core`, used by "Cap Standalone"). The widget talks to the
server over two HTTP endpoints:

```
POST {endpoint}challenge   (no body)          → challenge JSON
POST {endpoint}redeem      {token, solutions} → {success, token, expires}
```

After `redeem` succeeds the widget holds a short-lived **verification token**
(`cap-token` hidden form field / `solve` event). The app's form handler then
**validates** that token server-side (single use).

### 0.2 Why a new package

| Package | HashWX | Instrumentation | Notes |
|---|---|---|---|
| `capjs-core` (official, JS) | yes | yes | Node only |
| `capjs-server` (PyPI, vshn, 0.2.1) | no | no | SHA-256 only; good ideas: stateless HMAC, pluggable nonce store, Django extra |
| `django-cap` (PyPI, Somiona, 0.3.0, last release 2025-08) | no | no | SHA-256 only; good ideas: Ninja router, Django form field |

`capwx` = a faithful Python port of `capjs-core`'s **format-2** protocol
(the one the widget uses for HashWX), plus the good ideas above.

### 0.3 Upstream pins (the reference implementation)

Everything in this plan was checked against these exact versions. Pin them in
`UPSTREAM.md` in the new repo.

| Thing | Version / commit |
|---|---|
| `tiagozip/cap` repo | commit `29bbe6fbe284786cdb0d4489e5040aee6042b2a4` |
| `capjs-core` (npm) | `0.1.5` — files `core/src/{index,crypto,hashwx,instrumentation,detect,prng}.js` |
| `cap-widget` (npm) | `0.1.58` |
| `@cap.js/wasm` (npm, browser solver wasm) | `0.0.8` (Apache-2.0) |
| `pako` (widget's inflate fallback) | `2.1.0` |
| `tevador/hashwx` | commit `74b567a31276a4c5d7cb232a5b7639467f49f961`, **LGPL-3.0** |
| server `hashwx.wasm` | from `core/vendor/hashwx.wasm`, 12 541 bytes, sha256 `b1a0dbb3ef444d3c7069e0a5e0a0273ffa4cf8fef62cbbe43761c02f7cd6aff5` |
| `wasmtime` (PyPI) | `>=49,<50` (49.0.0 verified) |

### 0.4 Key decisions

1. **Name**: distribution `capwx`, import package `capwx`. (Free on PyPI as of
   2026-10-21; re-check before first publish.) README must say "unofficial,
   not affiliated with Cap".
2. **Licence**: our code **Apache-2.0** (same as Cap). The vendored
   `hashwx.wasm` stays **LGPL-3.0**, shipped as a *separate file* with its
   licence, source commit and build notes, loadable from a user-supplied path
   (that is what keeps the LGPL "replaceable component" condition easy). Do
   **not** port HashWX's C code to Python — that would make that module LGPL.
3. **HashWX engine**: run the vendored wasm with **`wasmtime`** (required
   dependency). Proven: it reproduces tevador's official test vectors and costs
   ~175 µs per verification in CPython.
4. **Protocols**: implement format 2 only, with `sha256-pow`, `hashwx`,
   `instrumentation`. **Skip** `rsw` (deprecated upstream) and format 1.
5. **Instrumentation obfuscation**: support levels 1–7 natively in Python
   (whitespace strip, string-table indirection). Levels 8–10 need
   `javascript-obfuscator` (Node) → clamp to 7 and log a warning once.
   No esbuild minification (Python can't run it); level 4–7 output is just
   unminified — functionally identical.
6. **Stateless core**: challenge tokens are HMAC-signed JWTs; expected answers
   are AES-GCM-encrypted inside the token. Storage is only needed for
   (a) replay protection and (b) single-use verification tokens — both behind
   small pluggable store interfaces.
7. **Python**: support 3.10–3.14. Zero runtime deps except `wasmtime` and
   `cryptography`. Framework integrations are extras.
8. **Sync core**, with thin `async` wrappers (`asyncio.to_thread` not needed —
   operations are sub-millisecond; async wrappers just call sync code, but
   stores may be async).

---

## 1. Repository layout

Create a new repo (not inside django-next). Use `uv` and `hatchling`.

```
capwx/
├── pyproject.toml
├── README.md
├── LICENSE                         # Apache-2.0 (full text)
├── NOTICE                          # attribution to Cap (Apache-2.0) and HashWX (LGPL-3.0)
├── UPSTREAM.md                     # §0.3 table + how to re-sync
├── CHANGELOG.md
├── SECURITY.md
├── src/capwx/
│   ├── __init__.py                 # public API re-exports (§10)
│   ├── py.typed
│   ├── _jsint.py                   # JS integer semantics helpers (§3)
│   ├── _crypto.py                  # b64url, JWT HS256, AES-GCM, sha256 helpers (§4)
│   ├── errors.py                   # Reason enum + CapwxError (§5)
│   ├── config.py                   # CapConfig dataclass (§6)
│   ├── protocols/
│   │   ├── __init__.py
│   │   ├── sha256_pow.py           # mint/verify (§7.1)
│   │   ├── hashwx.py               # mint/verify + engine (§7.2)
│   │   └── instrumentation/
│   │       ├── __init__.py         # generate()/verify_result() (§7.3)
│   │       ├── generator.py        # port of instrumentation.js
│   │       ├── obfuscate.py        # string-table obfuscation (levels 4–7)
│   │       └── detect.py           # port of detect.js (§7.4)
│   ├── challenge.py                # create_challenge(), redeem() (§8)
│   ├── tokens.py                   # verification tokens + validate_token() (§9)
│   ├── stores/
│   │   ├── __init__.py             # NonceStore / TokenStore protocols
│   │   ├── memory.py
│   │   ├── redis.py                # extra: redis
│   │   └── django_cache.py         # extra: django
│   ├── _vendor/hashwx/
│   │   ├── hashwx.wasm             # server wasm (LGPL-3.0)
│   │   ├── LICENSE                 # LGPL-3.0 text (copy core/vendor/hashwx-LICENSE.txt)
│   │   ├── COMMIT                  # 74b567a31276a4c5d7cb232a5b7639467f49f961
│   │   └── SHA256                  # b1a0dbb3...aff5
│   └── contrib/
│       ├── django/
│       │   ├── __init__.py
│       │   ├── apps.py             # AppConfig "capwx.contrib.django"
│       │   ├── conf.py             # reads settings.CAPWX
│       │   ├── views.py            # challenge / redeem / siteverify views
│       │   ├── urls.py
│       │   ├── forms.py            # CapField + CapWidget
│       │   ├── decorators.py       # @require_cap
│       │   ├── templatetags/capwx.py   # {% capwx_widget %}, {% capwx_scripts %}
│       │   ├── templates/capwx/widget.html
│       │   └── static/capwx/       # vendored browser assets (§11)
│       └── ninja/
│           ├── __init__.py
│           └── router.py           # build_router(), CapRequired auth helper
├── scripts/
│   ├── vendor_assets.py            # downloads + verifies pinned upstream assets
│   └── gen_vectors.mjs             # regenerates tests/vectors/*.json with Node + capjs-core
└── tests/
    ├── vectors/                    # JSON test vectors (§13.1) — committed
    ├── test_jsint.py
    ├── test_crypto.py
    ├── test_sha256_pow.py
    ├── test_hashwx.py
    ├── test_instrumentation.py
    ├── test_detect.py
    ├── test_challenge.py
    ├── test_tokens.py
    ├── test_stores.py
    ├── test_interop_node.py        # optional: runs only if `node` + capjs-core available
    ├── django_project/             # minimal settings/urls for contrib tests
    ├── test_django.py
    ├── test_ninja.py
    └── e2e/test_browser.py         # Playwright + real cap-widget (marker: e2e)
```

### 1.1 `pyproject.toml`

```toml
[build-system]
requires = ["hatchling>=1.25"]
build-backend = "hatchling.build"

[project]
name = "capwx"
version = "0.1.0"
description = "Python server for the Cap CAPTCHA widget: HashWX proof-of-work, instrumentation, Django/Ninja integration"
readme = "README.md"
license = "Apache-2.0"
license-files = ["LICENSE", "NOTICE", "src/capwx/_vendor/hashwx/LICENSE"]
requires-python = ">=3.10"
authors = [{ name = "..." }]
keywords = ["captcha", "cap", "proof-of-work", "hashwx", "bot-protection", "django"]
classifiers = [
  "Framework :: Django",
  "Programming Language :: Python :: 3",
  "Topic :: Security",
  "Typing :: Typed",
]
dependencies = [
  "wasmtime>=49,<50",
  "cryptography>=42",
]

[project.optional-dependencies]
django = ["django>=4.2"]
ninja = ["django>=4.2", "django-ninja>=1.1"]
redis = ["redis>=5"]

[dependency-groups]
dev = ["pytest>=8", "pytest-django>=4.8", "ruff>=0.6", "pyright>=1.1.380", "coverage>=7"]
e2e = ["playwright>=1.45"]

[tool.hatch.build.targets.wheel]
packages = ["src/capwx"]

[tool.hatch.build.targets.wheel.force-include]
"src/capwx/_vendor/hashwx/hashwx.wasm" = "capwx/_vendor/hashwx/hashwx.wasm"

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = ["e2e: real browser tests (playwright)", "node: needs node + capjs-core"]
addopts = "-m 'not e2e and not node'"

[tool.ruff]
line-length = 100
target-version = "py310"
```

**Done when**: `uv sync --group dev` works; `uv build` produces a wheel that
contains `capwx/_vendor/hashwx/hashwx.wasm` (check with `unzip -l`).

---

## 2. Milestone list (overview)

| # | Milestone | Depends on |
|---|---|---|
| M1 | Repo skeleton, vendoring script, CI lint | — |
| M2 | `_jsint.py` + tests | M1 |
| M3 | `_crypto.py` + tests | M1 |
| M4 | `protocols/sha256_pow.py` | M3 |
| M5 | `protocols/hashwx.py` (wasmtime engine) | M3 |
| M6 | Instrumentation generator + obfuscation | M2 |
| M7 | Instrumentation verify + `detect.py` | M6 |
| M8 | `challenge.py` (create + redeem) | M4, M5, M7 |
| M9 | Stores + `tokens.py` (verification tokens, siteverify) | M8 |
| M10 | Django contrib (views, urls, form field, template tags, static) | M9 |
| M11 | Ninja contrib | M10 |
| M12 | Browser e2e with real widget (Playwright) | M10 |
| M13 | Docs, packaging, release pipeline | all |

---

## 3. M2 — JavaScript integer semantics (`_jsint.py`)

The instrumentation generator computes, in Python, the exact numbers a browser
will compute in JavaScript. JS bitwise operators work on **32-bit signed
integers**; Python ints are unbounded. Getting this wrong silently breaks
everyone's verification. Implement exactly:

```python
"""JavaScript integer semantics. Every function here mirrors a JS operator."""

import math


def to_int32(n: int) -> int:  # JS: n | 0   (for integer n)
    n &= 0xFFFFFFFF
    return n - (1 << 32) if n & 0x80000000 else n


def to_uint32(n: int) -> int:  # JS: n >>> 0
    return n & 0xFFFFFFFF


def js_shl(a: int, k: int) -> int:  # JS: a << k
    return to_int32(to_int32(a) << (k & 31))


def js_sar(a: int, k: int) -> int:  # JS: a >> k  (arithmetic)
    return to_int32(a) >> (k & 31)


def js_shr(a: int, k: int) -> int:  # JS: a >>> k (logical)
    return to_uint32(a) >> (k & 31)


def js_xor(a: int, b: int) -> int:  # JS: a ^ b
    return to_int32(to_int32(a) ^ to_int32(b))


def js_and(a: int, b: int) -> int:
    return to_int32(to_int32(a) & to_int32(b))


def js_or(a: int, b: int) -> int:
    return to_int32(to_int32(a) | to_int32(b))


def js_not(a: int) -> int:  # JS: ~a
    return to_int32(~to_int32(a))


def js_rem(a: int, b: int) -> int:  # JS: a % b  (sign follows dividend!)
    return int(math.fmod(a, b))


def utf16_units(s: str) -> list[int]:  # JS: s.charCodeAt(i) for each i
    b = s.encode("utf-16-le")
    return [int.from_bytes(b[i : i + 2], "little") for i in range(0, len(b), 2)]


def js_number_str(n: int) -> str:  # JS: String(n) for safe integers
    return str(n)


def is_js_number(x) -> bool:  # JS: typeof x === "number" && isFinite(x)
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)
```

**Pitfall list** (put in the module docstring):
- Python `%` on negatives differs from JS → always `js_rem`.
- Python `bool` is an `int` → every "is this a number" check must exclude `bool`.
- `charCodeAt` is UTF-16 code units, not code points → `utf16_units`.

**Tests** (`tests/test_jsint.py`): table tests for each helper, including
`to_int32(2**31) == -2**31`, `js_rem(-7, 3) == -1`, `js_shl(1, 31) == -2**31`,
`utf16_units("😀") == [0xD83D, 0xDE00]`.

**Done when**: tests pass.

---

## 4. M3 — Crypto primitives (`_crypto.py`)

All of these must be **byte-compatible with `core/src/crypto.js`**, so that
tokens minted by the Node server validate in Python and vice versa (useful for
mixed deployments and for the interop test).

```python
import base64, hashlib, hmac, json, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def random_hex(nbytes: int) -> str:  # JS randomHex(n): n bytes -> 2n hex chars
    return os.urandom(nbytes).hex()


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def b64url(data: bytes) -> str:  # Node "base64url": NO padding
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


_JWT_HEADER_B64 = b64url(b'{"alg":"HS256","typ":"JWT"}')  # exact bytes, do not re-serialise


def _key(secret: str | bytes) -> bytes:
    return secret.encode("utf-8") if isinstance(secret, str) else secret


def jwt_sign(payload: dict, secret) -> str:
    body = b64url(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    sig_input = f"{_JWT_HEADER_B64}.{body}"
    sig = hmac.new(_key(secret), sig_input.encode("ascii"), hashlib.sha256).digest()
    return f"{sig_input}.{b64url(sig)}"


def jwt_verify(token: str, secret) -> dict | None:
    # Exactly 2 dots, first dot not at index 0, constant-time compare,
    # JSON object payload, else None. NEVER raise on bad input.
    ...


def jwt_sig_hex(token: str) -> str | None:  # hex of the decoded signature (replay key)
    ...


def encrypt_gcm(data, secret, info: str = "cap:enc-v1") -> str:
    key = hmac.new(_key(secret), info.encode("utf-8"), hashlib.sha256).digest()  # 32 bytes
    iv = os.urandom(12)
    ct_and_tag = AESGCM(key).encrypt(iv, json.dumps(data, separators=(",", ":")).encode(), None)
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    return b64url(iv + tag + ct)  # Node layout: iv(12) | tag(16) | ciphertext


def decrypt_gcm(blob: str, secret, info: str = "cap:enc-v1"):
    # decode; len < 28 -> None; split iv/tag/ct; AESGCM.decrypt(iv, ct + tag, None);
    # json.loads; any exception -> None
    ...
```

**The trap**: Python's `AESGCM.encrypt` returns `ciphertext || tag`; Node's blob
is `iv || tag || ciphertext`. Reorder on both encrypt and decrypt.

**Tests** (`tests/test_crypto.py`) using `tests/vectors/crypto.json` (§13.1):
- `jwt_verify(VECTOR.jwt, VECTOR.secret)` returns
  `{"f":2,"n":"00ff","exp":1893456000000,"iat":1893455400000,"sk":"login"}`.
- `decrypt_gcm(VECTOR.gcm, VECTOR.secret, "cap:fmt2-v1")` returns
  `{"expected":[{"protocol":"sha256-pow","salt":"ab","target":"0000"}]}`.
- Round-trips: `decrypt_gcm(encrypt_gcm(x))== x`; tampered byte → `None`;
  wrong `info` → `None`; JWT with 3 dots / bad sig / non-JSON → `None`.

**Done when**: tests pass.

---

## 5. Errors (`errors.py`)

Reasons are part of the public API (apps branch on them; logs/metrics use
them). Mirror upstream names:

```python
class Reason(str, enum.Enum):
    INVALID_BODY = "invalid_body"
    MISSING_TOKEN = "missing_token"
    MISSING_SOLUTIONS = "missing_solutions"
    INVALID_TOKEN = "invalid_token"
    SCOPE_MISMATCH = "scope_mismatch"
    EXPIRED = "expired"
    INVALID_SOLUTIONS = "invalid_solutions"  # wrong length / shape
    INVALID_SOLUTION = "invalid_solution"  # a solution fails verification
    ALREADY_REDEEMED = "already_redeemed"
    NONCE_STORE_ERROR = "nonce_store_error"
    INSTR_CORRUPTED = "instr_corrupted"
    INSTR_EXPIRED = "instr_expired"
    INSTR_MISSING = "instr_missing"
    INSTR_TIMEOUT = "instr_timeout"
    INSTR_FAILED = "instr_failed"
    INSTR_AUTOMATED_BROWSER = "instr_automated_browser"
    INSTR_PROBE_MISSING = "instr_probe_missing"
    ID_MISMATCH = "id_mismatch"
    INVALID_STATE = "invalid_state"
    FAILED_CHALLENGE = "failed_challenge"


class CapwxError(Exception):
    """Raised only for programmer/config errors (bad secret, bad params). Never for bad client input."""
```

Rule: **client input never raises** — functions return result objects with a
`reason`. Only misconfiguration raises `CapwxError`.

---

## 6. Config (`config.py`)

```python
@dataclass(frozen=True)
class InstrumentationOptions:
    enabled: bool = True
    block_automated_browsers: bool = False
    obfuscation_level: int = 3  # 1..10; >7 clamped to 7 with a warning


@dataclass(frozen=True)
class CapConfig:
    secret: str | bytes  # >= 16 bytes, else CapwxError
    protocols: tuple[str, ...] = ("hashwx", "instrumentation")  # also "sha256-pow"
    hashwx_difficulty: int = 1_000_000  # 1..1_000_000_000
    hashwx_challenge_count: int = 4  # 1..64
    hashwx_nonces_per_hash: int = 65_536  # 1..1_048_576
    sha256_count: int = 50  # 1..1000
    sha256_size: int = 32  # salt bytes -> 2*size hex chars, 1..256
    sha256_difficulty: int = 4  # hex prefix length 1..16
    challenge_ttl_ms: int = 10 * 60 * 1000
    token_ttl_ms: int = 20 * 60 * 1000  # verification token lifetime
    instrumentation: InstrumentationOptions = InstrumentationOptions()
    hashwx_wasm_path: str | None = None  # override vendored LGPL wasm
```

Validate every bound in `__post_init__` and raise `CapwxError` with the same
wording style as upstream (`"hashwx_difficulty must be an integer in [1, 1000000000]"`).

**Note on `sha256_size`**: upstream format-2 uses `randomHex(s)` = `s` random
**bytes** → `2*s` hex chars. Keep that.

---

## 7. Protocols

Every protocol module exposes:

```python
def mint(config) -> list[tuple[dict, dict]]:   # [(public_payload, expected), ...]
def verify(expected: dict, solution: object) -> bool   # never raises
```

### 7.1 M4 — `sha256-pow`

Port of the `proto === "sha256-pow"` branch of `generateChallengeV2` /
`validateChallengeV2`.

- **mint**: for `i in range(sha256_count)`: `salt = random_hex(sha256_size)`,
  `target = "0" * sha256_difficulty`; payload `{"salt": salt, "target": target}`,
  expected `{"protocol": "sha256-pow", "salt": salt, "target": target}`.
- **verify(expected, solution)**:
  1. `solution` must be a `dict` with key `nonce`.
  2. `nonce` is a non-bool `int` with `0 <= nonce <= 2**53 - 1`, **or** a `str`
     matching `^[0-9]{1,16}$`. Anything else → False. (Upstream accepts any JS
     number/string; we are stricter on purpose — floats like `1e21` stringify
     differently in JS and Python.)
  3. `digest_hex = sha256((expected["salt"] + str(nonce)).encode()).hexdigest()`
  4. return `digest_hex.startswith(expected["target"].lower())`.
  (Hex-prefix compare is equivalent to upstream `powMatchesPrefix`, including
  odd-length targets — verified.)

**Tests**: vectors `[["0","salt",13],["00","salt",194],["000a","salt",13834],["f","salt",38]]`
= (target, salt, smallest valid nonce). Assert valid for that nonce and invalid
for every smaller nonce. Plus: bool nonce rejected, float rejected, negative
rejected, `"0123"` accepted (string form), missing key rejected.

### 7.2 M5 — `hashwx`

#### Algorithm (from `core/src/hashwx.js` + `docs/guide/hashwx.md`)

- Constants: `U64_MAX = 2**64 - 1`, `CHALLENGE_SIZE = 32`, `SEED_SIZE = 32`.
- **mint**: `each = max(1, round(hashwx_difficulty / hashwx_challenge_count))`
  — use **JS rounding** (`math.floor(x + 0.5)`), *not* Python's banker's
  `round()`. For `i in range(hashwx_challenge_count)`:
  `spec = {"c": os.urandom(32).hex(), "d": each, "n": hashwx_nonces_per_hash}`;
  payload `= dict(spec)`, expected `= {"protocol": "hashwx", **spec}`.
- **verify(expected, solution)**:
  1. `c` must be 64 hex chars → 32 bytes, else False.
  2. `n` int in `[1, 1_048_576]`, `d` int ≥ 1, else False.
  3. Parse `nonce`: non-bool int `0 <= x <= 2**53-1`, or str `^[0-9]{1,20}$` with
     value `<= U64_MAX`. Else False.
  4. `target = U64_MAX // d`
  5. `block = nonce // n`
  6. `seed = sha256(c_bytes + block.to_bytes(8, "little")).digest()`
  7. `h = engine.hash(seed, nonce)`; return `h <= target`.

#### Engine (`HashwxEngine`)

The vendored wasm exports (verified): `memory`, `_initialize`,
`hashwx_alloc(type) -> ctx`, `hashwx_seed(ctx) -> ptr` (32-byte seed buffer
inside wasm memory), `hashwx_make(ctx, seed_ptr)`, `hashwx_exec(ctx, i64) -> i64`,
`hashwx_free`. It has **no imports**.

```python
import threading
from importlib import resources
from wasmtime import Engine, Instance, Module, Store

_U64 = (1 << 64) - 1
HASHWX_INTERPRETED = 0


class HashwxEngine:
    """Thread-safe: one compiled Module, one Store/Instance per thread."""

    def __init__(self, wasm_path: str | None = None):
        self._engine = Engine()
        data = (
            open(wasm_path, "rb").read()
            if wasm_path
            else resources.files("capwx._vendor.hashwx").joinpath("hashwx.wasm").read_bytes()
        )
        self._module = Module(self._engine, data)
        self._local = threading.local()

    def _state(self):
        st = getattr(self._local, "st", None)
        if st is None:
            store = Store(self._engine)
            inst = Instance(store, self._module, [])
            ex = inst.exports(store)
            if "_initialize" in ex:
                ex["_initialize"](store)
            ctx = ex["hashwx_alloc"](store, HASHWX_INTERPRETED)
            if ctx <= 0:
                raise CapwxError("hashwx_alloc failed")
            st = (store, ex, ctx, ex["hashwx_seed"](store, ctx))
            self._local.st = st
        return st

    def hash(self, seed: bytes, nonce: int) -> int:
        store, ex, ctx, seed_ptr = self._state()
        ex["memory"].write(store, seed, seed_ptr)
        ex["hashwx_make"](store, ctx, seed_ptr)
        signed = nonce - (1 << 64) if nonce >= (1 << 63) else nonce  # wasm i64 is signed
        return ex["hashwx_exec"](store, ctx, signed) & _U64
```

- Create **one module-level lazy singleton** (`get_engine()`), guarded by a lock.
  Expose `hashwx_ready()` that forces initialisation (call it at app startup).
- If `hashwx_wasm_path` is set in config, use a separate engine for that path.
- At import of the vendored wasm, verify its sha256 equals
  `_vendor/hashwx/SHA256`; mismatch → `CapwxError` (tamper/packaging check).

**Tests** (`tests/test_hashwx.py`) — tevador's official vectors (seed is the
ASCII string zero-padded to 32 bytes):

| seed | nonce | expected hash |
|---|---|---|
| `b"This is a test seed for hashwx"` | `0` | `0x973684176f8ee362` |
| same | `123456` | `0x401983bb07d69b07` |
| `b"Lorem ipsum dolor sit amet"` | `123456` | `0x4af38d834a9a8d3d` |
| same | `987654321123456789` | `0x6a8a5514432e17a3` |

Plus:
- a **solver helper in tests only** (`_solve(c, d, n)`: loop nonce from 0, return
  first passing nonce) with `d=50` → `verify` True for it, False for `nonce+1`
  if that one fails the target (assert by recomputing).
- nonce `>= 2**63` does not crash (string form).
- threads: run `verify` from 8 threads concurrently 200× each; no errors, same results.
- bad inputs (`c` 63 chars, `n=0`, bool nonce, `"-1"`, 21-digit string) → False.

### 7.3 M6/M7 — `instrumentation`

Port of `core/src/instrumentation.js` (generation + verify) and
`core/src/detect.js`. **Port line by line; keep upstream function names as
snake_case** (`build_probe`, `build_block_checks`, `build_client_script`,
`generate_instrumentation`, `verify_instrumentation_result`, `dom_sum_mock`,
`hash_with`, `custom_obfuscate_strings`). Copy the marker lists
(`WINDOW_PROP_MARKERS`, `DOC_PROP_MARKERS`, `NAV_OWN_PROP_MARKERS`,
`ATTR_SUBSTRING_MARKERS`, `STACK_SUBSTRING_MARKERS`, `WINDOW_PREFIX_MARKERS`,
`UA_TOKEN_MARKERS`, `WEBGL_*`, `PRODUCTSUB_GECKO`, `SEQUENTUM_MARKER`,
`PROBE_FONT_STACKS`) **verbatim** — order matters for `fontWidths.length`.

The JavaScript you emit is the same text upstream emits; copy the template
strings exactly, substituting Python f-strings. Inside f-strings, JS `{`/`}`
must be doubled (`{{`/`}}`). **Recommended technique** to avoid brace errors:
build each JS snippet with `str.replace` on placeholder tokens instead of
f-strings, e.g. `TPL.replace("@B@", b).replace("@HF@", h_f)`.

#### Randomness mapping

| JS | Python (use `secrets.SystemRandom()` as `_rng`) |
|---|---|
| `Math.random()` | `_rng.random()` |
| `fastRnd(a, b)` (inclusive) | `_rng.randint(a, b)` |
| `randomInt(a, b)` (b exclusive) | `_rng.randrange(a, b)` |
| `rHex(len)` = `randomBytes(len).hex().slice(0,len)` | `os.urandom(len).hex()[:len]` |
| `rVar(len?)`: len default `int(random*7)+4` (4..10); first char from a–z, rest from a–z0–9 | same |
| `shuffle(arr)` Fisher–Yates | `_rng.shuffle(arr)` |

#### Bit-exact helpers (verified against Node — vectors in §13.1)

```python
def hash_with(seed: int):
    def h(s: str) -> int:
        x = to_uint32(seed)
        for c in utf16_units(s):
            x = to_int32(x ^ c)
            x = to_uint32(
                x + js_shl(x, 1) + js_shl(x, 4) + js_shl(x, 7) + js_shl(x, 8) + js_shl(x, 24)
            )
        return x

    return h


def dom_sum_mock(x: int, y: int, z: int) -> int:
    ROOT = object()

    def build(parent, val):
        cur, v = parent, val
        for _ in range(8):
            child = (cur, str(v))  # (parentNode, innerText)
            if (v & 1) == 0:
                cur = child
            v = js_sar(v, 1)
        return cur

    node, s = build(build(build(ROOT, x), y), z), 0
    while node is not ROOT:
        node, text = node
        s += int(text)  # parseInt(text, 10)
    return to_int32(js_rem(s, 256))
```

`hash_with` **must** match the browser exactly: two of the environment checks
emit `return null` when `hF(...) !== <constant>`, so a mismatch makes **every
real user fail** (widget times out). The `[native code]` block check likewise
flags everyone when `block_automated_browsers` is on.

#### `generate_instrumentation(opts)` — the value pipeline

Follow upstream exactly:

1. `id = r_hex(32)`; `vars = [r_var(12) for _ in range(4)]`.
2. `init_vals = [randint(10, 250) ×4]`; `vals = list(init_vals)`.
3. `correct_key = randint(1000, 9000)`; `bad_key` likewise, re-roll while equal.
4. `vals[0] = to_int32(vals[0] ^ correct_key)`.
5. Emit helper decls (`fnHelper`, `domHelper` — copy JS text verbatim) and
   `clientEqs = helperDecls + f"{v0} = {v0} ^ (navigator.userAgent ? {correct_key} : {bad_key});"`.
6. 20 rounds: `op = randint(0,5)`, `dest, src1, src2, src3 = randint(0,3) ×4`;
   append JS and update `vals[dest]`:
   - op 0: JS `D = ~(D & S1);` → `vals[d] = js_not(js_and(vals[d], vals[s1]))`
   - op 1: `D = D ^ S1;` → `js_xor`
   - op 2: `D = D | S1;` → `js_or`
   - op 3: `D = D & S1;` → `js_and`
   - op 4: `D = fnHelper(S1, S2, D);` → `vals[d] = js_or(js_xor(vals[s2], vals[s1]), js_xor(vals[d], vals[s2]))`
   - op 5: `D = domHelper(S1, S2, S3);` → `vals[d] = dom_sum_mock(vals[s1], vals[s2], vals[s3])`
   (Read operands **before** assigning; op 4 reads `vals[d]` itself.)
7. 4 salts `randint(100_000, 999_999)`; for each var:
   JS `V=((V^salt)&0x7FFFFFFF)%900000+100000;` →
   `vals[i] = (js_and(js_xor(vals[i], salt), 0x7FFFFFFF) % 900_000) + 100_000`
   (non-negative here, so Python `%` is fine).
8. `script = build_client_script(...)` (port verbatim, including env checks,
   `buildProbe`, optional `buildBlockChecks`, and the `postMessage` payload
   `{type:'cap:instr', nonce:id, result:{i:id, state, p, ts:Date.now()}}`).
   Note: `evalSecret = randrange(1_000_000, 0x7fffffff)`, and the emitted
   `evalSecret + 1` / `evalSecret * 2` constants are plain Python ints (no
   int32 wrap — upstream uses JS number arithmetic, and `2*0x7fffffff` is
   below 2^53).
9. Obfuscation by level (`level = clamp(opts.level, 1, 10)`; if `level > 7`:
   warn once, `level = 7`):
   - 1–3: `re.sub(r"\n\s*", "\n", s)` then `re.sub(r"^\s+", "", s, flags=re.M)`
   - 4–7: `custom_obfuscate_strings(script)` (port: regex
     `(['"])((?:\\.|(?!\1)[^\\])*)\1`, `decode_js_string`, dedupe, Fisher–Yates
     shuffle with `randrange`, table var `"_T" + os.urandom(3).hex()`, output
     `f"var {t}={json.dumps(arr, ensure_ascii=False)};" + replaced`), then
     the same whitespace strip as 1–3.
10. `blob = base64.b64encode(zlib_raw_deflate(script.encode(), level=1))` —
    **standard** base64 (not url-safe). Raw deflate:
    `c = zlib.compressobj(1, zlib.DEFLATED, -15); c.compress(b) + c.flush()`.
11. Return `{"id", "expires", "expected_vals": vals, "vars", "block_automated_browsers", "blob"}`.

Public payload: `{"blob": blob}`. Expected entry:
`{"protocol": "instrumentation", "instrMeta": {"id", "expectedVals", "vars", "blockAutomatedBrowsers", "expires"}}`
— keep these **camelCase keys** so tokens interoperate with `capjs-core`.

#### `verify_instrumentation_result(meta, payload)` → `(valid, reason, risk_flags, blocked_by)`

Port verbatim. Checks in order: meta is dict; payload is dict;
`payload["i"] == meta["id"]` else `id_mismatch`; `state` is dict else
`invalid_state`; `vars`/`expectedVals` are lists else `invalid_meta`;
for each `i`: `state.get(vars[i])` must be a non-bool int **and** equal
`expectedVals[i]` → else `failed_challenge`. Then the probe: if `payload["p"]`
is a dict, build `vector = {**p, "innerWH": payload["vp"]}` when `vp` is a
2-element list, run `detect_automation(vector, font_stack_count=len(PROBE_FONT_STACKS))`;
if `blockAutomatedBrowsers and not pass` → `instr_automated_browser` with
`blocked_by`; else valid with `risk_flags`. No probe + block on →
`instr_probe_missing`; no probe + block off → valid.

### 7.4 M7 — `detect.py`

Port `core/src/detect.js` verbatim (`is_mobile_vector`, `probe_completeness`,
`geometry_stats`, `detect_automation`). Constants: `MAX_FONT_WIDTHS=64`,
`MAX_TAMPER_KEYS=8`, `MAX_TAMPER_KEY_LENGTH=32`, `MAX_DETAIL_FIELDS=6`,
`OUTER_HEIGHT_SLACK=16`, mobile regex (case-insensitive). Type checks use
`is_js_number` and must treat `bool` as boolean, not number. `Math.trunc(x) === x`
→ `is_js_number(x) and float(x).is_integer()`. Return
`{"pass", "checks": [{"id","passed","detail","gating"}], "blocked_by", "risk_flags"}`.
Gating checks: all except `native_tamper` (non-gating → `risk_flags`).

**Tests**: hand-written vectors for each check id (`probe_incomplete`,
`geometry_quantized`, `webdriver_true`, `webdriver_stripped`,
`gecko_contradiction`, `window_exceeds_screen`, `viewport_override`,
`headless_token`, `native_tamper`), plus a "normal Chrome desktop" vector that
passes. Generate a second set with Node via `scripts/gen_vectors.mjs`
(`detectAutomation` is exported by capjs-core) and assert identical output.

**Instrumentation tests** (`tests/test_instrumentation.py`):
- `hash_with` and `dom_sum_mock` vectors (§13.1).
- Generated blob inflates (`zlib.decompress(b64decode(blob), -15)`) to valid
  UTF-8 starting with `(function(){window.onload=`.
- Every level 1–10 generates without error; level 8 logs one warning.
- **Semantic check with Node** (marker `node`): write the inflated script's
  value pipeline into a tiny Node harness that stubs `navigator.userAgent`
  and a minimal DOM for `domHelper`, run it, compare the 4 output vars with
  `expected_vals`. (Simplest: evaluate the `clientEqs` portion only — expose a
  debug hook `generate_instrumentation(..., _return_client_eqs=True)`.)
- Full browser check lives in M12.

---

## 8. M8 — Challenge lifecycle (`challenge.py`)

### 8.1 `create_challenge(config, *, scope=None, extra=None, overrides=None) -> dict`

Port of `generateChallengeV2`. Steps:

1. `now = int(time.time() * 1000)`; `exp = now + config.challenge_ttl_ms`.
2. For each protocol in `config.protocols` (in order): call its `mint`, append
   public `{"protocol": name, "payload": payload}` to `challenges` and the
   expected dict to `expected`. Unknown protocol → `CapwxError`.
   For instrumentation set `instrMeta["expires"] = exp`.
3. `token_payload = {"f": 2, "n": random_hex(16), "exp": exp, "iat": now,
   "ev": encrypt_gcm({"expected": expected}, secret, "cap:fmt2-v1")}`;
   add `"sk": str(scope)` if scope; add `"x": extra` if extra is a dict
   (warn in docs: `x` is readable by the client).
4. Return **exactly** `{"token": jwt_sign(token_payload, secret), "format": 2,
   "challenges": challenges, "expires": exp}` — this is the JSON the widget
   expects from `POST …/challenge`.

`overrides` lets callers change difficulty per request (adaptive difficulty —
see §12): `dataclasses.replace(config, **overrides)` before minting.

### 8.2 `redeem(config, body, *, scope=None, nonce_store=None, token_store=None) -> RedeemResult`

Port of `validateChallenge` + `validateChallengeV2`, returning

```python
@dataclass
class RedeemResult:
    success: bool
    reason: Reason | None = None
    token: str | None = None          # verification token for the widget
    expires: int | None = None        # ms epoch
    scope: str | None = None
    risk_flags: list[str] = field(default_factory=list)
    blocked_by: list[str] = field(default_factory=list)
    instr_error: bool = False
    def to_widget_json(self) -> dict  # {"success": True, "token", "expires"} or {"success": False, "error": reason}
```

Order of checks (keep it — the replay claim must come **after** all
verification so garbage submissions can't burn a real user's nonce):

1. `body` dict → else `invalid_body`; `token` str → `missing_token`;
   `solutions` list → `missing_solutions`.
2. `payload = jwt_verify(token)` → else `invalid_token`; `payload.get("f") != 2`
   → `invalid_token` (we don't do format 1).
3. `scope` given and `payload.get("sk") != scope` → `scope_mismatch`.
4. `payload["exp"]` missing or `< now_ms` → `expired`.
5. `decrypt_gcm(payload["ev"], secret, "cap:fmt2-v1")` → dict with list
   `expected`, else `invalid_token`.
6. `len(solutions) != len(expected)` → `invalid_solutions`.
7. For each `(e, s)`: `s` must be a dict else `invalid_solution`; dispatch on
   `e["protocol"]`:
   - `sha256-pow` / `hashwx`: protocol `verify` False → `invalid_solution`.
   - `instrumentation`: `meta = e.get("instrMeta")` missing → `instr_corrupted`;
     `meta["expires"] < now` → `instr_expired`; `s.get("blocked") is True` →
     `instr_automated_browser` if `meta["blockAutomatedBrowsers"]` else
     `instr_failed`; `s.get("timeout") is True` → `instr_timeout`; `s.get("instr")`
     → `verify_instrumentation_result` (failure reason passthrough, collect
     `risk_flags`); none → `instr_missing`. All instr failures set `instr_error=True`.
     Also accept the legacy top-level `body["instr_blocked"]` / `body["instr_timeout"]`
     flags (the widget sends them in one code path): treat as `blocked`/`timeout`.
   - anything else → `invalid_solution`.
8. If `nonce_store`: `key = "capwx:nonce:" + jwt_sig_hex(token)`;
   `ttl_s = max(1, ceil((payload["exp"] - now) / 1000))`; `claimed = nonce_store.claim(key, ttl_s)`;
   exception → `nonce_store_error`; `False` → `already_redeemed`.
   If **no** nonce store is configured, log a warning once at startup (replay
   possible within TTL).
9. Issue the verification token (§9) and return success.

---

## 9. M9 — Stores and verification tokens

### 9.1 Store protocols (`stores/__init__.py`)

```python
class NonceStore(Protocol):
    def claim(self, key: str, ttl_seconds: int) -> bool: ...  # SET NX EX; True if newly set


class TokenStore(Protocol):
    def put(self, key: str, expires_ms: int, ttl_seconds: int) -> None: ...
    def take(self, key: str) -> int | None: ...  # atomic get-and-delete
```

Provide async twins (`AsyncNonceStore`, `AsyncTokenStore`) and async
functions `acreate_challenge`, `aredeem`, `avalidate_token` that `await` store
calls when the store is async.

Implementations:
- `MemoryStore` (both protocols; dict + expiry + `threading.Lock`; for tests and
  single-process dev only — docstring says so).
- `RedisStore(redis_client, prefix="capwx:")` — `claim` = `SET key 1 NX EX ttl`;
  `put` = `SET key expires EX ttl`; `take` = `GETDEL` (Redis ≥ 6.2), fall back
  to a `MULTI/GET/DEL` pipeline.
- `DjangoCacheStore(alias="default")` — `claim` = `cache.add(key, 1, ttl)`;
  `put` = `cache.set`; `take` = `get` then `delete` (document: not atomic on
  every backend; use Redis in production).

**Tests**: one shared test suite parametrised over Memory, Redis (skip if no
`REDIS_URL`), DjangoCache (locmem) — claim twice → True/False; take twice →
value/None; expiry respected (use small TTL + monkeypatched clock for Memory).

### 9.2 Verification tokens (`tokens.py`)

Standalone-compatible format (so `siteverify` clients written for Cap
Standalone work unchanged):

- Issue: `token_id = random_hex(8)`; `secret_part = random_hex(15)`;
  `site = scope or "default"`; token `f"{site}:{token_id}:{secret_part}"`;
  store key `f"capwx:token:{site}:{token_id}:{sha256_hex(secret_part)}"`
  (we store the **hash**, never the raw token); `expires = now + token_ttl_ms`;
  `token_store.put(key, expires, ceil(token_ttl_ms/1000))`.
- If **no** token store: issue a **stateless** token instead:
  `"v1." + jwt_sign({"t": "verify", "sk": scope, "exp": expires, "n": random_hex(8)}, secret)`
  and document that stateless tokens are **not single-use** (replayable until
  expiry) — recommended only with a nonce store on redeem and short TTL.
- `validate_token(config, token, *, scope=None, token_store=None, consume=True) -> bool`:
  parse 3 parts (or `v1.` stateless), check `site == (scope or "default")`,
  recompute key, `take` (or `get` when `consume=False`), check `expires > now`.
  Never raises on bad input.

### 9.3 `siteverify(config, secret_from_request, response_token, ...)`

Standalone-compatible endpoint logic: compare the given site secret with the
configured per-site secret (`hmac.compare_digest`), then `validate_token`.
Returns `{"success": bool}` (plus `"error"` on failure). Lets other services
(Node, Go…) verify tokens issued by your Python app with the reCAPTCHA-style
API.

---

## 10. Public API (`__init__.py`)

```python
from capwx.config import CapConfig, InstrumentationOptions
from capwx.challenge import create_challenge, redeem, acreate_challenge, aredeem, RedeemResult
from capwx.tokens import validate_token, avalidate_token, siteverify
from capwx.errors import Reason, CapwxError
from capwx.protocols.hashwx import hashwx_ready
from capwx.stores.memory import MemoryStore

__all__ = [...]
__version__ = "0.1.0"
```

Minimal framework-free usage (put in README):

```python
cfg = CapConfig(secret=os.environ["CAPWX_SECRET"])
store = MemoryStore()
# POST /cap/challenge
return json(create_challenge(cfg, scope="login"))
# POST /cap/redeem
return json(
    redeem(cfg, request_json, scope="login", nonce_store=store, token_store=store).to_widget_json()
)
# in the protected form handler
if not validate_token(cfg, form["cap-token"], scope="login", token_store=store):
    reject()
```

---

## 11. M10 — Django integration (`capwx.contrib.django`)

### 11.1 Settings

```python
CAPWX = {
    "SECRET": env(
        "CAPWX_SECRET"
    ),  # required, >= 16 bytes; never DJANGO SECRET_KEY reuse by default
    "SITES": {  # optional: per-site (scope) overrides + siteverify secrets
        "login": {
            "HASHWX_DIFFICULTY": 1_000_000,
            "INSTRUMENTATION": {"BLOCK_AUTOMATED_BROWSERS": True},
        },
    },
    "STORE": "capwx.stores.django_cache.DjangoCacheStore",  # or RedisStore path + kwargs
    "STORE_OPTIONS": {"alias": "default"},
    "PROTOCOLS": ["hashwx", "instrumentation"],
    "HASHWX_DIFFICULTY": 1_000_000,
    "TOKEN_TTL_MS": 1_200_000,
    "CSRF_EXEMPT": True,  # widget POSTs carry no CSRF header (see 11.3)
    "DIFFICULTY_HOOK": None,  # dotted path: f(request, site) -> dict overrides (§12)
    "BEFORE_CHALLENGE_HOOK": None,  # dotted path: f(request, site) -> None or raise to block
}
```

`conf.py` builds and caches one `CapConfig` per site (merge global + site
overrides, map UPPER_CASE keys to dataclass fields) and the store instance.
Validate at `AppConfig.ready()` and call `hashwx_ready()` there.

### 11.2 Views and URLs

`urls.py` (`app_name = "capwx"`):

```
<str:site>/challenge   → challenge_view   POST only → JSON create_challenge(...)
<str:site>/redeem      → redeem_view      POST only, JSON body → JSON to_widget_json()
<str:site>/siteverify  → siteverify_view  POST only, JSON {secret, response}
```

- Unknown site (not in `SITES` and not `"default"`) → 404 JSON `{"error": "Invalid site key"}`.
- `redeem` status codes like Standalone: 200 on success; 400 `invalid_*`;
  403 for `expired`, `already_redeemed`, `scope_mismatch`, `instr_*`.
  Body always `{"success": false, "error": "<reason>"}` on failure (the widget
  reads `resp.error`).
- Request body limit: reject `Content-Length > 64 KiB` with 413 (instrumentation
  probe + 4 HashWX nonces is a few KB).
- `never_cache` on all three. `require_POST`.
- Usage: `path("cap/", include("capwx.contrib.django.urls"))` → widget endpoint
  `data-cap-api-endpoint="/cap/login/"`.

### 11.3 CSRF

The widget's `fetch` sends no CSRF token. Two supported modes:

1. `CSRF_EXEMPT: True` (default): the three views are `csrf_exempt`. Safe
   because they read no session/cookie credentials and grant nothing by
   themselves (the verification token must still be submitted with the real,
   CSRF-protected form).
2. `CSRF_EXEMPT: False`: views stay protected; `{% capwx_scripts %}` installs
   `window.CAP_CUSTOM_FETCH` that adds `X-CSRFToken` from the `csrftoken`
   cookie and `credentials: "same-origin"`. Use this when a global policy
   forbids exempt routes (e.g. django-next's `APICsrfMiddleware` rule).

### 11.4 Static assets and template tags

Vendor into `contrib/django/static/capwx/` with `scripts/vendor_assets.py`
(downloads npm tarballs at the pinned versions, verifies sha256, copies files,
writes `static/capwx/VERSIONS.json`):

| File | Source |
|---|---|
| `cap.min.js` | `cap-widget@0.1.58` `cap.min.js` (Apache-2.0) |
| `hashwx.wasm` | `@cap.js/wasm@0.0.8` `browser/hashwx.wasm` (LGPL-3.0 — ship LICENSE beside it) |
| `cap_wasm_bg.wasm` | `@cap.js/wasm@0.0.8` `browser/cap_wasm_bg.wasm` (SHA-256 solver) |
| `pako_inflate.min.js` | `pako@2.1.0` `dist/pako_inflate.min.js` (MIT) |

`{% capwx_scripts %}` renders (all URLs via `{% static %}`, nonce from
`request.csp_nonce` if present):

```html
<script>
  window.CAP_CUSTOM_HASHWX_URL = "{% static 'capwx/hashwx.wasm' %}";
  window.CAP_CUSTOM_WASM_URL   = "{% static 'capwx/cap_wasm_bg.wasm' %}";
  window.CAP_PAKO_URL          = "{% static 'capwx/pako_inflate.min.js' %}";
  /* when CSRF_EXEMPT is False: window.CAP_CUSTOM_FETCH = (u, c) => fetch(u, {...c, credentials: "same-origin", headers: {...(c.headers||{}), "X-CSRFToken": <cookie>}}); */
</script>
<script src="{% static 'capwx/cap.min.js' %}" defer></script>
```

So **no CDN** is contacted (privacy, CSP). `{% capwx_widget site="login" %}`
renders `<cap-widget data-cap-api-endpoint="{% url 'capwx:...' %}">` pointing
at the site's base path.

### 11.5 Form field and decorator

- `CapField(site="default")`: `forms.CharField` with widget rendering
  `{% capwx_widget %}`; `clean()` calls `validate_token(..., scope=site)`;
  error message "Please complete the verification." The widget injects the
  hidden input named `cap-token`, so the field's HTML name must be `cap-token`
  (set `CapWidget.value_from_datadict` to read `data.get("cap-token")`).
- `@require_cap(site="default", field="cap-token", header="X-Cap-Token")`
  for function views / JSON APIs: reads the token from the header or POST/JSON
  field, 403 JSON `{"error": "captcha_required"}` if invalid.

**Tests** (`tests/test_django.py`, pytest-django with `tests/django_project`):
challenge returns format 2 with expected protocol list; full flow with a
Python solver (low difficulty overrides, instrumentation **disabled** for this
test) → redeem 200 → `validate_token` True once, False second time; replay of
the same redeem body → `already_redeemed`; unknown site → 404; GET → 405;
oversized body → 413; `CapField` valid/invalid; `CSRF_EXEMPT=False` enforces CSRF.

---

## 12. Best-of features (from the other packages and Standalone)

Implement in this order; each is small.

1. **Adaptive difficulty hook** (`DIFFICULTY_HOOK` / `overrides=`): host app
   returns e.g. `{"hashwx_difficulty": 4_000_000}` for suspicious IPs.
   `RedeemResult.risk_flags` (e.g. `native_tamper`) is the signal to feed back.
2. **Before-challenge hook**: block/ratelimit by IP, country, ASN in the host
   app (Standalone has IP/ASN block rules; we leave data sources to the app).
3. **Per-site config + scope binding** (Standalone site keys; `sk` claim).
4. **Siteverify-compatible endpoint** (Standalone / reCAPTCHA API shape).
5. **Pluggable stores** (capjs-server's `nonce_store` idea) — Memory/Redis/Django cache.
6. **Django form field + Ninja router** (django-cap's ideas).
7. **Self-hosted assets, no CDN** (ALTCHA's CSP-friendly approach).
8. **Structured logging**: `logging.getLogger("capwx")`, one INFO line per
   redeem with `site`, `success`, `reason`, `duration_ms`; never log tokens,
   solutions or probe data. Optional `on_event(name, **labels)` callback for
   metrics (low-cardinality labels only: `site`, `reason`, `protocol`).
9. **Management command** `python manage.py capwx_check`: verifies the wasm
   hash, runs the HashWX test vectors, mints+redeems one low-difficulty
   challenge end to end, prints timings.

---

## 13. Testing strategy

### 13.1 Committed vectors (`tests/vectors/`)

Generated with Node from capjs-core 0.1.5 by `scripts/gen_vectors.mjs` and
**already verified against a Python port** while writing this plan:

```json
{
  "hashWith": [[1,"webdriver",590152607],[2147483646,"[native code]",2371459876],
               [123456789,"[object Navigator]",426332371],[987654321,"",987654321],
               [42,"HeadlessChrome",1730379643]],
  "domSum": [[10,20,30,74],[250,250,250,168],[-5,7,-300,-244],
             [-2147483648,2147483647,0,0],[123,-1,99,72]],
  "secret": "test-secret-0123456789abcdef",
  "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmIjoyLCJuIjoiMDBmZiIsImV4cCI6MTg5MzQ1NjAwMDAwMCwiaWF0IjoxODkzNDU1NDAwMDAwLCJzayI6ImxvZ2luIn0.TLYneOrnsPtsFCEdF3UejUIGyNqz6VF4RtmGmGQ9nek",
  "gcm": "VFcnrw9SL2wogwj6Mh-0aE1E9tTWtlS0ak1SeYb3zlqIi-JuILOUTeLg2Gx75kJzuGXFnHKxTQZ04VKBIFtGiG7yYsXNqOUyjWmWoyGWzZQPYleOQCro_qGf3EtkrZK4",
  "pow": [["0","salt",13],["00","salt",194],["000a","salt",13834],["f","salt",38]],
  "hashwx": [["This is a test seed for hashwx",0,"973684176f8ee362"],
             ["This is a test seed for hashwx",123456,"401983bb07d69b07"],
             ["Lorem ipsum dolor sit amet",123456,"4af38d834a9a8d3d"],
             ["Lorem ipsum dolor sit amet",987654321123456789,"6a8a5514432e17a3"]]
}
```

(`hashWith` entries: `[seed, string, expected]`; `domSum`: `[x, y, z, expected]`;
`gcm` decrypts with `info="cap:fmt2-v1"`; HashWX seeds are ASCII zero-padded to 32 bytes.)

`scripts/gen_vectors.mjs` must import the real upstream files (not copies) from
a checkout of the pinned Cap commit, so vectors can be regenerated when
upgrading.

### 13.2 Interop tests (marker `node`, CI job with Node 22+)

`npm i capjs-core@0.1.5` in a temp dir, then:
- Node mints a format-2 challenge (`protocols: ["sha256-pow"]`, low difficulty,
  fixed secret); Python solves (test solver) and `redeem`s it → success.
- Python mints; a Node script runs `validateChallenge` on a Python-solved body → success.
- Same for `["hashwx"]` with `hashwxDifficulty: 20`.

### 13.3 Browser e2e (M12, marker `e2e`)

Playwright + Chromium against `tests/django_project` (`runserver` in a fixture):
1. Page with `{% capwx_scripts %}{% capwx_widget site="e2e" %}`, site config
   `hashwx_difficulty=20_000`, instrumentation on, `block_automated_browsers=False`.
   Click the widget → wait for `solve` event → submit form → server says valid.
   This is **the** test that proves the instrumentation port is bit-exact.
2. Same with obfuscation levels 1, 4, 7.
3. `block_automated_browsers=True` → Playwright Chromium is detected → widget
   error and redeem returns `instr_automated_browser` (expected, documents
   behaviour).
4. Network assertion: no request leaves `localhost` (no CDN).

### 13.4 Coverage and quality gates

`ruff check`, `ruff format --check`, `pyright` (strict on `src/capwx`),
coverage ≥ 90 % on `src/capwx` excluding `contrib/*/templates`.

---

## 14. M13 — Packaging, CI, release

- **CI** (GitHub Actions): matrix Python 3.10–3.14 × ubuntu/macos/windows for
  unit tests (wasmtime ships wheels for all three); one ubuntu job with Redis
  service; one job with Node for `node` tests; one job with Playwright for `e2e`.
- **Release**: tag `vX.Y.Z` → build sdist + wheel with `uv build` → publish
  with PyPI **Trusted Publishing** (no API tokens). Check the wheel contains the
  wasm, the LGPL licence and the static assets.
- **Upstream sync procedure** (`UPSTREAM.md`): bump pins → re-run
  `scripts/vendor_assets.py` → diff `core/src/*.js` between old and new commit
  → port changes → regenerate vectors → run node + e2e suites.
- **Security policy**: report address, supported versions, "never log tokens".
- **Docs** (README): install, framework-free example, Django quickstart,
  config reference, security notes (secret length, store choice, stateless
  token caveat, CSRF modes), licence note on the LGPL wasm.

---

## 15. Security checklist (verify before 0.1.0)

- [ ] Secret ≥ 16 bytes enforced; docs recommend 32+ random bytes from env.
- [ ] All HMAC/token comparisons use `hmac.compare_digest`.
- [ ] Client input never raises; bodies size-limited; JSON depth irrelevant (only fixed keys read).
- [ ] Replay claim happens after verification; nonce key derived from JWT signature.
- [ ] Verification tokens single-use (`take` = get-and-delete) when a store is configured.
- [ ] Only token **hashes** are stored.
- [ ] No tokens, nonces, solutions, probe vectors in logs.
- [ ] Vendored wasm hash verified at load.
- [ ] `x` (extra) claim documented as client-readable.
- [ ] Difficulty bounds enforced on both mint and verify (`d`, `n` ranges).

---

## 16. Using it in django-next (after the package exists)

Update `captcha.proposal.md` accordingly:

1. `uv add "capwx[django,redis]"`; add `"capwx.contrib.django"` to `THIRD_PARTY_APPS`.
2. Mount the views **outside `/api/`** (e.g. `path("cap/", include(...))`) and
   keep `CSRF_EXEMPT: False` + `CAP_CUSTOM_FETCH` (project rule: no CSRF-exempt
   routes), or document an explicit exception in `docs/security.md`.
3. `CAPWX["SECRET"]` from env (`CAPWX_SECRET`), store = Redis (`REDIS_URL`).
4. `AuthGuardService.check()` (from `captcha.proposal.md`) calls
   `capwx.validate_token(..., scope="login")` with the token from the
   `X-Auth-Guard` header's `pow` field, replacing the planned in-house ALTCHA backend.
5. `/o/login/` template: `{% capwx_scripts %}` + an invisible/programmatic widget
   that solves when the guard says `required`.
6. Constance `AUTH_CAPTCHA_MODE` + adaptive difficulty via `DIFFICULTY_HOOK`
   reading the existing failure counters in `apps/accounts/rate_limit.py`.

---

## 17. Open questions

1. Name/branding: confirm `capwx` and the "unofficial" wording; consider asking
   the Cap author whether they'd list it under community libraries.
2. LGPL wasm in an Apache wheel: the separate-file + replaceable-path approach is
   the common reading of LGPL-3.0 §4–5, but get a licence review before 1.0.
3. Should we also ship a pure-SHA-256 fallback when `wasmtime` has no wheel for
   a platform (e.g. musl/armv7)? Proposal: `protocols=("sha256-pow", "instrumentation")`
   works without importing wasmtime — import it lazily inside `hashwx.py`.
4. Levels 8–10 obfuscation: optional subprocess to `npx javascript-obfuscator`
   behind an extra? Not in 0.1.
