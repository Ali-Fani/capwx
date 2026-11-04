# FastAPI integration

`capwx.contrib.fastapi` puts capwx into a [FastAPI](https://fastapi.tiangolo.com/) application. It has
four parts:

- `Cap`, one object that holds the sites, the store and the hooks,
- `cap.router`, an `APIRouter` with the three widget endpoints (challenge, redeem, siteverify),
- `cap.require(site)`, a dependency that requires a verification token on any route,
- `cap.mount_assets(app)` and `cap.scripts()` / `cap.widget()`, which serve the widget files and render its HTML.

Install with the `fastapi` extra:

```bash
pip install 'capwx[fastapi]'
```

This pulls in `fastapi>=0.111`. Forms with a token in a multipart body also need `python-multipart`, which
the extra does not install. See [Tokens in the request](#tokens-in-the-request).

The integration targets FastAPI. The package imports `fastapi` when it is imported, so plain Starlette
without FastAPI is not supported. The tests do not run it on Starlette directly.

## Minimal app

```python
import os

from fastapi import Depends, FastAPI
from fastapi.responses import HTMLResponse

from capwx import CapConfig
from capwx.contrib.fastapi import Cap
from capwx.stores.memory import AsyncMemoryStore

cap = Cap(
    {"login": CapConfig(secret=os.environ["CAPWX_SECRET"])},
    store=AsyncMemoryStore(),  # per process: development only, see Stores below
)

app = FastAPI()
app.include_router(cap.router, prefix="/cap")  # POST /cap/login/challenge, /redeem, /siteverify
cap.mount_assets(app)  # widget files under /cap-static/
cap.install(app)  # a failed require() answers {"error": "captcha_required"}


@app.get("/login", response_class=HTMLResponse)
async def login_page() -> str:
    return f"""<!doctype html>
<html>
<body>
  {cap.scripts()}
  <form method="post" action="/orders">
    {cap.widget("login")}
    <button>Place order</button>
  </form>
</body>
</html>"""


@app.post("/orders", dependencies=[Depends(cap.require("login"))])
async def create_order() -> dict[str, bool]:
    return {"ok": True}
```

- `include_router(cap.router, prefix="/cap")` sets the base path. The widget's endpoint is then `/cap/login/`,
  which is what `cap.widget("login")` puts in the element. If you use another prefix, pass
  `endpoint=` to `widget()`.
- `mount_assets(app)` serves the files under `/cap-static`. `scripts()` uses the same default. If you pass
  another path to one, pass the same path to the other: `mount_assets(app, path="/static/capwx")` and
  `scripts(static_path="/static/capwx")`.
- `scripts()` and `widget()` return plain strings. Put them in the page with `HTMLResponse`, or with a
  template engine that does not escape them (in Jinja2, `|safe`). Put the scripts before the form.
- `cap.install(app)` changes only the body of the 403 from `require()`. Without it the body is FastAPI's
  default `{"detail": "captcha_required"}`.

## Redis store

`AsyncMemoryStore` is process-local. With more than one worker, replay protection and single use do not
hold. In production use `AsyncRedisStore`, which takes a `redis.asyncio.Redis` client:

```bash
pip install 'capwx[fastapi,redis]'
```

```python
import os

import redis.asyncio as redis

from capwx import CapConfig
from capwx.contrib.fastapi import Cap
from capwx.stores.redis import AsyncRedisStore

client = redis.Redis.from_url(os.environ["REDIS_URL"])
cap = Cap(
    {"login": CapConfig(secret=os.environ["CAPWX_SECRET"])},
    store=AsyncRedisStore(client),  # keys start with "capwx:" by default
)
```

`Cap` rejects a synchronous store with `CapwxError` at construction. Stores must have `async def` methods
(`claim`, `put`, `take`); `MemoryStore` and `RedisStore` are rejected for this reason.

## Multiple sites

Each site has its own `CapConfig`. Use `SiteSettings` when the site also needs `/siteverify`, which
requires `site_secret`:

```python
import os

from capwx import CapConfig
from capwx.contrib.fastapi import Cap, SiteSettings
from capwx.stores.memory import AsyncMemoryStore

SECRET = os.environ["CAPWX_SECRET"]

cap = Cap(
    {
        "login": CapConfig(secret=SECRET),
        "signup": SiteSettings(
            config=CapConfig(secret=SECRET, protocols=("sha256-pow",)),
            site_secret=os.environ["CAPWX_SIGNUP_SITE_SECRET"],
        ),
    },
    store=AsyncMemoryStore(),
)
```

- Site names must match `[A-Za-z0-9_.-]{1,64}`. A name that does not match raises `CapwxError`.
- A token is bound to its site. A token from `login` is refused by `require("signup")` (`scope_mismatch`).
- `cap.require("nope")` for a site that is not configured raises `CapwxError` when the route is defined,
  so a typo fails at startup.
- `site_secret` is not shown in `repr()`.

## Protecting routes with `require()`

`cap.require(site)` returns a dependency. It raises 403 unless the request carries a valid, unused
token for the site:

```python
signup_guard = cap.require("signup")


@app.post("/signup", dependencies=[Depends(signup_guard)])
async def signup(payload: SignupIn) -> dict[str, str]: ...
```

`require(site, header="X-Cap-Token", field="cap-token")` takes the header and body field names.

### Tokens in the request

The token is read from the first place that has one:

1. the `X-Cap-Token` header, if it is not empty;
2. the top-level `cap-token` field of the body. JSON bodies are read on any method. Form bodies
   (`application/x-www-form-urlencoded` and `multipart/form-data`) are read only on POST.

- `field=""` turns off the body lookup, so only the header counts.
- A body over 64 KiB gives no token, so the request gets 403.
- A multipart body is read only when `python-multipart` is installed. Without it there is no token and
  the request gets 403. It does not raise.
- The endpoint can still read the body after the dependency has read it.

The token is consumed when it is checked. A second use fails, and so does a request whose handler
later fails validation after the token was checked. Check the token last if that matters.

### The 403 body

| Setup | Body of a failed `require()` |
|---|---|
| `cap.install(app)` called | `{"error": "captcha_required"}` |
| not called | `{"detail": "captcha_required"}` (FastAPI default) |

`install()` only changes this exception. Other `HTTPException`s keep FastAPI's default bodies.

## Hooks

Both hooks take `(request, site)`, where `request` is the Starlette `Request`. They may be `def` or
`async def`.

### `before_challenge`

Runs before a challenge is issued. It can refuse the request:

```python
from fastapi import Request

from capwx.contrib.fastapi import Blocked

BLOCKED_IPS = {"203.0.113.7"}


async def before_challenge(request: Request, site: str) -> None:
    if request.client is not None and request.client.host in BLOCKED_IPS:
        raise Blocked()


cap = Cap(sites, store=store, before_challenge=before_challenge)
```

- Raising `Blocked` gives `403 {"success": false, "error": "blocked"}`. The message of `Blocked` is neither
  sent nor logged.
- Raising an `HTTPException` gives FastAPI's default body for it.
- Returning normally allows the challenge.
- Any other exception is not caught and becomes a 500.

### `difficulty_hook`

Returns a mapping of `CapConfig` field overrides for this challenge, or `None` to keep the defaults:

```python
from fastapi import Request


def difficulty(request: Request, site: str) -> dict[str, int] | None:
    if site == "signup":
        return {"sha256_difficulty": 4}
    return None


cap = Cap(sites, store=store, difficulty_hook=difficulty)
```

- The keys are `CapConfig` field names. An unknown key raises `CapwxError` while the challenge is built,
  which is a 500.
- Returning anything that is not a mapping or `None` also raises `CapwxError` (500).
- The hook runs on every challenge request, so keep it fast.

## Siteverify

`POST /cap/<site>/siteverify` checks a token from the server side, once, like reCAPTCHA's siteverify. The
caller sends the site secret and the token:

```bash
curl -X POST https://example.com/cap/signup/siteverify \
  -H "Content-Type: application/json" \
  -d '{"secret": "<site_secret>", "response": "<token>"}'
```

- It answers `{"success": true}` or `{"success": false, "error": "<code>"}`.
- A site without `site_secret` answers 404 `siteverify_not_configured`.
- The token is consumed by a successful check, as with `require()`.

## Status codes and bodies

The endpoints give the same JSON bodies and status codes as the Django views (`capwx.contrib.django.views`)
and the Ninja integration. Checks run in this order: method, site, body size, then the endpoint itself.

| Case | Status | Body |
|---|---|---|
| Any method other than POST on the three paths | 405 | `{"error": "method_not_allowed"}`, `Allow: POST` |
| Unknown site | 404 | `{"error": "Invalid site key"}` |
| Body over 64 KiB (also without `Content-Length`) | 413 | `{"success": false, "error": "body_too_large"}` |
| Challenge refused by `before_challenge` (`Blocked`) | 403 | `{"success": false, "error": "blocked"}` |
| Challenge issued | 200 | the widget's challenge JSON |
| Redeem with malformed or non-UTF-8 JSON | 400 | `{"success": false, "error": "invalid_body"}` |
| Redeem succeeded | 200 | `{"success": true, "token": ..., "expires": ...}` |
| Redeem failed: `nonce_store_error` | 500 | `{"success": false, "error": "nonce_store_error"}` |
| Redeem failed: `expired`, `already_redeemed`, `scope_mismatch`, `id_mismatch`, `failed_challenge`, `missing_meta`, `invalid_meta`, or `instr_*` (for example `instr_csp_eval_blocked`) | 403 | `{"success": false, "error": "<code>"}` |
| Redeem failed: any other reason (for example `invalid_solution`) | 400 | `{"success": false, "error": "<code>"}` |
| Siteverify with a body that is not a JSON object | 400 | `{"success": false, "error": "invalid_body"}` |
| Siteverify without `site_secret` | 404 | `{"success": false, "error": "siteverify_not_configured"}` |
| Siteverify: `invalid_secret` | 403 | `{"success": false, "error": "invalid_secret"}` |
| Siteverify: `missing_parameters`, `invalid_token` | 400 | `{"success": false, "error": "<code>"}` |
| `require()` fails (missing, invalid, used or expired token) | 403 | `{"error": "captcha_required"}` after `install()` |

Every capwx response carries `Cache-Control: no-store`. Responses are returned as JSON directly, so
FastAPI does not validate or re-serialise them.

## Async and threads

- The challenge and redeem endpoints use the async core functions. `acreate_challenge` and `aredeem` run
  their CPU-bound work (minting, and checking the solutions) in a worker thread (`asyncio.to_thread`), so a
  challenge does not hold up the event loop.
- Store calls are awaited on the event loop. `AsyncMemoryStore` and `AsyncRedisStore` do not block it.
- `validate_token` and `siteverify` run on the event loop without a worker thread. They do a hash
  comparison and store calls.
- Hooks that do blocking I/O (a database query or a synchronous HTTP call) should be `async def` with an
  async client, or call `asyncio.to_thread` themselves. A blocking hook blocks the event loop.

## Content Security Policy

capwx does not set a Content-Security-Policy header. Your application sets it. The rules are the same as
in [Content Security Policy](../README.md#content-security-policy) in the README:

- The widget needs `'wasm-unsafe-eval'` in `script-src` for its wasm solvers, and `worker-src blob:`.
- The widget does not need `'unsafe-eval'`. The instrumentation probe does run `eval` and `new Function`
  checks, which a CSP without `'unsafe-eval'` blocks. The probe detects this, skips those checks and
  reports it. The server then rejects the redeem with `instr_csp_eval_blocked` (403), because a bot could
  fake the same report.
- Pick one of these:
  - add `'unsafe-eval'` to `script-src`;
  - set `CapConfig(instrumentation=InstrumentationOptions(allow_csp_eval_blocked=True))` for the site. The
    challenge is accepted with the risk flag `csp_eval_blocked`, and the anti-emulation check is weaker;
  - use `protocols=("hashwx",)` and skip instrumentation.
- If your `script-src` uses nonces, pass the same nonce to `scripts()` (or `Cap(..., script_nonce=...)`).
  It goes on both script tags and also sets `CAP_SCRIPT_NONCE` and `CAP_CSS_NONCE` for the widget.

## Serving the assets

`mount_assets(app, path="/cap-static")` checks the vendored files before it mounts them:

- every file listed in `VERSIONS.json` must exist and match its recorded sha256;
- a missing or altered file raises `CapwxError`, and nothing is mounted.

The files are served from the installed package, so there is no copy to keep in sync. The widget also
needs `cap.min.js`, `hashwx.wasm`, `cap_wasm_bg.wasm` and `pako_inflate.min.js`, which `scripts()` names.
Only change them through the project's `scripts/vendor_assets.py`.

## Limits

- Same origin is the supported setup, as for the Bolt integration. The widget endpoints answer a CORS
  preflight (`OPTIONS`) with 405 JSON, unless a CORS middleware answers it first. Cross-origin use was not
  tested with FastAPI.
- capwx does not rate limit challenges or redeems. Put a rate limit in front of the endpoints.
- `AsyncMemoryStore` is for development and tests only.
- `hashwx` sites need wasmtime, which is installed on x86-64 and ARM64 Linux, macOS and Windows. On other
  platforms `Cap` raises `CapwxError` for a `hashwx` site. Use `protocols=("sha256-pow", "instrumentation")`
  there. See [docs/platforms.md](platforms.md).

## Tests

`tests/test_fastapi.py` covers the flow, the error paths and status codes, the body limit, both token
sources, `require()` consumed once, the hooks, siteverify, the assets and scripts, and the missing-package
error. Most of its tests use the `sha256-pow` protocol, so they do not need wasmtime. It is skipped when `fastapi` or
`httpx` is missing. `tests/test_async_threadpool.py` covers the worker-thread change.
