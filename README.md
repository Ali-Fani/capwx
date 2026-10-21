# capwx

Python server for the [Cap](https://github.com/tiagozip/cap) CAPTCHA widget: HashWX and
sha256-pow proof-of-work challenges, browser instrumentation checks, and Django / Django Ninja
integration.

> **Unofficial.** `capwx` is an independent port. It is not affiliated with, endorsed by, or
> supported by Cap or its authors.

**Status: 0.2.0, beta.** Published on PyPI as [`capwx`](https://pypi.org/project/capwx/). The API may
still change in minor releases; changes are listed in the [changelog](CHANGELOG.md).

## What it is

Cap is a proof-of-work CAPTCHA. The widget in the browser solves challenges the server issues and
posts the solutions back. `capwx` is the server side of Cap's format-2 protocol:

- `create_challenge` mints challenges and an encrypted token for the widget.
- `redeem` verifies the solutions and issues a verification token.
- `validate_token` (or `siteverify`) lets your form handler check that token, once.

Three challenge protocols:

| Protocol | What the browser does |
|---|---|
| `hashwx` | Runs the HashWX proof-of-work (wasm) to find nonces below a target |
| `sha256-pow` | Finds a nonce whose `sha256(salt + nonce)` starts with a number of zero hex digits |
| `instrumentation` | Runs a generated probe script and reports the browser's state |

Upstream pins (details in [UPSTREAM.md](UPSTREAM.md)):

| Thing | Pin |
|---|---|
| Cap repository | `tiagozip/cap` at commit `29bbe6fbe284786cdb0d4489e5040aee6042b2a4` |
| Server protocol logic | `capjs-core` 0.1.5 |
| Browser widget | `cap-widget` 0.1.58 |
| Browser solver wasm | `@cap.js/wasm` 0.0.8 |
| Widget inflate fallback | `pako` 2.1.0 |
| HashWX | `tevador/hashwx` at commit `74b567a31276a4c5d7cb232a5b7639467f49f961` |

## Install

```bash
pip install capwx                 # core: wasmtime and cryptography
pip install "capwx[django]"       # Django integration
pip install "capwx[ninja]"        # Django Ninja integration (also pulls in Django)
pip install "capwx[drf]"          # Django REST Framework integration (also pulls in Django)
pip install "capwx[bolt]"         # django-bolt integration (Python 3.12+; also pulls in Django)
pip install "capwx[redis]"        # RedisStore (you bring the redis-py client)
```

With uv: `uv add "capwx[django,ninja,drf,bolt,redis]"`.

Python 3.10 to 3.14. `capwx` is pure Python and ships one universal wheel. HashWX needs wasmtime, which
is installed automatically on x86-64 and ARM64 Linux, macOS and Windows. On other CPUs (32-bit, armv7,
ppc64le, s390x) the package still installs and `sha256-pow` and `instrumentation` work; see
[docs/platforms.md](docs/platforms.md).

For development from a checkout:

```bash
uv sync --group dev --extra django --extra ninja --extra drf --extra bolt
uv run pytest
```

## Quick start (framework-free)

This is the whole flow. Call `hashwx_ready()` once at startup so a broken wasm fails early.

```python
import os

from capwx import CapConfig, MemoryStore, create_challenge, hashwx_ready, redeem, validate_token

hashwx_ready()
cfg = CapConfig(secret=os.environ["CAPWX_SECRET"])
store = MemoryStore()  # development only; see "Stores" under Security notes

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

`json(...)` stands for your framework's JSON response. `request_json` is the parsed body of the
widget's redeem request.

## Django quickstart

**1. Settings.** Add the app and a `CAPWX` dict. Read the secret from the environment.

```python
# settings.py
import os

INSTALLED_APPS = [
    # ...
    "capwx.contrib.django",
]

CAPWX = {
    "SECRET": os.environ["CAPWX_SECRET"],  # at least 16 bytes; 32 random bytes recommended
    "SITES": {
        "login": {
            "HASHWX_DIFFICULTY": 1_000_000,
            "INSTRUMENTATION": {"BLOCK_AUTOMATED_BROWSERS": True},
            "SITE_SECRET": os.environ["CAPWX_LOGIN_SITE_SECRET"],  # optional: enables /siteverify
        },
    },
    "STORE": "capwx.stores.django_cache.DjangoCacheStore",  # see "Stores" below
    "STORE_OPTIONS": {"alias": "default"},
    "CSRF_EXEMPT": True,
}
```

The valid site names are `"default"` (always present) and the keys of `SITES`. Any other name gets a 404.

**2. URLs.** Mount the endpoints outside any API prefix:

```python
# urls.py
from django.urls import include, path

urlpatterns = [
    path("cap/", include("capwx.contrib.django.urls")),
]
```

The widget then posts to `/cap/<site>/challenge`, `/cap/<site>/redeem` and `/cap/<site>/siteverify`.

**3. Templates.** Load the tags once per page, before the form, and render the widget inside it:

```django
{% load capwx %}
{% capwx_scripts %}
<form method="post">
  {% csrf_token %}
  {% capwx_widget site="login" %}
  <button type="submit">Log in</button>
</form>
```

`{% capwx_scripts %}` loads the browser assets from `{% static %}` only, so no CDN is contacted. It
uses `request.csp_nonce` (or Django's `request._csp_nonce`) for its inline script when present.
`{% capwx_widget %}` renders `<cap-widget>` with a hidden input named `cap-token`.

**4. Forms.** `CapField` checks the token when the form is cleaned:

```python
from django import forms
from capwx.contrib.django.forms import CapField


class LoginForm(forms.Form):
    username = forms.CharField()
    # The widget's hidden input is always "cap-token", whatever this field is called.
    cap = CapField(site="login")
```

`clean()` consumes the token. If the rest of the form then fails, the user must solve the widget
again.

**5. Views.** `@require_cap` protects a function view or a JSON endpoint. It reads the token from the
`X-Cap-Token` header, then the `cap-token` POST field, then a top-level `cap-token` field of a JSON
body. A missing or invalid token gets `403 {"error": "captcha_required"}`:

```python
from capwx.contrib.django.decorators import require_cap


@require_cap(site="login")
def create_order(request): ...
```

The check runs before the view, so a decorated view must not do side effects before the decorator
runs.

**6. CSRF.** Two modes, set with `CSRF_EXEMPT`:

- `True` (default): the three widget endpoints are `csrf_exempt`. They read no cookies and grant
  nothing by themselves, because the verification token only means something when your
  CSRF-protected form submits it.
- `False`: the endpoints enforce Django's CSRF check themselves, on every request. `{% capwx_scripts %}`
  then installs `window.CAP_CUSTOM_FETCH`, which adds the `X-CSRFToken` header and sends
  same-origin credentials. Use this when a project policy forbids exempt routes.

**7. Hooks.** Both are dotted paths (or callables in the settings):

- `BEFORE_CHALLENGE_HOOK(request, site)`: return `None`, or raise `PermissionDenied` to refuse the
  challenge with `403 {"error": "blocked"}`. The hook's message is not logged, because it may
  describe the client.
- `DIFFICULTY_HOOK(request, site)`: return a dict of `CapConfig` field overrides for this request,
  such as `{"hashwx_difficulty": 4000}`, or `None`. Field names are lowercase. Return values that
  are not a dict or `None` are a configuration error. Override values that `CapConfig` rejects
  raise `CapwxError`, so validate them in the hook.

**8. Check the setup.** `python manage.py capwx_check` verifies the vendored wasm and the static copy
against their pinned SHA-256, runs the four official HashWX test vectors, and does one full
challenge round trip per configured site. It exits non-zero on any failure.

**Startup.** `AppConfig.ready()` validates `CAPWX` (raising `ImproperlyConfigured` with the key that is
wrong) and loads the HashWX engine for every site that uses it.

## Django Ninja

```python
from ninja import NinjaAPI
from capwx.contrib.ninja import CapRequired, build_router, install

api = NinjaAPI()
install(api)  # answers CapRequired failures with 403 {"error": "captcha_required"}
api.add_router("/cap/", build_router())  # challenge, redeem and siteverify, per site


@api.post("/orders", auth=CapRequired(site="login"))
def create_order(request): ...
```

With the API mounted at `/api/`, the widget's endpoint is `/api/cap/<site>/`. `build_router()` answers
the same JSON bodies and status codes as the Django views, including 405 JSON for any method other
than POST and 413 for bodies over 64 KiB.

`CapRequired` takes the token from the header (default `X-Cap-Token`), then from the top-level
`cap-token` field of a JSON body. Pass `field=""` to accept the header only. Each token works for one
request.

Without `install(api)`, the failure body is ninja's default `{"detail": "captcha_required"}` with
status 403. Request body schemas are documented in OpenAPI only. They do not validate the request,
because the view parses the raw body itself.

## Django REST Framework

```python
# urls.py
from django.urls import include, path

urlpatterns = [
    path("cap/", include("capwx.contrib.drf.urls")),  # widget endpoint: /cap/<site>/
]
```

```python
# a protected view
from capwx.contrib.drf import cap_permission


class OrderView(APIView):
    permission_classes = [cap_permission(site="login")]
```

Also provides `CapTokenField` for serializers. Full guide: [docs/drf.md](docs/drf.md).

## django-bolt

```python
from capwx.contrib.bolt import CapRequired, install

install(api, prefix="/cap")  # POST /cap/{site}/challenge, /redeem, /siteverify
login_cap = CapRequired(site="login")  # use as Depends(login_cap.check)
```

Needs Python 3.12+ and same-origin use (no CORS preflight). Full guide: [docs/bolt.md](docs/bolt.md).

## Configuration reference

### `CapConfig` (framework-free, and per site in Django)

`CapConfig(**fields)` checks every bound in `__post_init__` and raises `CapwxError`. A `bool` is
rejected wherever an integer is expected.

| Field | Default | Bounds | Notes |
|---|---|---|---|
| `secret` | required | `str` or `bytes`, at least 16 bytes | Keys the token signature and the encrypted claims. Never logged or shown in `repr()`. |
| `protocols` | `("hashwx", "instrumentation")` | non-empty tuple of unique names from `hashwx`, `sha256-pow`, `instrumentation` | Challenges are minted in this order. |
| `hashwx_difficulty` | `1_000_000` | 1 to 1 000 000 000 | Split across the HashWX challenges: each gets `d = max(1, round(difficulty / count))`. |
| `hashwx_challenge_count` | `4` | 1 to 64 | Number of HashWX challenges in one widget challenge. |
| `hashwx_nonces_per_hash` | `65_536` | 1 to 1 048 576 | Nonces that share one seed (the block size). |
| `sha256_count` | `50` | 1 to 1000 | Number of sha256-pow challenges. |
| `sha256_size` | `16` | 1 to 256 | Salt bytes, sent as `2 x size` hex characters. The default is 16 because of the browser solver limit below. |
| `sha256_difficulty` | `4` | 1 to 16 | Leading zero hex digits the hash must start with. |
| `challenge_ttl_ms` | `600_000` (10 min) | 1 to 2^53 - 1 | How long a challenge stays redeemable. |
| `token_ttl_ms` | `1_200_000` (20 min) | 1 to 2^53 - 1 | Lifetime of a verification token. |
| `instrumentation` | `InstrumentationOptions()` | see below | |
| `hashwx_wasm_path` | `None` | `str` or `None` | Path to a replacement HashWX wasm. When set, the file is used as given and is not hash-checked. |

`InstrumentationOptions(enabled=True, block_automated_browsers=False, obfuscation_level=3)`:

| Field | Default | Bounds | Notes |
|---|---|---|---|
| `enabled` | `True` | bool | `False` skips the instrumentation challenge at mint time. |
| `block_automated_browsers` | `False` | bool | Fails the challenge when the probe finds automation. Without it the probe only adds risk flags. |
| `obfuscation_level` | `3` | 1 to 10 | See "Obfuscation levels" below. |

**The sha256 salt length.** The browser's sha256 solver (`cap_wasm_bg.wasm`) only matches messages
under 56 bytes, which is the salt plus the decimal nonce. Salts of about 27 bytes or more hang the
solver in the widget. Upstream's 32-byte salt hangs for that reason, so capwx defaults to 16 bytes
(32 hex characters).

### Django `CAPWX` settings

| Key | Default | Notes |
|---|---|---|
| `SECRET` | required, global only | As `CapConfig.secret`. Do not reuse `DJANGO SECRET_KEY`. |
| `SITES` | `{}` | Per-site overrides, keyed by site name. The name `"default"` always exists. Names match `[A-Za-z0-9_.-]{1,64}`. |
| `SITES[name]` | | Any `CapConfig` field in UPPER_CASE (for example `HASHWX_DIFFICULTY`), plus `INSTRUMENTATION` (a dict with `ENABLED`, `BLOCK_AUTOMATED_BROWSERS`, `OBFUSCATION_LEVEL`) and `SITE_SECRET`. |
| `SITE_SECRET` | none | Per site. When set, `/siteverify` accepts this secret. Must be a non-empty string. |
| Top-level `CapConfig` fields | `CapConfig` defaults | For example `PROTOCOLS`, `TOKEN_TTL_MS`. A site entry overrides them. |
| `STORE` | `capwx.stores.django_cache.DjangoCacheStore` | A dotted path (built with `STORE_OPTIONS` as keyword arguments) or a store instance. |
| `STORE_OPTIONS` | `{}` | Keyword arguments for a `STORE` path. |
| `CSRF_EXEMPT` | `True` | See "CSRF" above. |
| `DIFFICULTY_HOOK` | `None` | See "Hooks" above. |
| `BEFORE_CHALLENGE_HOOK` | `None` | See "Hooks" above. |

## Stores

A store holds the nonces used for replay protection and the verification tokens, so the same
solution or token cannot be used twice.

| Store | Use | Single use across processes |
|---|---|---|
| `MemoryStore` | Development and tests only. Process-local. | No |
| `DjangoCacheStore` | The default for Django. Uses `django.core.cache` with an alias. | Yes, on backends where `cache.add` is atomic: Redis, Memcached and locmem. Not the database cache backend. |
| `RedisStore(client)` | Production. Takes a `redis.Redis` client. Uses `SET NX` and `GETDEL` (or a transaction). | Yes |
| `AsyncRedisStore(client)` | Async code paths (`aredeem`, `avalidate_token`). Takes a `redis.asyncio.Redis` client. | Yes |

For production, pass a Redis store instance:

```python
import os
import redis
from capwx.stores.redis import RedisStore

CAPWX = {
    # ...
    "STORE": RedisStore(redis.Redis.from_url(os.environ["REDIS_URL"])),
}
```

The Django views need a synchronous store. An async store in `CAPWX["STORE"]` is rejected at startup.

## Security notes

- **Secret.** capwx refuses secrets shorter than 16 bytes. Use 32 or more random bytes from the
  environment, for example `python -c "import secrets; print(secrets.token_urlsafe(32))"`. Keep it out
  of source control. Rotating it invalidates outstanding challenges and tokens.
- **Stores.** `MemoryStore` is per process: a second worker cannot see the first worker's nonces or
  tokens, so replay protection and single use do not hold. Use `RedisStore` in production. Use
  `DjangoCacheStore` only on a cache backend with an atomic `add`.
- **Stateless tokens.** Without a token store, `issue_token` returns a stateless token. It is valid
  until `token_ttl_ms` and can be replayed inside that window. Use short token lifetimes with it, and
  do not use it where replay matters. `validate_token` refuses stateless tokens when a store is
  given, because they cannot be consumed there.
- **Nonce store.** Without a `nonce_store`, a solved challenge can be redeemed repeatedly until it
  expires. capwx logs a warning once.
- **The `x` claim.** The `extra` value passed to `create_challenge` is stored in the token's `x` claim.
  The token is a JWT, so the client can read it. Never put secrets in `extra`.
- **Scopes.** A scope cannot contain `:`, which separates the fields of a stored token. Django site
  names are restricted to `[A-Za-z0-9_.-]`.
- **Logs.** capwx never logs tokens, nonces, solutions or probe data. It logs one INFO line per redeem
  with the site, success, reason and duration. Do not log request bodies yourself.
- **Stored tokens.** Only a SHA-256 hash of the secret part of a stored token is kept in the store.
- **Bounds.** Difficulty and nonce bounds are checked when minting (`CapConfig`) and again when
  verifying (`hashwx` and `sha256-pow`), so a crafted expectation cannot ask the server for unbounded
  work.
- **Not rate limited.** capwx does not limit how often a client can request challenges or redeem
  them. Put your rate limits in front of the endpoints.
- **Probe is not a boundary.** The instrumentation probe is a heuristic. Obfuscation hides code from
  casual reading, not from a determined reader. `block_automated_browsers` raises the cost of
  automation but does not stop it.

## Licence

capwx is licensed under the Apache License 2.0 (see [LICENSE](LICENSE)).

The vendored `hashwx.wasm` is the HashWX binary by tevador, licensed under the GNU Lesser General
Public License v3.0. It is shipped as a separate file, with its licence beside it:

- `src/capwx/_vendor/hashwx/hashwx.wasm`, `LICENSE`, `COMMIT`, `SHA256`
- `static/capwx/hashwx.wasm` and `static/capwx/hashwx-LICENSE.txt` (the browser copy)

The HashWX C source is not included in capwx, and capwx does not link to a HashWX library. You can
replace the server wasm with your own build through `hashwx_wasm_path`. The browser assets are
Apache-2.0 (`cap-widget`, `@cap.js/wasm`) and MIT (`pako`). See [NOTICE](NOTICE) and
[UPSTREAM.md](UPSTREAM.md). This section is not legal advice.

## Obfuscation levels

The instrumentation script is generated by capwx. `obfuscation_level` controls how it is written
out:

- Levels 1 to 3: whitespace stripped.
- Levels 4 to 7: string table obfuscation plus whitespace stripping. Upstream minifies these levels
  with esbuild. capwx has no esbuild, so its output differs from upstream's, but the server verifies
  the probe results the same way.
- Levels 8 to 10: clamped to 7, with a warning logged once. Upstream uses `javascript-obfuscator`
  for these levels, which is not available in Python.

## Known limitations

- Beta. The API may still change in minor releases.
- The Django views need a synchronous store.
- Stateless tokens can be replayed until they expire.
- The database cache backend does not give single use under concurrency. Use Redis.
- A replacement `hashwx_wasm_path` is not hash-checked.
- Obfuscation levels 8 to 10 are clamped to 7, and levels 4 to 7 differ from upstream's output.
- The Node interop tests (`pytest -m node`) need `npm` and install `capjs-core` in a temp directory.
  The browser tests (`pytest -m e2e`) need Chromium.
- Syncing with upstream is manual. See [UPSTREAM.md](UPSTREAM.md).
