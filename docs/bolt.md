# django-bolt integration

`capwx.contrib.bolt` serves the widget endpoints from a [django-bolt](https://bolt.farhana.li/)
`BoltAPI` (Rust/Actix server, async Python handlers) and provides `CapRequired`, a dependency that
guards any Bolt operation with a verification token.

Requirements: Python 3.12 or newer and `django-bolt>=0.12`. Install with
`pip install 'capwx[bolt]'`. Without django-bolt, `import capwx.contrib.bolt` raises an `ImportError`
that names the install command. On Python 3.10 or 3.11 the package refuses to import, with a message
that suggests `capwx.contrib.django` or `capwx.contrib.ninja`.

## Settings

The settings are the same as for the Django integration: `CAPWX` with `SECRET`, `SITES`, `STORE`,
`CSRF_EXEMPT`, `BEFORE_CHALLENGE_HOOK` and `DIFFICULTY_HOOK` (see `capwx/contrib/django/conf.py`).
django-bolt runs inside Django, so `CAPWX` is read from `django.conf.settings`. Nothing else is
needed in `INSTALLED_APPS` for the handlers to work (the test suite runs them without `django_bolt`
in `INSTALLED_APPS`).

## Mounting the widget endpoints

```python
# myproject/bolt_api.py
from django_bolt import BoltAPI, Depends, Request
from capwx.contrib.bolt import CapRequired, install

api = BoltAPI()
install(api, prefix="/cap")  # POST /cap/{site}/challenge, /redeem, /siteverify

login_cap = CapRequired(site="login")


@api.post("/orders")
async def create_order(request: Request, _: Annotated[None, Depends(login_cap.check)]):
    return {"ok": True}
```

`install(api, prefix)` is `api.include_router(build_router(), prefix=prefix)`. Use `build_router()`
directly if you want to mount the routes yourself.

Any method other than POST on those three paths answers `405 {"error": "method_not_allowed"}` with
`Allow: POST`, as the Django urls do.

Run the API with Django's settings and `django_bolt` installed:

```
python -m django runbolt --settings=myproject.settings --host 127.0.0.1 --port 8000
```

`runbolt` finds the API in the project's `api` or `bolt_api` module, or in `BOLT_API`
(`["myproject.bolt_api:api"]`). `django_bolt` must be in `INSTALLED_APPS` for the `runbolt` command.
The repository's test settings have a separate module, `tests/django_project/settings_bolt.py`,
which adds exactly that.

## The widget

Point the widget at the mount prefix. The base is the site's path with a trailing slash:

```html
<div data-cap-api-endpoint="/cap/login/" ...></div>
```

The widget then posts to `/cap/login/challenge`, `/cap/login/redeem` and `/cap/login/siteverify`
in the same way as with the Django and Ninja integrations.

## CapRequired

`CapRequired(site="login", header="X-Cap-Token", field=None)` is a dependency, not a Bolt guard.
Bolt's guards (`IsAuthenticated`, `Requires`) and auth backends are compiled to Rust and cannot run
Python code. Pass `cap.check` to `Depends` in the handler signature.

- The token comes from the `X-Cap-Token` header. If it is absent, the top-level `cap-token` field of
  a JSON body or a form-encoded body is used. `field=""` allows the header only.
- The token is validated and consumed for the site scope. A token works once.
- A missing, invalid, expired, reused or other-site token gets `403 {"error": "captcha_required"}`.
  No extra setup is needed for that body.

## CORS (limitation)

Serve the widget endpoints from the same origin as the page that embeds the widget. This is the
supported setup.

Cross-origin use does not work out of the box. A browser preflight (`OPTIONS`) on the widget paths
gets `405 {"error": "method_not_allowed"}`. With Django's `CORS_ALLOWED_ORIGINS` set, the response
also carries `Access-Control-Allow-Origin`, but the status is still 405, and browsers need a 2xx
answer to a preflight. django-bolt's `@cors(origins=[...])` decorator is per handler, and
`build_router()` does not take it, so it cannot be applied to these endpoints without changing the
package. Verified with django-bolt 0.12.

## Sync stores and the event loop

The capwx stores are synchronous. `CAPWX['STORE']` must not be an async store, because
`capwx.contrib.django.conf` rejects one with `ImproperlyConfigured`. The Bolt handlers run the
whole synchronous body in a worker thread (`asgiref` `sync_to_async`, `thread_sensitive=False`),
so cache or Redis I/O and database queries in hooks do not block the event loop. The async core
functions (`aredeem`, `acreate_challenge`, `avalidate_token`) are not used by this integration,
because the settings do not allow an async store.

## Hooks

`BEFORE_CHALLENGE_HOOK` and `DIFFICULTY_HOOK` are called with a Django `HttpRequest` built from the
Bolt request, not with the Bolt request itself. It carries `method`, `path`, `META` (Bolt's META
plus every request header under its `HTTP_` name, so `request.META["HTTP_X_HARD"]` works), and
`COOKIES`. It has no `user`, `session` or `FILES`, because Bolt does not run the Django middleware.
Raising `PermissionDenied` in the before-hook gives `403 {"success": false, "error": "blocked"}`.

## CSRF

Bolt does not run Django's CSRF middleware. With `CSRF_EXEMPT: True` (the default) the widget
endpoints need no token. With `CSRF_EXEMPT: False` the endpoints run Django's CSRF check on the
request (header `X-CSRFToken` or the `csrftoken` cookie), so the widget must send the token as
`{% capwx_scripts %}` does for Django.

## Limits and deviations

- Bodies above Bolt's upload limit, `BOLT_MAX_UPLOAD_SIZE` (default 1 MiB), are rejected by the
  Rust server with Bolt's own `413 {"detail": "Payload too large"}` before the handler runs. Setting
  `BOLT_MAX_UPLOAD_SIZE = 64 * 1024` should make Bolt answer those bodies too (not tested here).
  Bodies between 64 KiB and that limit get the capwx JSON `413 {"success": false, "error": "body_too_large"}`.
- `CapRequired` reads a form-encoded body field but not multipart form data. The widget sends JSON.
- Bolt has no TRACE routes, so TRACE on the widget paths gets Bolt's default answer, not the 405 JSON.
- Bolt's `runbolt` is used for serving. The test suite uses django-bolt's in-process `TestClient`,
  so it does not start the Rust server.

## Tests

`tests/test_bolt.py` skips when django-bolt is missing or Python is older than 3.12. It drives the
challenge, solve (`tests/_solver.py`), redeem and validate flow, replay rejection, unknown site,
wrong method, 413, malformed JSON, siteverify, `CapRequired` (header, JSON field, form field,
consumed once, other site), hooks, CSRF and the missing-package error. The API is
`tests/django_project/bolt_api.py`.
