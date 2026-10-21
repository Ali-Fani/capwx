"""capwx.contrib.bolt.router: widget endpoints and ``CapRequired`` for django-bolt.

Mount the endpoints on a ``BoltAPI``::

    from django_bolt import BoltAPI, Depends, Request
    from capwx.contrib.bolt import CapRequired, install

    api = BoltAPI()
    install(api)  # POST /cap/{site}/challenge, /redeem, /siteverify

    login_cap = CapRequired(site="login")

    @api.post("/orders")
    async def create_order(request: Request, _: Annotated[None, Depends(login_cap.check)]):
        ...

The widget then uses ``data-cap-api-endpoint="/cap/login/"``.

Behaviour matches the Django views (``capwx.contrib.django.views``), because the Bolt handlers call
the same inner view functions: identical JSON bodies, status codes, 404 for an unknown site, 413
over 64 KiB, 400 ``invalid_body`` for malformed JSON, the ``CSRF_EXEMPT`` setting, and the
``BEFORE_CHALLENGE_HOOK`` and ``DIFFICULTY_HOOK`` settings. Hooks receive a Django ``HttpRequest``
built from the Bolt request (see :func:`_django_request`).

This module is not annotated ``from __future__ import annotations`` on purpose: django-bolt reads
the handler annotations (``request: Request``) when it registers a route.
"""

import logging
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import parse_qsl

from asgiref.sync import sync_to_async
from django.http import HttpRequest, QueryDict
from django_bolt import BoltAPI, Request, Response, Router
from django_bolt.exceptions import HTTPException

from capwx._types import as_json_dict
from capwx.contrib.django import views as _views
from capwx.contrib.django.conf import (
    DEFAULT_SITE,
    MAX_BODY_BYTES,
    TOKEN_FIELD,
    TOKEN_HEADER,
    CapwxConf,
    SiteConf,
    get_conf,
    require_site,
)
from capwx.tokens import validate_token

logger = logging.getLogger("capwx")

_NO_STORE = "max-age=0, no-cache, no-store, must-revalidate, private"
_FORM_TYPES = ("application/x-www-form-urlencoded",)

# (endpoint name, route path, OpenAPI summary). The name keys _HANDLERS.
_ENDPOINTS: tuple[tuple[str, str, str], ...] = (
    ("challenge", "/{site}/challenge", "Issue a challenge for a site"),
    ("redeem", "/{site}/redeem", "Redeem solved challenges for a verification token"),
    ("siteverify", "/{site}/siteverify", "Server-side verification of a verification token"),
)

# The Django views' inner functions: (request, site_conf, conf, body) -> Django JsonResponse.
# They are private, but the views module is part of this package and the reuse keeps the two
# integrations identical.
_HANDLERS: dict[str, Callable[[Any, SiteConf, CapwxConf, bytes], Any]] = {
    "challenge": _views._challenge,  # pyright: ignore[reportPrivateUsage]
    "redeem": _views._redeem,  # pyright: ignore[reportPrivateUsage]
    "siteverify": _views._siteverify,  # pyright: ignore[reportPrivateUsage]
}


# --------------------------------------------------------------------------- request adapters


def _media_type(headers: Any) -> str:
    return str(headers.get("content-type", "")).split(";", 1)[0].strip().lower()


def _django_request(request: Any) -> HttpRequest:
    """A Django ``HttpRequest`` built from the Bolt request, for the views and the hooks.

    It carries ``method``, ``path``, ``META`` (Bolt's META plus every request header under its
    ``HTTP_`` name, so ``HTTP_X_CSRFTOKEN`` and custom hook headers work), ``COOKIES`` and an empty
    or form ``POST``. There is no ``user``, ``session`` or ``FILES``, because Bolt does not run the
    Django middleware that sets them.
    """
    headers: dict[str, str] = dict(request.headers)
    meta: dict[str, Any] = dict(request.META)
    for name, value in headers.items():
        key = name.upper().replace("-", "_")
        if key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
            meta[key] = value
        else:
            meta.setdefault("HTTP_" + key, value)

    shim = HttpRequest()
    shim.method = str(request.method)  # pyright: ignore[reportAttributeAccessIssue]
    shim.path = str(request.path)
    shim.path_info = str(request.path)
    shim.META = meta
    shim.COOKIES = dict(request.cookies)
    form = bytes(request.body) if _media_type(headers) in _FORM_TYPES else b""
    shim.POST = QueryDict(form)  # pyright: ignore[reportAttributeAccessIssue]
    return shim


def _read_body(request: Any) -> bytes | None:
    """The body, or None when it is over MAX_BODY_BYTES (the declared length or the bytes)."""
    declared = str(request.headers.get("content-length", ""))
    if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        return None
    data = bytes(request.body)
    return None if len(data) > MAX_BODY_BYTES else data


def _extract_token(request: Any, field: str, header: str) -> object:
    """The token from the header, else a JSON or form body field named ``field``.

    Mirrors :func:`capwx.contrib.django.decorators.extract_token`, which needs a Django request.
    ``field=""`` disables the body lookup. Multipart bodies are not read (the widget sends JSON).
    """
    value = request.headers.get(header.lower())
    if value:
        return value
    if not field:
        return None
    ctype = _media_type(request.headers)
    if ctype == "application/json":
        data = as_json_dict(_views._parse_json(bytes(request.body)))  # pyright: ignore[reportPrivateUsage]
        return None if data is None else data.get(field)
    if ctype in _FORM_TYPES:
        text = bytes(request.body).decode("utf-8", "replace")
        return dict(parse_qsl(text)).get(field)
    return None


# --------------------------------------------------------------------------- responses


def _json_response(status: int, data: dict[str, Any]) -> Response:
    return Response(data, status_code=status, headers={"Cache-Control": _NO_STORE})


def _to_bolt(django_response: Any) -> Response:
    """Convert a Django JsonResponse from the views into a Bolt Response (same status, body, headers)."""
    headers = {
        str(k): str(v) for k, v in django_response.items() if str(k).lower() != "content-type"
    }
    headers["Cache-Control"] = _NO_STORE
    return Response(
        bytes(django_response.content),
        status_code=int(django_response.status_code),
        headers=headers,
    )


# --------------------------------------------------------------------------- handlers


def _serve(request: Any, site: str, name: str) -> Response:
    """The Django views' wrapper, in the same order: CSRF, then site, then body size."""
    shim = _django_request(request)
    denied = _views._csrf_gate(shim)  # pyright: ignore[reportPrivateUsage]
    if denied is not None:
        return _to_bolt(denied)
    conf = get_conf()
    site_conf = conf.sites.get(site)
    if site_conf is None:
        return _json_response(404, {"error": "Invalid site key"})
    body = _read_body(request)
    if body is None:
        logger.warning("capwx: request body over %d bytes rejected", MAX_BODY_BYTES)
        return _json_response(413, {"success": False, "error": "body_too_large"})
    return _to_bolt(_HANDLERS[name](shim, site_conf, conf, body))


async def _run(request: Request, site: str, name: str) -> Response:
    # The capwx stores are synchronous (CAPWX['STORE'] must not be async; see conf.py), and cache
    # backends may do network I/O, and hooks may use the database. So the whole synchronous body
    # runs in a worker thread and the event loop is never blocked. thread_sensitive=False: the
    # work does not need Django's single shared sync thread.
    return await sync_to_async(_serve, thread_sensitive=False)(request, site, name)


def _endpoint(name: str) -> Callable[[str, Request], Awaitable[Response]]:
    async def endpoint(site: str, request: Request) -> Response:
        return await _run(request, site, name)

    return endpoint


def _method_not_allowed() -> Callable[[str, Request], Awaitable[Response]]:
    async def not_allowed(site: str, request: Request) -> Response:
        return Response(
            {"error": "method_not_allowed"},
            status_code=405,
            headers={"Allow": "POST", "Cache-Control": _NO_STORE},
        )

    return not_allowed


# --------------------------------------------------------------------------- router


def build_router(*, tags: list[str] | None = None) -> Router:
    """A django-bolt Router with the three widget endpoints at ``/{site}/...``.

    Every other method on those paths answers 405 ``{"error": "method_not_allowed"}`` with
    ``Allow: POST``, as the Django urls do. Mount it with ``api.include_router(router, prefix="/cap")``
    or call :func:`install`.
    """
    router = Router(tags=tags)
    for name, path, summary in _ENDPOINTS:
        router.post(path, name=f"capwx_{name}", summary=summary)(_endpoint(name))
        for add in (
            router.get,
            router.put,
            router.patch,
            router.delete,
            router.head,
            router.options,
        ):
            add(path, name=f"capwx_{name}_not_allowed", include_in_schema=False)(
                _method_not_allowed()
            )
    return router


def install(api: BoltAPI, prefix: str = "/cap", *, tags: list[str] | None = None) -> None:
    """Include the widget endpoints in ``api`` under ``prefix`` (the widget base is ``prefix/<site>/``)."""
    api.include_router(build_router(tags=tags), prefix=prefix)


# --------------------------------------------------------------------------- CapRequired


class CapRequired:
    """A django-bolt dependency that requires a valid, unused capwx verification token.

    Bolt's guards (``IsAuthenticated``, ``Requires``) and auth backends are compiled to Rust and
    cannot run Python code, so the check is a dependency, passed with ``Depends`` to a handler::

        login_cap = CapRequired(site="login")

        @api.post("/orders")
        async def create_order(request: Request, _: Annotated[None, Depends(login_cap.check)]): ...

    The token comes from the ``header`` (default ``X-Cap-Token``), else from the top-level ``field``
    of a JSON body or a form-encoded body (default ``cap-token``). ``field=""`` disables the body
    lookup. It is validated and consumed through :func:`capwx.validate_token` with the site's
    scope and the configured store, so a token works once.

    A missing, invalid, expired, already-used or other-site token raises a Bolt
    ``HTTPException(403)`` whose body is ``{"error": "captcha_required"}``, the same as the Django
    ``require_cap`` decorator and the Ninja ``CapRequired``. No setup is needed for that body.
    """

    def __init__(
        self,
        site: str = DEFAULT_SITE,
        header: str = TOKEN_HEADER,
        field: str | None = None,
    ) -> None:
        self.site = site
        self.header = header
        self.field = TOKEN_FIELD if field is None else field

    async def check(self, request: Request) -> None:
        """The dependency. Runs the synchronous token check in a worker thread."""
        await sync_to_async(self._verify, thread_sensitive=False)(request)

    def _verify(self, request: Any) -> None:
        token = _extract_token(request, self.field, self.header)
        conf_site = require_site(self.site)
        if not validate_token(
            conf_site.config, token, scope=self.site, token_store=get_conf().store
        ):
            raise HTTPException(status_code=403, body={"error": "captcha_required"})


__all__ = ["CapRequired", "build_router", "install"]
