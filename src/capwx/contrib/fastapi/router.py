"""capwx.contrib.fastapi.router: the widget endpoints (challenge, redeem, siteverify) as an APIRouter.

The behaviour is the Django views' behaviour (``capwx.contrib.django.views``): the same JSON
bodies, status codes and ``{"success": false, "error": ...}`` failures. Order of checks per request:

1. Method: anything but POST gets 405 JSON with ``Allow: POST``.
2. Site: an unknown site gets 404 ``{"error": "Invalid site key"}``.
3. Body: more than ``MAX_BODY_BYTES`` gets 413. The Content-Length header is not trusted; the
   bytes are counted as they arrive.
4. The endpoint itself.

Every response carries ``Cache-Control: no-store``. Responses are returned as ``JSONResponse``, so
FastAPI does not validate or re-serialise them.
"""

from __future__ import annotations

import inspect
import json
import logging
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Final, cast

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.requests import ClientDisconnect

from capwx import acreate_challenge, aredeem
from capwx._http import MAX_BODY_BYTES, redeem_status, siteverify_status
from capwx._types import as_json_dict
from capwx.errors import CapwxError, Reason
from capwx.tokens import asiteverify

if TYPE_CHECKING:
    from capwx.contrib.fastapi.config import Cap

logger = logging.getLogger("capwx")

_NON_POST_METHODS: Final = ["GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]
_INVALID: Final = object()


class Blocked(Exception):
    """Raise from ``before_challenge`` to refuse a challenge: the client gets 403
    ``{"success": false, "error": "blocked"}``. The message is neither sent nor logged."""


def _json(
    status: int, data: Mapping[str, Any], headers: Mapping[str, str] | None = None
) -> JSONResponse:
    extra = dict(headers or {})
    return JSONResponse(
        dict(data), status_code=status, headers={"Cache-Control": "no-store", **extra}
    )


def _failure(status: int, error: str) -> JSONResponse:
    return _json(status, {"success": False, "error": error})


def _parse_json(data: bytes) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return _INVALID


async def read_limited_body(request: Request) -> bytes | None:
    """The request body, or None when it exceeds MAX_BODY_BYTES.

    Reads the stream and counts the bytes, so a missing or lying Content-Length cannot bypass the
    cap. The bytes are cached on the request the way Starlette's ``request.body()`` caches them,
    so the endpoint (and any form parser) can still read the body after this call.
    """
    chunks: list[bytes] = []
    size = 0
    try:
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                return None
            chunks.append(chunk)
    except ClientDisconnect:
        pass  # a truncated body fails the JSON parse, which answers 400
    body = b"".join(chunks)
    # Starlette keeps the body in this attribute for request.body(); setting it is the cache.
    setattr(request, "_body", body)  # noqa: B010
    return body


async def _maybe_await(value: object) -> Any:
    return await value if inspect.isawaitable(value) else value


async def _not_allowed() -> JSONResponse:
    return _json(405, {"error": "method_not_allowed"}, {"Allow": "POST"})


def build_router(cap: Cap) -> APIRouter:
    """The widget router for ``cap``. Mount it with ``app.include_router(cap.router, prefix=...)``."""
    router = APIRouter()

    async def _gate(site: str, request: Request) -> JSONResponse | bytes:
        """The site and body checks shared by the three endpoints: a response, or the body."""
        if site not in cap.sites:
            return _json(404, {"error": "Invalid site key"})
        body = await read_limited_body(request)
        if body is None:
            logger.warning("capwx: request body over %d bytes rejected", MAX_BODY_BYTES)
            return _failure(413, "body_too_large")
        return body

    @router.post("/{site}/challenge", summary="Issue a challenge for a site")
    async def challenge(site: str, request: Request) -> JSONResponse:
        gated = await _gate(site, request)
        if isinstance(gated, JSONResponse):
            return gated
        if cap.before_challenge is not None:
            try:
                await _maybe_await(cap.before_challenge(request, site))
            except Blocked:
                logger.info("capwx: challenge blocked site=%s", site)
                return _failure(403, "blocked")
        overrides: Mapping[str, Any] | None = None
        if cap.difficulty_hook is not None:
            hook_result: object = await _maybe_await(cap.difficulty_hook(request, site))
            if hook_result is not None and not isinstance(hook_result, Mapping):
                raise CapwxError("difficulty_hook must return a mapping or None")
            overrides = cast("Mapping[str, Any] | None", hook_result)
        payload = await acreate_challenge(cap.sites[site].config, scope=site, overrides=overrides)
        return _json(200, payload)

    @router.post("/{site}/redeem", summary="Redeem solved challenges for a verification token")
    async def redeem(site: str, request: Request) -> JSONResponse:
        gated = await _gate(site, request)
        if isinstance(gated, JSONResponse):
            return gated
        parsed = _parse_json(gated)
        if parsed is _INVALID:
            return _failure(400, Reason.INVALID_BODY.value)
        result = await aredeem(
            cap.sites[site].config,
            parsed,
            scope=site,
            nonce_store=cap.store,
            token_store=cap.store,
        )
        status = 200 if result.success else redeem_status(result.reason)
        return _json(status, result.to_widget_json())

    @router.post(
        "/{site}/siteverify", summary="ReCAPTCHA-style server-side verification of a token"
    )
    async def siteverify(site: str, request: Request) -> JSONResponse:
        gated = await _gate(site, request)
        if isinstance(gated, JSONResponse):
            return gated
        parsed = _parse_json(gated)
        data = None if parsed is _INVALID else as_json_dict(parsed)
        if data is None:
            return _failure(400, Reason.INVALID_BODY.value)
        site_settings = cap.sites[site]
        secret = site_settings.site_secret
        if secret is None:
            return _failure(404, "siteverify_not_configured")
        result = await asiteverify(
            site_settings.config,
            data.get("secret"),
            data.get("response"),
            site_secret=secret,
            scope=site,
            token_store=cap.store,
        )
        if result["success"]:
            return _json(200, result)
        return _json(siteverify_status(result.get("error")), result)

    for path in ("/{site}/challenge", "/{site}/redeem", "/{site}/siteverify"):
        router.add_api_route(path, _not_allowed, methods=_NON_POST_METHODS, include_in_schema=False)

    return router
