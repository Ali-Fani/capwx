"""capwx.contrib.fastapi.deps: ``Depends(cap.require(...))`` and the 403 response body.

Mirrors :func:`capwx.contrib.django.decorators.require_cap`: the token comes from the header, else
the top-level ``field`` of a JSON body, else a form field (POST only). It is checked and consumed
once, with the site's config, scope = site and the shared store.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Final
from urllib.parse import parse_qsl

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.applications import Starlette
from starlette.formparsers import MultiPartException

from capwx import avalidate_token
from capwx._types import as_json_dict
from capwx.contrib.fastapi.router import read_limited_body

if TYPE_CHECKING:
    from capwx.contrib.fastapi.config import Cap

DEFAULT_SITE: Final = "default"
TOKEN_HEADER: Final = "X-Cap-Token"
TOKEN_FIELD: Final = "cap-token"

_JSON: Final = "application/json"
_URLENCODED: Final = "application/x-www-form-urlencoded"
_MULTIPART: Final = "multipart/form-data"


class CaptchaRequired(HTTPException):
    """Raised by the dependency when the token is missing, invalid, expired or already used.

    Without :meth:`Cap.install`, the body is FastAPI's default ``{"detail": "captcha_required"}``.
    With it, the body is ``{"error": "captcha_required"}``, as in the Django and Ninja adapters.
    """

    def __init__(self) -> None:
        super().__init__(status_code=403, detail="captcha_required")


async def _token(request: Request, field: str, header: str) -> object:
    """The token from the header, else the body (JSON, urlencoded or multipart). None if absent."""
    value = request.headers.get(header)
    if value:
        return value
    if not field:  # field="" disables the body lookup
        return None
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type not in (_JSON, _URLENCODED, _MULTIPART):
        return None
    if content_type != _JSON and request.method != "POST":
        return None
    try:
        body = await read_limited_body(request)  # bounded, and cached for the endpoint
    except RuntimeError:  # FastAPI already read the stream for a Form/File parameter
        form = getattr(request, "_form", None)  # Starlette caches the parsed form here
        return None if form is None else form.get(field)
    if body is None:
        return None
    if content_type == _JSON:
        try:
            data = as_json_dict(json.loads(body.decode("utf-8")))
        except (UnicodeDecodeError, ValueError, RecursionError):
            return None
        return None if data is None else data.get(field)
    if content_type == _URLENCODED:
        return dict(parse_qsl(body.decode("utf-8", errors="replace"))).get(field)
    try:
        form = await request.form()  # reads the cached body; needs python-multipart
    except (AssertionError, MultiPartException, HTTPException):
        return None
    return form.get(field)


def make_require(
    cap: Cap, site: str, header: str, field: str
) -> Callable[[Request], Awaitable[None]]:
    """The dependency for one site. :meth:`Cap.require` checks that the site exists first."""

    async def require_cap(request: Request) -> None:
        token = await _token(request, field, header)
        if not await avalidate_token(
            cap.sites[site].config, token, scope=site, token_store=cap.store
        ):
            raise CaptchaRequired()

    return require_cap


def install_handler(app: Starlette) -> None:
    """Answer :class:`CaptchaRequired` with ``403 {"error": "captcha_required"}``.

    Only that exception class is handled, so other HTTPExceptions keep FastAPI's default bodies.
    """

    async def handle(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            {"error": "captcha_required"}, status_code=403, headers={"Cache-Control": "no-store"}
        )

    app.add_exception_handler(CaptchaRequired, handle)
