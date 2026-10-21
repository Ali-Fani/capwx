"""capwx.contrib.ninja.router: Django Ninja endpoints and the ``CapRequired`` auth helper (plan §11.2).

Mount the widget endpoints under a ``NinjaAPI``::

    from ninja import NinjaAPI
    from capwx.contrib.ninja import build_router, CapRequired, install

    api = NinjaAPI()
    install(api)  # optional, see CapRequired below
    api.add_router("/cap/", build_router())

    @api.post("/orders", auth=CapRequired(site="login"))
    def create_order(request): ...

The widget's base endpoint is then ``/api/cap/<site>/`` (``data-cap-api-endpoint="/api/cap/login/"``),
which posts to ``.../challenge``, ``.../redeem`` and ``.../siteverify``.

Behaviour is the Django views' behaviour, because the ninja operations call the very same view
functions (``capwx.contrib.django.views``): identical JSON bodies, status codes, 404 for an unknown
site, 413 for bodies over 64 KiB, 400 ``invalid_body`` for malformed JSON, and the same
``CSRF_EXEMPT`` handling. Any method other than POST answers 405 with the same JSON body as the
Django urls (``{"error": "method_not_allowed"}`` and ``Allow: POST``), not ninja's plain-text 405.

Request body schemas (``ninja.Schema``) appear in the OpenAPI document only. They do not validate
the request, because strict validation would change the documented 400 ``invalid_body`` and 413
behaviour; the view parses the raw body itself.

CSRF: django-ninja 1.7 has no ``csrf`` flag on ``NinjaAPI``. Its views are always ``csrf_exempt``
at Django's middleware level, so the widget endpoints are governed by ``CAPWX["CSRF_EXEMPT"]``
exactly as in the Django urls. With ``CSRF_EXEMPT: False`` the views check the CSRF token
themselves, so ``{% capwx_scripts %}`` must install ``CAP_CUSTOM_FETCH`` as usual.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from django.http import HttpResponse
from ninja import NinjaAPI, Router, Schema
from ninja.errors import HttpError
from ninja.security import APIKeyHeader

from capwx.contrib.django._types import DjangoRequest
from capwx.contrib.django.conf import (
    DEFAULT_SITE,
    TOKEN_FIELD,
    TOKEN_HEADER,
    get_conf,
    require_site,
)
from capwx.contrib.django.decorators import extract_token
from capwx.contrib.django.views import challenge_view, redeem_view, siteverify_view
from capwx.tokens import validate_token

# Every method except POST. The Django views answer these with 405 JSON, so the ninja router sends
# them there too instead of ninja's plain-text 405.
_NON_POST_METHODS = ["GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]
_ERROR_STATUSES = (400, 403, 404, 413, 500)


# --------------------------------------------------------------------------- documentation schemas


class ErrorOut(Schema):
    success: bool = False
    error: str


class ChallengeOut(Schema):
    format: int
    token: str
    expires: int
    challenges: list[dict[str, Any]]


class RedeemOut(Schema):
    success: bool
    token: str | None = None
    expires: int | None = None
    error: str | None = None


class RedeemIn(Schema):
    token: str
    solutions: list[dict[str, Any]]


class SiteverifyIn(Schema):
    secret: str
    response: str


class SiteverifyOut(Schema):
    success: bool
    error: str | None = None


def _json_body(model: type[Schema]) -> dict[str, Any]:
    return {
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": model.model_json_schema()}},
        }
    }


_CHALLENGE_RESPONSES: dict[int, Any] = {200: ChallengeOut, 403: ErrorOut, 404: ErrorOut}
_REDEEM_RESPONSES: dict[int, Any] = {
    200: RedeemOut,
    400: ErrorOut,
    403: ErrorOut,
    404: ErrorOut,
    413: ErrorOut,
    500: ErrorOut,
}
_SITEVERIFY_RESPONSES: dict[int, Any] = {
    200: SiteverifyOut,
    400: ErrorOut,
    403: ErrorOut,
    404: ErrorOut,
    413: ErrorOut,
}

ViewFn = Callable[[DjangoRequest, str], HttpResponse]


def _site_operation(view: ViewFn) -> Callable[[DjangoRequest, str], HttpResponse]:
    """Adapt a Django view taking (request, site) into a ninja operation of the same shape."""

    def operation(request: DjangoRequest, site: str) -> HttpResponse:
        return view(request, site)

    return operation


# --------------------------------------------------------------------------- router


def build_router(*, tags: Iterable[str] | None = None) -> Router:
    """A ninja Router with the three widget endpoints, mounted at ``/{site}/...``.

    ``tags`` are passed to the router, so they group the operations in the OpenAPI document.
    Mount it with ``api.add_router("/cap/", build_router())``.
    """
    router = Router(tags=list(tags) if tags is not None else None)

    @router.post(
        "/{site}/challenge",
        response=_CHALLENGE_RESPONSES,
        summary="Issue a challenge for a site",
    )
    def challenge(request: DjangoRequest, site: str) -> HttpResponse:
        return challenge_view(request, site)

    @router.post(
        "/{site}/redeem",
        response=_REDEEM_RESPONSES,
        openapi_extra=_json_body(RedeemIn),
        summary="Redeem solved challenges for a verification token",
    )
    def redeem(request: DjangoRequest, site: str) -> HttpResponse:
        return redeem_view(request, site)

    @router.post(
        "/{site}/siteverify",
        response=_SITEVERIFY_RESPONSES,
        openapi_extra=_json_body(SiteverifyIn),
        summary="ReCAPTCHA-style server-side verification of a token",
    )
    def siteverify(request: DjangoRequest, site: str) -> HttpResponse:
        return siteverify_view(request, site)

    for path, view in (
        ("/{site}/challenge", challenge_view),
        ("/{site}/redeem", redeem_view),
        ("/{site}/siteverify", siteverify_view),
    ):
        router.add_api_operation(  # pyright: ignore[reportUnknownMemberType]
            path, _NON_POST_METHODS, _site_operation(view), include_in_schema=False
        )

    return router


# --------------------------------------------------------------------------- CapRequired


class CaptchaRequired(HttpError):
    """Raised by :class:`CapRequired` when the token is missing, invalid, expired or already used."""

    def __init__(self) -> None:
        super().__init__(403, "captcha_required")


class CapRequired(APIKeyHeader):
    """Ninja auth that requires a valid, unused capwx verification token.

    Usage: ``@api.post("/orders", auth=CapRequired(site="login"))``.

    The token comes from the ``header`` (default ``X-Cap-Token``), otherwise from the top-level
    ``field`` of a JSON body or a form POST. ``field=None`` means ``"cap-token"``, the same as
    :func:`capwx.contrib.django.decorators.require_cap`; ``field=""`` disables the body lookup.
    The token is validated and consumed through :func:`capwx.validate_token` with the configured
    store, so one token works for one request only.

    Failure is a 403 ``{"error": "captcha_required"}``, the same as ``require_cap``. That body
    needs :func:`install` on the ``NinjaAPI``. Without it, the body is ninja's default
    ``{"detail": "captcha_required"}`` with status 403.
    """

    openapi_description = "A capwx verification token (single use)."

    def __init__(
        self,
        site: str = DEFAULT_SITE,
        header: str = TOKEN_HEADER,
        field: str | None = None,
    ) -> None:
        self.site = site
        self.header = header
        self.field = TOKEN_FIELD if field is None else field
        self.param_name = header
        super().__init__()

    def _get_key(self, request: DjangoRequest) -> str | None:
        token = extract_token(request, self.field, self.header)
        return token if isinstance(token, str) else None

    def authenticate(self, request: DjangoRequest, key: str | None) -> str | None:
        conf_site = require_site(self.site)
        if key and validate_token(
            conf_site.config, key, scope=self.site, token_store=get_conf().store
        ):
            return self.site
        raise CaptchaRequired()


def install(api: NinjaAPI) -> None:
    """Answer :class:`CapRequired` failures with ``403 {"error": "captcha_required"}``.

    Call it once for each ``NinjaAPI`` that uses ``CapRequired``. Without it, the body is
    ninja's default ``{"detail": "captcha_required"}``. Other exception handlers are unaffected.
    """

    def handle(request: DjangoRequest, exc: object) -> HttpResponse:
        return api.create_response(request, {"error": "captcha_required"}, status=403)

    api.add_exception_handler(CaptchaRequired, handle)


__all__ = ["CapRequired", "CaptchaRequired", "build_router", "install"]
