"""capwx.contrib.drf.permissions: ``IsCapVerified``, a DRF permission that requires a capwx token.

Usage::

    from capwx.contrib.drf.permissions import IsCapVerified, cap_permission

    class OrderView(APIView):
        permission_classes = [cap_permission(site="login")]   # or a subclass of IsCapVerified

The token comes from the ``X-Cap-Token`` header first, then from the top-level ``cap-token`` field of
the parsed DRF body (``request.data``). Both are read through DRF, so they work with any DRF parser.
Pass ``field=""`` to accept the header only.

The token is validated and consumed through :func:`capwx.tokens.validate_token`, so one token works
for one request. The decision is cached on the Django request, so a request that passes through
several permission checks still consumes the token once.

A missing, invalid, expired or used token raises :class:`CaptchaRequired`. That is a 403 with the body
``{"error": "captcha_required"}``, the same body as ``require_cap``. The exception is raised from
``has_permission`` on purpose: DRF's own ``permission_denied`` would answer 401 when the view has
authentication classes, and it would render ``{"detail": ...}``.
"""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from django.core.exceptions import RequestDataTooBig
from rest_framework.exceptions import (  # pyright: ignore[reportUnknownVariableType]
    APIException,
    PermissionDenied,
)
from rest_framework.permissions import BasePermission  # pyright: ignore[reportUnknownVariableType]

from capwx._types import as_mapping
from capwx.contrib.django._types import DjangoRequest
from capwx.contrib.django.conf import (
    DEFAULT_SITE,
    TOKEN_FIELD,
    TOKEN_HEADER,
    get_conf,
    require_site,
)
from capwx.tokens import validate_token

# Attribute on the Django HttpRequest that caches the verification result for this request.
_CACHE_ATTR = "_capwx_drf_verified"


class CaptchaRequired(PermissionDenied):  # pyright: ignore[reportUntypedBaseClass]
    """403 ``{"error": "captcha_required"}``. A dict ``detail`` is rendered as the whole body."""

    default_detail: ClassVar[dict[str, str]] = {"error": "captcha_required"}
    default_code: ClassVar[str] = "captcha_required"


def cap_token_from_request(request: DjangoRequest, field: str, header: str) -> str | None:
    """The verification token of a DRF request: the header, else the body field, else None.

    The header wins when it is present and non-empty. ``field=""`` skips the body lookup. The body
    is read through DRF (``request.data``), because DRF may already have read the stream, and a second
    read of the raw body would fail. A body that DRF cannot parse yields None.
    """
    value = request.headers.get(header)
    if value:
        return value if isinstance(value, str) else None
    if not field:
        return None
    try:
        data: object = request.data
    except (APIException, RequestDataTooBig):
        return None
    mapping = as_mapping(data)
    if mapping is None:
        return None
    token: object = mapping.get(field)
    return token if isinstance(token, str) else None


def verify_cap_token(site: str, token: str | None) -> bool:
    """True when ``token`` is valid and unused for ``site``. Consumes the token when it is valid.

    An unknown site raises ``ImproperlyConfigured`` (a configuration error, as in ``require_cap``).
    """
    if not token:
        return False
    conf_site = require_site(site)
    return validate_token(conf_site.config, token, scope=site, token_store=get_conf().store)


class IsCapVerified(BasePermission):  # pyright: ignore[reportUntypedBaseClass]
    """Grant access only with a valid, unused capwx token for ``site``.

    Configure it by subclassing (set ``site``, ``header`` and ``field``), or with
    :func:`cap_permission`.
    """

    site: ClassVar[str] = DEFAULT_SITE
    header: ClassVar[str] = TOKEN_HEADER
    field: ClassVar[str] = TOKEN_FIELD

    def has_permission(self, request: DjangoRequest, view: object) -> Literal[True]:
        http_request: Any = request._request
        cache: dict[tuple[str, str, str], bool] | None = getattr(http_request, _CACHE_ATTR, None)
        if cache is None:
            cache = {}
            setattr(http_request, _CACHE_ATTR, cache)
        key = (self.site, self.header, self.field)
        verified = cache.get(key)
        if verified is None:
            token = cap_token_from_request(request, self.field, self.header)
            verified = verify_cap_token(self.site, token)
            cache[key] = verified
        if not verified:
            raise CaptchaRequired()
        return True


def cap_permission(
    site: str = DEFAULT_SITE, header: str = TOKEN_HEADER, field: str = TOKEN_FIELD
) -> type[IsCapVerified]:
    """A subclass of :class:`IsCapVerified` for one site, header and body field."""
    return type(
        "IsCapVerified",
        (IsCapVerified,),
        {"site": site, "header": header, "field": field, "__module__": __name__},
    )


__all__ = ["CaptchaRequired", "IsCapVerified", "cap_permission", "cap_token_from_request"]
