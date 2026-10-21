"""capwx.contrib.django.decorators: @require_cap for function views and JSON APIs."""

from __future__ import annotations

import functools
import json
from collections.abc import Callable
from typing import Any

from django.core.exceptions import RequestDataTooBig
from django.http import (
    HttpResponse,
    JsonResponse,
    RawPostDataException,
)

from capwx._types import as_json_dict
from capwx.contrib.django._types import DjangoRequest
from capwx.contrib.django.conf import (
    DEFAULT_SITE,
    TOKEN_FIELD,
    TOKEN_HEADER,
    get_conf,
    require_site,
)
from capwx.tokens import validate_token


def extract_token(request: DjangoRequest, field: str, header: str) -> object:
    """Token from the header, else the POST field, else a top-level JSON body field."""
    value = request.META.get("HTTP_" + header.upper().replace("-", "_"))
    if value:
        return value
    if not field:  # field="" disables the body lookup (CapRequired documents this)
        return None
    if request.method == "POST" and field in request.POST:
        return request.POST.get(field)
    if request.content_type == "application/json":
        try:
            data = as_json_dict(json.loads(request.body))
        except (ValueError, OSError, RequestDataTooBig, RawPostDataException):
            return None
        if data is not None:
            return data.get(field)
    return None


def require_cap(
    site: str = DEFAULT_SITE, field: str = TOKEN_FIELD, header: str = TOKEN_HEADER
) -> Callable[[Callable[..., HttpResponse]], Callable[..., HttpResponse]]:
    """Reject the request with 403 ``{"error": "captcha_required"}`` unless it carries a valid,
    unused verification token for ``site``. The token is checked when the request arrives, so
    a view decorated this way must not run its own side effects before the decorator."""

    def decorator(view: Callable[..., HttpResponse]) -> Callable[..., HttpResponse]:
        @functools.wraps(view)
        def wrapper(request: DjangoRequest, *args: Any, **kwargs: Any) -> HttpResponse:
            token = extract_token(request, field, header)
            conf_site = require_site(site)
            if not validate_token(
                conf_site.config, token, scope=site, token_store=get_conf().store
            ):
                return JsonResponse({"error": "captcha_required"}, status=403)
            return view(request, *args, **kwargs)

        return wrapper

    return decorator
