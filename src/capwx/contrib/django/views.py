"""capwx.contrib.django.views: challenge, redeem and siteverify endpoints (plan section 11.2).

Every endpoint runs the same wrapper, in this order:

1. Method: anything but POST gets 405 JSON.
2. CSRF: when ``CSRF_EXEMPT`` is False, the token is checked here, on each request. Django's
   ``CsrfViewMiddleware`` reads the exemption before the view runs, so a flag set inside the view
   would come too late. The views are always ``csrf_exempt``; the middleware skips them and this
   wrapper decides instead.
3. Site: an unknown site gets 404 ``{"error": "Invalid site key"}``.
4. Body: more than 64 KiB, by header or by the bytes actually read, gets 413.

Failure bodies are ``{"success": false, "error": <reason>}``, which is what the widget reads.
Client input never raises: malformed JSON gives 400 ``invalid_body``.
"""

from __future__ import annotations

import functools
import json
import logging
from collections.abc import Callable, Mapping
from typing import Any, cast

from django.core.exceptions import ImproperlyConfigured, PermissionDenied
from django.http import HttpResponse, JsonResponse
from django.middleware.csrf import CsrfViewMiddleware
from django.views.decorators.cache import never_cache  # pyright: ignore[reportUnknownVariableType]
from django.views.decorators.csrf import csrf_exempt  # pyright: ignore[reportUnknownVariableType]

from capwx._types import as_json_dict
from capwx.challenge import create_challenge, redeem
from capwx.contrib.django._types import DjangoRequest
from capwx.contrib.django.conf import MAX_BODY_BYTES, CapwxConf, SiteConf, get_conf
from capwx.errors import Reason
from capwx.tokens import siteverify

logger = logging.getLogger("capwx")

_INVALID_JSON = object()

# Redeem failures that are instrumentation or session-state problems answer 403.
_FORBIDDEN_REASONS = frozenset(
    {
        Reason.EXPIRED.value,
        Reason.ALREADY_REDEEMED.value,
        Reason.SCOPE_MISMATCH.value,
        Reason.ID_MISMATCH.value,
        Reason.FAILED_CHALLENGE.value,
        "missing_meta",
        "invalid_meta",
    }
)
_SITEVERIFY_STATUS = {"missing_parameters": 400, "invalid_secret": 403, "invalid_token": 400}


def _json(status: int, data: Mapping[str, Any]) -> JsonResponse:
    return JsonResponse(dict(data), status=status)


def _failure(status: int, error: str) -> JsonResponse:
    return _json(status, {"success": False, "error": error})


def _reason_text(reason: object) -> str:
    return reason.value if isinstance(reason, Reason) else str(reason)


def redeem_status(reason: object) -> int:
    """HTTP status for a failed redeem: 403 for expired/replayed/instrumentation, 500 for store
    outages, 400 for everything else (malformed or invalid input)."""
    text = _reason_text(reason)
    if text == Reason.NONCE_STORE_ERROR.value:
        return 500
    if text in _FORBIDDEN_REASONS or text.startswith("instr_"):
        return 403
    return 400


def _parse_json(data: bytes) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return _INVALID_JSON


def _read_body(request: DjangoRequest) -> bytes | None:
    """The request body, or None when it exceeds MAX_BODY_BYTES (the header is not trusted)."""
    cached = getattr(request, "_body", None)
    if cached is not None:
        return cached if len(cached) <= MAX_BODY_BYTES else None
    declared = request.META.get("CONTENT_LENGTH", "")
    if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        return None
    try:
        data = request.read(MAX_BODY_BYTES + 1)
    except OSError:  # UnreadablePostError: treat as an empty body, the JSON parse rejects it
        return b""
    return None if len(data) > MAX_BODY_BYTES else data


def _noop(request: DjangoRequest) -> None:
    return None


def _csrf_gate(request: DjangoRequest) -> JsonResponse | None:
    """Enforce CSRF now (not at import time) when the CAPWX ``CSRF_EXEMPT`` setting is False."""
    if get_conf().csrf_exempt:
        return None

    def _probe_view(request: DjangoRequest) -> None:  # has no csrf_exempt, so the check applies
        return None

    middleware = CsrfViewMiddleware(_noop)
    if middleware.process_view(request, _probe_view, (), {}) is None:  # pyright: ignore[reportUnknownMemberType]
        return None
    logger.warning("capwx: CSRF check failed for %s", request.path)
    return _failure(403, "csrf_failed")


Handler = Callable[[DjangoRequest, SiteConf, CapwxConf, bytes], HttpResponse]


def _endpoint(handler: Handler) -> Callable[..., HttpResponse]:
    @csrf_exempt
    @never_cache
    @functools.wraps(handler)
    def view(request: DjangoRequest, site: str) -> HttpResponse:
        if request.method != "POST":
            response = _json(405, {"error": "method_not_allowed"})
            response["Allow"] = "POST"
            return response
        denied = _csrf_gate(request)
        if denied is not None:
            return denied
        conf = get_conf()
        site_conf = conf.sites.get(site)
        if site_conf is None:
            return _json(404, {"error": "Invalid site key"})
        body = _read_body(request)
        if body is None:
            logger.warning("capwx: request body over %d bytes rejected", MAX_BODY_BYTES)
            return _failure(413, "body_too_large")
        return handler(request, site_conf, conf, body)

    return view


def _challenge(
    request: DjangoRequest, site_conf: SiteConf, conf: CapwxConf, body: bytes
) -> HttpResponse:
    if conf.before_challenge_hook is not None:
        try:
            conf.before_challenge_hook(request, site_conf.name)
        except PermissionDenied:
            # The hook's message is not logged: it may describe the client.
            logger.info("capwx: challenge blocked site=%s", site_conf.name)
            return _failure(403, "blocked")
    overrides: Mapping[str, Any] | None = None
    if conf.difficulty_hook is not None:
        hook_result: object = conf.difficulty_hook(request, site_conf.name)
        if hook_result is not None and not isinstance(hook_result, Mapping):
            raise ImproperlyConfigured("CAPWX['DIFFICULTY_HOOK'] must return a dict or None")
        overrides = cast("Mapping[str, Any] | None", hook_result)
    payload = create_challenge(site_conf.config, scope=site_conf.name, overrides=overrides)
    return _json(200, payload)


def _redeem(
    request: DjangoRequest, site_conf: SiteConf, conf: CapwxConf, body: bytes
) -> HttpResponse:
    parsed = _parse_json(body)
    if parsed is _INVALID_JSON:
        return _failure(400, Reason.INVALID_BODY.value)
    result = redeem(
        site_conf.config,
        parsed,
        scope=site_conf.name,
        nonce_store=conf.store,
        token_store=conf.store,
    )
    status = 200 if result.success else redeem_status(result.reason)
    return _json(status, result.to_widget_json())


def _siteverify(
    request: DjangoRequest, site_conf: SiteConf, conf: CapwxConf, body: bytes
) -> HttpResponse:
    parsed = _parse_json(body)
    data = None if parsed is _INVALID_JSON else as_json_dict(parsed)
    if data is None:
        return _failure(400, Reason.INVALID_BODY.value)
    if site_conf.site_secret is None:
        return _failure(404, "siteverify_not_configured")
    result = siteverify(
        site_conf.config,
        data.get("secret"),
        data.get("response"),
        site_secret=site_conf.site_secret,
        scope=site_conf.name,
        token_store=conf.store,
    )
    if result["success"]:
        return _json(200, result)
    return _json(_SITEVERIFY_STATUS.get(result.get("error", ""), 400), result)


challenge_view = _endpoint(_challenge)
redeem_view = _endpoint(_redeem)
siteverify_view = _endpoint(_siteverify)

__all__ = ["challenge_view", "redeem_status", "redeem_view", "siteverify_view"]
