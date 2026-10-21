"""capwx.contrib.drf.views: the widget endpoints as Django REST Framework ``APIView`` classes.

``ChallengeView``, ``RedeemView`` and ``SiteverifyView`` answer POST for ``<site>/challenge``,
``<site>/redeem`` and ``<site>/siteverify``. Each one hands the request to the very same Django view
function that :mod:`capwx.contrib.django.views` defines, so the JSON bodies, status codes, 404 for an
unknown site, 413 for bodies over 64 KiB, 400 ``invalid_body``, CSRF gate and the 405 answer for other
methods are identical to the Django urls.

Three things differ from a stock ``APIView``, and each one keeps that behaviour:

* Content negotiation is skipped. An ``Accept`` header that DRF cannot satisfy would otherwise answer
  406 before the Django view runs.
* Only ``post`` is a handler. Every other method goes to :meth:`http_method_not_allowed`, which runs
  the Django view. That view answers 405 JSON with ``Allow: POST``, and DRF's own 405 body is not used.
* DRF's default response headers are not added. DRF would otherwise overwrite ``Allow``.

The Django view reads the original ``HttpRequest`` (``request._request``). DRF parsers are disabled,
so nothing reads the body before the view does.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, ClassVar, cast

from django.http import HttpResponse
from rest_framework.permissions import AllowAny  # pyright: ignore[reportUnknownVariableType]
from rest_framework.renderers import JSONRenderer  # pyright: ignore[reportUnknownVariableType]
from rest_framework.views import APIView  # pyright: ignore[reportUnknownVariableType]

from capwx.contrib.django._types import DjangoRequest
from capwx.contrib.django.views import challenge_view, redeem_view, siteverify_view

DjangoEndpoint = Callable[[DjangoRequest, str], HttpResponse]


class _WidgetAPIView(APIView):  # pyright: ignore[reportUntypedBaseClass]
    """Shared settings and delegation for the three widget endpoints. Not routed by itself."""

    # The widget is anonymous: no DRF authentication (so no CSRF enforcement by SessionAuthentication)
    # and no permission check. The Django view does the CSRF check when CSRF_EXEMPT is False.
    authentication_classes: ClassVar[list[type[Any]]] = []
    permission_classes: ClassVar[list[type[Any]]] = [AllowAny]
    # The Django view reads the raw body itself. Disabling DRF parsers keeps DRF from consuming it.
    parser_classes: ClassVar[list[type[Any]]] = []
    renderer_classes: ClassVar[list[type[Any]]] = [JSONRenderer]
    # Only POST is a handler. Every other method, including OPTIONS and HEAD, goes to
    # http_method_not_allowed, which answers like the Django view (405 JSON with Allow: POST).
    http_method_names: ClassVar[list[str]] = ["post"]

    def _django_view(self) -> DjangoEndpoint:
        """The Django view this endpoint delegates to. Each subclass returns its own."""
        raise NotImplementedError

    @property
    def default_response_headers(self) -> dict[str, str]:
        # DRF would set Allow (and Vary) here. Allow must stay "POST" on the 405 answer.
        return {}

    def perform_content_negotiation(self, request: Any, force: bool = False) -> Any:
        # Accept headers are not part of the widget protocol. The Django views always answer JSON.
        renderers = cast("list[Any]", self.get_renderers())  # pyright: ignore[reportUnknownMemberType]
        renderer: Any = renderers[0]
        return renderer, renderer.media_type

    def post(self, request: DjangoRequest, site: str) -> HttpResponse:
        return self._django_view()(request._request, site)

    def http_method_not_allowed(  # pyright: ignore[reportIncompatibleMethodOverride]
        self, request: DjangoRequest, *args: Any, **kwargs: Any
    ) -> HttpResponse:
        # The Django view answers non-POST with 405 JSON and Allow: POST, the same as the urls.
        return self._django_view()(request._request, kwargs["site"])


class ChallengeView(_WidgetAPIView):  # pyright: ignore[reportUntypedBaseClass]
    """POST ``<site>/challenge``: issue a challenge for the site."""

    def _django_view(self) -> DjangoEndpoint:
        return challenge_view


class RedeemView(_WidgetAPIView):  # pyright: ignore[reportUntypedBaseClass]
    """POST ``<site>/redeem``: redeem solved challenges for a verification token."""

    def _django_view(self) -> DjangoEndpoint:
        return redeem_view


class SiteverifyView(_WidgetAPIView):  # pyright: ignore[reportUntypedBaseClass]
    """POST ``<site>/siteverify``: ReCAPTCHA-style server-side check of a token."""

    def _django_view(self) -> DjangoEndpoint:
        return siteverify_view


__all__ = ["ChallengeView", "RedeemView", "SiteverifyView"]
