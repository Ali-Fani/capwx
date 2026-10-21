"""capwx.contrib.drf.urls: the DRF widget endpoints. Mount with ``path("cap/", include(...))``.

    path("cap/", include("capwx.contrib.drf.urls"))

The widget's base endpoint is then ``/cap/<site>/`` (``data-cap-api-endpoint="/cap/login/"``), which
posts to ``.../challenge``, ``.../redeem`` and ``.../siteverify``. The namespace is ``capwx_drf``, so
it does not clash with ``capwx.contrib.django.urls`` (namespace ``capwx``).
"""

from django.urls import path

from capwx.contrib.drf.views import ChallengeView, RedeemView, SiteverifyView

app_name = "capwx_drf"

urlpatterns = [
    path("<str:site>/challenge", ChallengeView.as_view(), name="challenge"),  # pyright: ignore[reportUnknownMemberType]
    path("<str:site>/redeem", RedeemView.as_view(), name="redeem"),  # pyright: ignore[reportUnknownMemberType]
    path("<str:site>/siteverify", SiteverifyView.as_view(), name="siteverify"),  # pyright: ignore[reportUnknownMemberType]
]
