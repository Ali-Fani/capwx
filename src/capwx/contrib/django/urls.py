"""capwx.contrib.django.urls: widget endpoints. Mount with ``path("cap/", include(...))``.

The widget's base endpoint is then ``/cap/<site>/``, and it posts to ``.../challenge``,
``.../redeem`` and ``.../siteverify``.
"""

from django.urls import path

from capwx.contrib.django import views

app_name = "capwx"

urlpatterns = [
    path("<str:site>/challenge", views.challenge_view, name="challenge"),
    path("<str:site>/redeem", views.redeem_view, name="redeem"),
    path("<str:site>/siteverify", views.siteverify_view, name="siteverify"),
]
