"""URLconf for the capwx ninja contrib tests (tests/test_ninja.py), selected per test via settings.

``api`` mounts the widget router and installs the ``captcha_required`` body. ``plain_api`` does not
call ``install``, so its CapRequired failures show ninja's default ``{"detail": ...}`` body.
"""

from django.urls import path
from ninja import NinjaAPI

from capwx.contrib.ninja import CapRequired, build_router, install

api = NinjaAPI(urls_namespace="capwx-ninja-tests")
install(api)
api.add_router("/cap/", build_router(tags=["capwx"]))


@api.post("/protected", auth=CapRequired(site="login"))
def protected(request):
    return {"ok": True}


@api.post("/header-only", auth=CapRequired(site="login", field=""))
def header_only(request):
    return {"ok": True}


plain_api = NinjaAPI(urls_namespace="capwx-ninja-plain")
plain_api.add_router("/cap/", build_router())


@plain_api.post("/protected", auth=CapRequired(site="login"))
def plain_protected(request):
    return {"ok": True}


urlpatterns = [
    path("api/", api.urls),
    path("plain/", plain_api.urls),
]
