"""URLconf for the capwx DRF contrib tests (tests/test_drf.py), selected per test via settings.

The widget endpoints are mounted at ``drf/cap/``. The other views show the permission and serializer
helpers. ``ProtectedView`` has no DRF authentication, ``BasicProtectedView`` has one (one that sends a
WWW-Authenticate challenge), to check that a captcha failure is still 403 and never a 401.
"""

from django.urls import include, path
from rest_framework import serializers
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from capwx.contrib.drf import CapTokenField, cap_permission


class ProtectedView(APIView):
    authentication_classes = ()
    permission_classes = (cap_permission(site="login"),)

    def post(self, request):
        return Response({"ok": True})


class HeaderOnlyView(APIView):
    authentication_classes = ()
    permission_classes = (cap_permission(site="login", field=""),)

    def post(self, request):
        return Response({"ok": True})


class ChallengingAuthentication:
    """Authenticates nobody and sends a WWW-Authenticate header, as Basic auth does. DRF only calls
    these two methods, so no base class is needed. Importing rest_framework.authentication would
    pull in django.contrib.auth, which needs INSTALLED_APPS."""

    def authenticate(self, request):
        return None

    def authenticate_header(self, request):
        return 'Basic realm="capwx"'


class BasicProtectedView(APIView):
    authentication_classes = (ChallengingAuthentication,)
    permission_classes = (cap_permission(site="login"),)

    def post(self, request):
        return Response({"ok": True})


class SignupSerializer(serializers.Serializer):
    cap_token = CapTokenField(site="login")
    note = serializers.CharField()


class SignupView(APIView):
    authentication_classes = ()
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"ok": True})


urlpatterns = [
    path("drf/cap/", include("capwx.contrib.drf.urls")),
    # The Django urls, next to the DRF ones, for the parity tests.
    path("cap/", include("capwx.contrib.django.urls")),
    path("drf/protected", ProtectedView.as_view(), name="drf-protected"),
    path("drf/header-only", HeaderOnlyView.as_view(), name="drf-header-only"),
    path("drf/basic-protected", BasicProtectedView.as_view(), name="drf-basic-protected"),
    path("drf/signup", SignupView.as_view(), name="drf-signup"),
]
