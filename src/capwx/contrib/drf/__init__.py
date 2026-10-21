"""capwx.contrib.drf: Django REST Framework integration for capwx.

``ChallengeView``, ``RedeemView`` and ``SiteverifyView`` are the widget endpoints as ``APIView``
classes (mount :mod:`capwx.contrib.drf.urls`). ``IsCapVerified`` / ``cap_permission`` protect other
DRF views with a token, and ``CapTokenField`` checks a token inside a serializer. See ``docs/drf.md``.
"""

from capwx.contrib.drf.permissions import CaptchaRequired, IsCapVerified, cap_permission
from capwx.contrib.drf.serializers import CapTokenField
from capwx.contrib.drf.views import ChallengeView, RedeemView, SiteverifyView

__all__ = [
    "CapTokenField",
    "CaptchaRequired",
    "ChallengeView",
    "IsCapVerified",
    "RedeemView",
    "SiteverifyView",
    "cap_permission",
]
