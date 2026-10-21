"""capwx.contrib.drf.serializers: ``CapTokenField``, a serializer field that checks a capwx token.

The widget's hidden input is named ``cap-token``, and Python names cannot contain a dash. So the field
is named after its Python attribute (``cap_token`` below) and reads the widget's key as a fallback::

    from rest_framework import serializers
    from capwx.contrib.drf.serializers import CapTokenField

    class SignupSerializer(serializers.Serializer):
        cap_token = CapTokenField(site="signup")      # reads "cap_token", else "cap-token"
        email = serializers.EmailField()

    s = SignupSerializer(data=request.data)           # the widget posts cap-token
    s.is_valid(raise_exception=True)

To read the token from the ``X-Cap-Token`` header instead, put it in the data yourself::

    SignupSerializer(data={**request.data, "cap_token": request.headers.get("X-Cap-Token")})

The token is validated and consumed once, when the serializer validates it. A blank or missing value
is an ordinary "required" or "blank" error and does not consume anything. A wrong, used or expired
token fails with "Please complete the verification.". The field is write-only by default, so the
token is never echoed back in ``serializer.data``.
"""

from __future__ import annotations

from typing import Any, ClassVar, cast

from rest_framework import serializers  # pyright: ignore[reportUnknownVariableType]
from rest_framework.fields import empty  # pyright: ignore[reportUnknownVariableType]

from capwx.contrib.django.conf import DEFAULT_SITE, TOKEN_FIELD
from capwx.contrib.drf.permissions import verify_cap_token


class CapTokenField(serializers.CharField):  # pyright: ignore[reportUntypedBaseClass]
    """A required string that must be a valid, unused capwx token for ``site``."""

    # DRF merges default_error_messages across the MRO, so the CharField messages are kept.
    default_error_messages: ClassVar[dict[str, str]] = {  # pyright: ignore[reportIncompatibleVariableOverride]
        "captcha_required": "Please complete the verification.",
    }

    def __init__(
        self,
        *,
        site: str = DEFAULT_SITE,
        body_key: str = TOKEN_FIELD,
        **kwargs: Any,
    ) -> None:
        """``site`` is the capwx site scope. ``body_key`` is the data key used as a fallback when the
        field's own name is missing (the widget posts ``cap-token``)."""
        kwargs.setdefault("write_only", True)
        self.site = site
        self.body_key = body_key
        super().__init__(**kwargs)  # pyright: ignore[reportUnknownMemberType]

    def get_value(self, dictionary: Any) -> object:
        value = cast("object", super().get_value(dictionary))  # pyright: ignore[reportUnknownMemberType]
        own_name = cast("str", self.field_name)  # pyright: ignore[reportUnknownMemberType]
        if value is empty and self.body_key != own_name:
            value = cast("object", dictionary.get(self.body_key, empty))
        return value

    def to_internal_value(self, data: Any) -> str:
        token: str = super().to_internal_value(data)  # pyright: ignore[reportUnknownMemberType]
        if not verify_cap_token(self.site, token):
            self.fail("captcha_required")  # pyright: ignore[reportUnknownMemberType]
        return token


__all__ = ["CapTokenField"]
