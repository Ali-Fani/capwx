"""capwx.contrib.django.forms: CapField (form field) and CapWidget (renders the Cap widget).

The widget fills a hidden input named ``cap-token``, so the widget always submits under that
name, whatever the form field is called. ``CapField.clean`` consumes the token (single use).
If the rest of the form then fails validation, the user must solve the widget again.
"""

from __future__ import annotations

from typing import Any, ClassVar

from django import forms
from django.core.exceptions import ValidationError

from capwx.contrib.django.conf import (
    DEFAULT_SITE,
    TOKEN_FIELD,
    endpoint_base,
    get_conf,
    require_site,
)
from capwx.tokens import validate_token

VERIFICATION_MESSAGE = "Please complete the verification."


class CapWidget(forms.Widget):
    template_name = "capwx/widget.html"

    def __init__(self, site: str = DEFAULT_SITE, attrs: dict[str, Any] | None = None) -> None:
        super().__init__(attrs)  # pyright: ignore[reportUnknownMemberType]
        self.site = site

    def value_from_datadict(self, data: Any, files: Any, name: str) -> str | None:
        # The widget's hidden input is always "cap-token", whatever the form field is called.
        return data.get(TOKEN_FIELD)

    def value_omitted_from_data(self, data: Any, files: Any, name: str) -> bool:
        return TOKEN_FIELD not in data

    def get_context(self, name: str, value: Any, attrs: dict[str, Any] | None) -> dict[str, Any]:
        context: dict[str, Any] = super().get_context(TOKEN_FIELD, None, attrs)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        require_site(self.site)  # unknown sites are a template error, reported at render time
        context["widget"]["endpoint"] = endpoint_base(self.site)
        context["widget"]["site"] = self.site
        return context


class CapField(forms.CharField):
    default_error_messages: ClassVar[dict[str, str]] = {
        "required": VERIFICATION_MESSAGE,
        "invalid": VERIFICATION_MESSAGE,
    }

    def __init__(self, *, site: str = DEFAULT_SITE, **kwargs: Any) -> None:
        self.site = site
        kwargs.setdefault("widget", CapWidget(site=site))
        kwargs.setdefault("required", True)
        super().__init__(**kwargs)  # pyright: ignore[reportUnknownMemberType]

    def clean(self, value: Any) -> Any:
        # Django's clean() and error_messages are untyped; the declared types below are the contract.
        cleaned = super().clean(value)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        site = require_site(self.site)
        if not validate_token(site.config, cleaned, scope=self.site, token_store=get_conf().store):  # pyright: ignore[reportUnknownArgumentType]
            message = self.error_messages["invalid"]  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
            raise ValidationError(message, code="invalid")  # pyright: ignore[reportUnknownArgumentType]
        return cleaned  # pyright: ignore[reportUnknownVariableType]
