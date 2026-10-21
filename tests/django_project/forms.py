"""Test form using CapField for the login site."""

from django import forms

from capwx.contrib.django.forms import CapField


class LoginForm(forms.Form):
    username = forms.CharField()
    captcha = CapField(site="login")


def e2e_form_class(site: str) -> type[forms.Form]:
    """A username form whose captcha field validates against ``site`` (browser e2e pages)."""
    return type(
        "E2EForm",
        (forms.Form,),
        {"username": forms.CharField(), "captcha": CapField(site=site)},
    )
