"""capwx.contrib.django.templatetags.capwx: ``{% capwx_scripts %}`` and ``{% capwx_widget %}``.

    {% load capwx %}
    {% capwx_scripts %}                        {# once per page, before the form #}
    <form method="post">
      {% capwx_widget site="login" %}          {# renders <cap-widget> with the hidden input #}
    </form>

The scripts load only from ``{% static %}`` (no CDN). The CSP nonce comes from
``request.csp_nonce`` or Django's own ``request._csp_nonce``, when either is present.
"""

from __future__ import annotations

from typing import Any

from django import template
from django.middleware.csrf import get_token  # pyright: ignore[reportUnknownVariableType]
from django.template.loader import render_to_string  # pyright: ignore[reportUnknownVariableType]
from django.utils.safestring import SafeString

from capwx.contrib.django.conf import DEFAULT_SITE, get_conf, require_site
from capwx.contrib.django.forms import CapWidget

register = template.Library()

FETCH_TEMPLATE = "capwx/scripts.html"
WIDGET_TEMPLATE = "capwx/widget.html"


def _nonce(context: Any) -> str | None:
    request = context.get("request")
    value = getattr(request, "csp_nonce", None) or getattr(request, "_csp_nonce", None)
    if value is None:
        value = context.get("csp_nonce")
    return str(value) if value else None


@register.simple_tag(takes_context=True)  # pyright: ignore[reportUnknownMemberType, reportUntypedFunctionDecorator]
def capwx_scripts(context: Any) -> SafeString:
    """Static-file URLs, the nonce (when present), and the CSRF fetch hook (CSRF_EXEMPT False)."""
    request = context.get("request")
    csrf_fetch = (not get_conf().csrf_exempt) and request is not None
    return SafeString(
        render_to_string(  # pyright: ignore[reportUnknownArgumentType]
            FETCH_TEMPLATE,
            {
                "nonce": _nonce(context),
                "csrf_fetch": csrf_fetch,
                "csrf_token": get_token(request) if csrf_fetch else "",
            },
        )
    )


@register.simple_tag  # pyright: ignore[reportUnknownMemberType]
def capwx_widget(site: str = DEFAULT_SITE) -> SafeString:
    """The ``<cap-widget>`` element for ``site``, with its hidden ``cap-token`` input."""
    require_site(site)
    rendered = str(CapWidget(site=site).render("cap-token", None))  # pyright: ignore[reportUnknownMemberType, reportUnknownArgumentType]
    return SafeString(rendered)
