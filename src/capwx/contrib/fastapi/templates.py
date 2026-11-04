"""capwx.contrib.fastapi.templates: the widget's script tags and ``<cap-widget>`` as plain strings.

Same HTML as the Django templates ``capwx/scripts.html`` and ``capwx/widget.html``, without a
template engine. Attribute values are HTML-escaped. JavaScript string literals are JSON-encoded
with ``<``, ``>`` and ``&`` escaped, so a value can never close the script element.
"""

from __future__ import annotations

import html
import json


def _attr(value: str) -> str:
    return html.escape(value, quote=True)


def _js(value: str) -> str:
    text = json.dumps(value)  # ensure_ascii: U+2028/U+2029 are already escaped
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def render_scripts(static_path: str, nonce: str | None) -> str:
    """The inline configuration script and the deferred ``cap.min.js`` tag."""
    base = static_path.rstrip("/")
    nonce_attr = f' nonce="{_attr(nonce)}"' if nonce else ""
    lines = [
        f"<script{nonce_attr}>",
        f"  window.CAP_CUSTOM_HASHWX_URL = {_js(base + '/hashwx.wasm')};",
        f"  window.CAP_CUSTOM_WASM_URL = {_js(base + '/cap_wasm_bg.wasm')};",
        f"  window.CAP_PAKO_URL = {_js(base + '/pako_inflate.min.js')};",
    ]
    if nonce:
        lines.append(f"  window.CAP_SCRIPT_NONCE = {_js(nonce)};")
        lines.append(f"  window.CAP_CSS_NONCE = {_js(nonce)};")
    lines.append("</script>")
    widget_src = _attr(base + "/cap.min.js")
    lines.append(f'<script src="{widget_src}" defer{nonce_attr}></script>')
    return "\n".join(lines)


def render_widget(endpoint: str, field: str) -> str:
    """The ``<cap-widget>`` element, with the hidden input the widget fills."""
    name = _attr(field)
    endpoint_attr = _attr(endpoint)
    return (
        f'<cap-widget data-cap-api-endpoint="{endpoint_attr}" data-cap-hidden-field-name="{name}">'
        f'<input type="hidden" name="{name}" value=""></cap-widget>'
    )
