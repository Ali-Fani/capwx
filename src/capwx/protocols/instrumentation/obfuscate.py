"""capwx.protocols.instrumentation.obfuscate: string-table obfuscation and blob packing.

Port of ``customObfuscateStrings`` plus the level-dependent finishing steps of upstream
``generateInstrumentation`` (core/src/instrumentation.js, Cap commit 29bbe6fb...).

Upstream levels 8-10 use ``javascript-obfuscator`` and levels 4-7 minify with ``esbuild``
when those packages are installed. Neither exists in Python, so:

- levels 1-3: whitespace stripping (same as upstream without esbuild);
- levels 4-7: string table + whitespace stripping (same as upstream without esbuild);
- levels 8-10: clamped to 7 with a one-time warning (deliberate deviation).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import secrets
import zlib

logger = logging.getLogger("capwx")

_rng = secrets.SystemRandom()
_clamp_warned = False

# JS \s character class (ECMAScript WhiteSpace + LineTerminator). Python's \s is broader.
_JS_WS = "\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
_WS_AFTER_NEWLINE_RE = re.compile("\n[" + _JS_WS + "]*")
_WS_LINE_START_RE = re.compile("^[" + _JS_WS + "]+", re.MULTILINE)

# JS: /(['"])((?:\\.|(?!\1)[^\\])*)\1/g   ('.' excludes JS line terminators)
_STRING_LITERAL = re.compile(r"""(['"])((?:\\[^\n\r\u2028\u2029]|(?!\1)[^\\])*)\1""")


def decode_js_string(quote: str, body: str) -> str:
    """Port of upstream ``decodeJsString``: turn a JS string literal body into its value."""
    parts: list[str] = []
    i = 0
    n = len(body)
    while i < n:
        c = body[i]
        if c == "\\":
            i += 1
            # JS: safe += c + body[++i]  (body[i] is undefined past the end; unreachable here)
            parts.append("\\" + (body[i] if i < n else "undefined"))
        elif c == '"':
            parts.append('\\"')
        else:
            parts.append(c)
        i += 1
    safe = "".join(parts)
    if quote == "'":
        safe = safe.replace("\\'", "'")
    return json.loads('"' + safe + '"')


def custom_obfuscate_strings(script: str) -> str:
    """Port of upstream ``customObfuscateStrings``: move string literals into a shuffled table."""
    matches = list(_STRING_LITERAL.finditer(script))
    if not matches:
        return script
    seen: dict[str, int] = {}
    arr: list[str] = []
    for m in matches:
        value = decode_js_string(m.group(1), m.group(2))
        if value not in seen:
            seen[value] = len(arr)
            arr.append(value)
    _rng.shuffle(arr)
    new_index = {s: i for i, s in enumerate(arr)}
    t_name = "_T" + os.urandom(3).hex()
    out = _STRING_LITERAL.sub(
        lambda m: f"{t_name}[{new_index[decode_js_string(m.group(1), m.group(2))]}]",
        script,
    )
    table = json.dumps(arr, separators=(",", ":"), ensure_ascii=False)
    return f"var {t_name}={table};{out}"


def strip_whitespace(script: str) -> str:
    """Upstream: ``script.replace(/\\n\\s*/g, "\\n").replace(/^\\s+/gm, "")``."""
    s = _WS_AFTER_NEWLINE_RE.sub("\n", script)
    return _WS_LINE_START_RE.sub("", s)


def apply_obfuscation(script: str, level: int) -> str:
    """Apply the upstream level-dependent finishing step (levels clamped to 7, see module doc)."""
    global _clamp_warned
    if level > 7:
        if not _clamp_warned:
            _clamp_warned = True
            logger.warning(
                "instrumentation obfuscation_level=%d needs javascript-obfuscator, which is not "
                "available in Python; clamping to 7",
                level,
            )
        level = 7
    if level <= 3:
        return strip_whitespace(script)
    return strip_whitespace(custom_obfuscate_strings(script))


def build_blob(script: str) -> str:
    """Raw deflate (level 1) then STANDARD base64, matching upstream ``deflateRawSync``."""
    c = zlib.compressobj(1, zlib.DEFLATED, -15)
    data = c.compress(script.encode("utf-8")) + c.flush()
    return base64.b64encode(data).decode("ascii")
