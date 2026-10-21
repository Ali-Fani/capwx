"""capwx.protocols.instrumentation.generator: port of upstream ``core/src/instrumentation.js``.

Covers ``generateInstrumentation`` (value pipeline), ``buildClientScript``, ``buildProbe``,
``buildBlockChecks``, ``hashWith`` and ``domSumMock``. Upstream commit:
29bbe6fbe284786cdb0d4489e5040aee6042b2a4.

Conventions:
- JS snippets are raw strings copied from upstream template literals. Dynamic parts are
  ``%%NAME%%`` tokens filled with ``str.replace`` (never f-strings, so JS braces stay literal).
- Random draws happen in the same order as upstream, so a deterministic RNG reproduces
  upstream output (the differential check in the test suite relies on this).
- Upstream ``JSON.stringify`` output is compact, so ``json_compact`` uses ``separators=(",", ":")``.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, TypeVar, cast

from capwx._jsint import (
    js_and,
    js_not,
    js_or,
    js_rem,
    js_sar,
    js_shl,
    js_xor,
    to_int32,
    to_uint32,
    utf16_units,
)
from capwx.protocols.instrumentation.obfuscate import apply_obfuscation, build_blob

_rng = secrets.SystemRandom()
_T = TypeVar("_T")


@dataclass(frozen=True)
class _DomNode:
    """A fake DOM node for ``dom_sum_mock``: its parent and its ``innerText``."""

    parent: _DomNode | None
    text: str


DEFAULT_TTL_MS = 5 * 60 * 1000

# ---------------------------------------------------------------------------
# Constants: copied verbatim from upstream, in the same order.
# ---------------------------------------------------------------------------

WINDOW_PROP_MARKERS = [
    "_Selenium_IDE_Recorder",
    "_selenium",
    "calledSelenium",
    "__webdriverFunc",
    "__lastWatirAlert",
    "__lastWatirConfirm",
    "__lastWatirPrompt",
    "_WEBDRIVER_ELEM_CACHE",
    "ChromeDriverw",
    "awesomium",
    "CefSharp",
    "RunPerfTest",
    "fmget_targets",
    "geb",
    "spawn",
    "domAutomation",
    "domAutomationController",
    "wdioElectron",
    "callPhantom",
    "_phantom",
    "__nightmare",
    "nightmare",
    "__playwright__binding__",
    "__pwInitScripts",
]
DOC_PROP_MARKERS = [
    "__selenium_evaluate",
    "selenium-evaluate",
    "__selenium_unwrapped",
    "__webdriver_script_fn",
    "__driver_evaluate",
    "__webdriver_evaluate",
    "__fxdriver_evaluate",
    "__driver_unwrapped",
    "__webdriver_unwrapped",
    "__fxdriver_unwrapped",
    "__webdriver_script_func",
    "__webdriver_script_function",
]
NAV_OWN_PROP_MARKERS = [
    "webdriver",
    "userAgent",
    "appVersion",
    "userAgentData",
    "platform",
    "vendor",
    "product",
    "productSub",
    "languages",
    "language",
    "plugins",
    "mimeTypes",
    "hardwareConcurrency",
    "deviceMemory",
    "maxTouchPoints",
    "permissions",
    "connection",
]
ATTR_SUBSTRING_MARKERS = ["selenium", "webdriver", "driver"]
STACK_SUBSTRING_MARKERS = ["pptr:", "UtilityScript.", "PhantomJS"]
WINDOW_PREFIX_MARKERS = ["puppeteer_", "cdc_", "$cdc_"]
UA_TOKEN_MARKERS = [
    "HeadlessChrome",
    "PhantomJS",
    "SlimerJS",
    "headless",
]
WEBGL_VENDOR_MARKER = "Brian Paul"
WEBGL_RENDERER_MARKER = "Mesa OffScreen"
PRODUCTSUB_GECKO = "20030107"
SEQUENTUM_MARKER = "Sequentum"

PROBE_FONT_STACKS = [
    "sans-serif",
    "serif",
    "monospace",
    "Arial",
    "'Times New Roman'",
    "'Courier New'",
    "'Segoe UI'",
    "'SF Pro Text'",
    "'Helvetica Neue'",
    "'Ubuntu'",
    "'DejaVu Sans'",
    "'Roboto'",
    "Tahoma",
    "Calibri",
    "'Cantarell'",
    "'Liberation Sans'",
    "'Noto Sans'",
]

VAR_LETTERS = "abcdefghijklmnopqrstuvwxyz"
VAR_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"

# ---------------------------------------------------------------------------
# JS templates (verbatim from upstream; ``%%NAME%%`` tokens are filled by _fill).
# A ``\{`` in these raw strings is the JS text ``\{`` (upstream writes ``\\{`` in a template).
# ---------------------------------------------------------------------------

_PROBE_HEAD = (
    r"var %%P%%={};function %%SF%%(k,f){try{%%P%%[k]=f()}catch(e){%%P%%[k]=null}}"
    r"function %%NAT%%(fn){try{return /\{\s*\[native code\]\s*\}/.test(Function.prototype.toString.call(fn))}catch(e){return true}}"
)

_PROBE_FIELDS = [
    r'%%SF%%("ua",function(){return navigator.userAgent});',
    r'%%SF%%("productSub",function(){return navigator.productSub});',
    r'%%SF%%("webdriver",function(){return navigator.webdriver});',
    r'%%SF%%("oscpu",function(){return navigator.oscpu===undefined?"__undefined":navigator.oscpu});',
    r'%%SF%%("deviceMemory",function(){return navigator.deviceMemory});',
    r'%%SF%%("uaDataPresent",function(){return !!navigator.userAgentData});',
    r'%%SF%%("uaData",function(){var u=navigator.userAgentData;return u?{mobile:u.mobile,brands:(u.brands||[]).map(function(b){return b.brand+"/"+b.version})}:null});',
    r'%%SF%%("plugins",function(){return {length:navigator.plugins.length}});',
    r'%%SF%%("pdfViewerEnabled",function(){return navigator.pdfViewerEnabled});',
    r'%%SF%%("engine",function(){return {hasMozInnerScreenX:typeof window.mozInnerScreenX!=="undefined",hasChrome:typeof window.chrome!=="undefined"}});',
    r'%%SF%%("screen",function(){return {width:screen.width,height:screen.height}});',
    r'%%SF%%("outerWH",function(){return [outerWidth,outerHeight]});',
    r'%%SF%%("isExtended",function(){return screen.isExtended===undefined?null:screen.isExtended});',
    r'%%SF%%("fontWidths",function(){var sp=document.createElement("span");sp.style.cssText="position:absolute;left:-9999px;top:-9999px;font-size:72px;white-space:nowrap";sp.textContent="mmmmmmmmmmlli WwWwGg @#Xj";document.body.appendChild(sp);var st=%%FONTS%%;var out=[];for(var i=0;i<st.length;i++){sp.style.fontFamily=st[i];out.push(Math.round(sp.getBoundingClientRect().width*100)/100)}document.body.removeChild(sp);return out});',
    r'%%SF%%("tamper",function(){return {getParameterWebGL:%%NAT%%(WebGLRenderingContext.prototype.getParameter),toDataURL:%%NAT%%(HTMLCanvasElement.prototype.toDataURL),getImageData:%%NAT%%(CanvasRenderingContext2D.prototype.getImageData),permissionsQuery:navigator.permissions?%%NAT%%(navigator.permissions.query):true,fnToString:%%NAT%%(Function.prototype.toString)}});',
]

_HELPERS = (
    r"function %%HF%%(s){let h=%%SEED%%>>>0;for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=(h+(h<<1)+(h<<4)+(h<<7)+(h<<8)+(h<<24))>>>0;}return h>>>0;}"
    r"function %%HSET%%(a,v){for(var i=0;i<a.length;i++)if(a[i]===v)return true;return false;}"
)

_HELPER_DECLS = (
    r"function %%FN%%(a,b,c){function F(d){this.v=function(){return this.k^d;}};var p={k:c};var i=new F(a);i.k=b;F.prototype=p;return i.v()|(new F(b)).v();}"
    r"function %%DOM%%(x,y,z){var d=document.createElement('div');d.style.display='none';document.body.appendChild(d);function A(p,v){for(var i=0;i<8;i++){var c=document.createElement('div');p.appendChild(c);c.innerText=v;if((v&1)==0)p=c;v=v>>1;}return p;}function B(n,r,s){if(!n||n==r)return s%256;while(n.children.length>0)n.removeChild(n.lastElementChild);return B(n.parentNode,r,s+parseInt(n.innerText));}var s=B(A(A(A(d,x),y),z),d,0);d.parentNode.removeChild(d);return s;}"
)

# buildBlockChecks pieces. Each is one template_literal pushed to `checks`, in upstream order.
_BC_NAV_DESCRIPTORS = r"if (!%%B%%) { try { var d = Object.getOwnPropertyDescriptors(navigator); var __wh = %%H_WEBDRIVER%%; for (const k in d) { if (%%HF%%(k) === __wh) { %%B%% = true; break; } } if (!%%B%%) { var p = Object.getPrototypeOf(navigator); while (p && !%%B%%) { for (const k of Object.getOwnPropertyNames(p)) { if (%%HF%%(k) === __wh) { try { if (navigator[k]) %%B%% = true; } catch {} break; } } p = Object.getPrototypeOf(p); } } } catch { %%B%% = true; } }"
_BC_NAV_OWN = r"if (!%%B%%) { try { var %%A%% = %%LIST%%; for (const k of Object.getOwnPropertyNames(navigator)) { if (%%HSET%%(%%A%%, %%HF%%(k))) { %%B%% = true; break; } } } catch { %%B%% = true; } }"
_BC_WIN_PREFIX = r"if (!%%B%%) { var %%A%% = %%LIST%%; for (const k of Object.getOwnPropertyNames(window)) { for (var pl = 4; pl <= 5; pl++) { if (%%HSET%%(%%A%%, %%HF%%(k.slice(0, pl)))) { %%B%% = true; break; } } if (%%B%%) break; } }"
_BC_WIN_PROPS = r"if (!%%B%%) { var %%A%% = %%LIST%%; for (const k of Object.getOwnPropertyNames(window)) { if (%%HSET%%(%%A%%, %%HF%%(k))) { %%B%% = true; break; } } }"
_BC_DOC_PROPS = r"if (!%%B%%) { var %%A%% = %%LIST%%; for (const k of Object.getOwnPropertyNames(document)) { if (%%HSET%%(%%A%%, %%HF%%(k))) { %%B%% = true; break; } } }"
_BC_ATTR = r"if (!%%B%%) { try { var %%A%% = %%LIST%%; var an = document.documentElement.getAttributeNames(); for (const n of an) { for (const t of n.split(/[^a-z]+/i)) { if (t && %%HSET%%(%%A%%, %%HF%%(t.toLowerCase()))) { %%B%% = true; break; } } if (%%B%%) break; } } catch { %%B%% = true; } }"
_BC_STACK = r"if (!%%B%%) { try { var %%A%% = %%LIST%%; var %%ST%% = (new Error()).stack || ''; for (var i = 0; i + 5 <= %%ST%%.length; i++) { for (var sl = 5; sl <= 14; sl++) { if (i + sl > %%ST%%.length) break; if (%%HSET%%(%%A%%, %%HF%%(%%ST%%.substr(i, sl)))) { %%B%% = true; break; } } if (%%B%%) break; } } catch {} }"
_BC_EXPOSED_FN = r"if (!%%B%%) { try { if (typeof window.exposedFn !== 'undefined') { var s = window.exposedFn.toString(); for (var i = 0; i + 19 <= s.length; i++) { if (%%HF%%(s.substr(i, 19)) === %%H_EXPOSE%%) { %%B%% = true; break; } } } } catch {} }"
_BC_PROCESS = r"if (!%%B%% && typeof window.process !== 'undefined') { try { if (%%HF%%(window.process.type || '') === %%H_RENDERER%% || (window.process.versions && window.process.versions.electron)) %%B%% = true; } catch { %%B%% = true; } }"
_BC_UA_TOKENS = r"if (!%%B%%) { try { var %%A%% = %%LIST%%; var ua = navigator.userAgent || ''; for (const t of ua.split(/[\s/(),;]/)) { if (t && %%HSET%%(%%A%%, %%HF%%(t))) { %%B%% = true; break; } } if (!%%B%%) { var av = navigator.appVersion || ''; for (const t of av.split(/[\s/(),;]/)) { if (t && %%HSET%%(%%A%%, %%HF%%(t))) { %%B%% = true; break; } } } } catch {} }"
_BC_WEBGL = r"if (!%%B%%) { try { var c = document.createElement('canvas').getContext('webgl'); if (c) { var v = c.getParameter(c.VENDOR); var r = c.getParameter(c.RENDERER); if (%%HF%%(v || '') === %%H_VENDOR%% && %%HF%%(r || '') === %%H_RENDERER_GL%%) %%B%% = true; } } catch {} }"
_BC_FOCUS = r"if (!%%B%%) { try { if (document.hasFocus && document.hasFocus() && window.outerWidth === 0 && window.outerHeight === 0) %%B%% = true; } catch { %%B%% = true; } }"
_BC_EVAL_NATIVE = r"if (!%%B%%) { try { var es = Function.prototype.toString.call(eval); var found = false; for (var i = 0; i + 13 <= es.length; i++) { if (%%HF%%(es.substr(i, 13)) === %%H_NATIVE%%) { found = true; break; } } if (!found) %%B%% = true; } catch {} }"
_BC_BIND = r"if (!%%B%%) { try { if (typeof Function.prototype.bind === 'undefined') %%B%% = true; } catch {} }"
_BC_EXTERNAL = r"if (!%%B%%) { try { if (window.external && typeof window.external.toString === 'function') { var s = window.external.toString(); for (var i = 0; i + 9 <= s.length; i++) { if (%%HF%%(s.substr(i, 9)) === %%H_SEQUENTUM%%) { %%B%% = true; break; } } } } catch { %%B%% = true; } }"
_BC_MIME = r"if (!%%B%%) { try { if (navigator.mimeTypes) { var %%OK%% = Object.getPrototypeOf(navigator.mimeTypes) === MimeTypeArray.prototype; for (var %%I%% = 0; %%I%% < navigator.mimeTypes.length && %%OK%%; %%I%%++) { %%OK%% = Object.getPrototypeOf(navigator.mimeTypes[%%I%%]) === MimeType.prototype; } if (!%%OK%%) %%B%% = true; } } catch {} }"
_BC_PRODUCTSUB = r"if (!%%B%%) { try { var %%PS%% = navigator.productSub; var %%UA%% = navigator.userAgent || ''; if (%%PS%% && %%HF%%(%%PS%%) !== %%H_GECKO%%) { var likeBlink = false; for (const t of %%UA%%.toLowerCase().split(/[\s/(),;]/)) { var hh = %%HF%%(t); if (hh === %%H_CHROME%% || hh === %%H_SAFARI%% || hh === %%H_OPERA%%) { likeBlink = true; break; } } if (likeBlink) %%B%% = true; } } catch {} }"
_BC_WIN_SUFFIX = r"if (!%%B%%) { try { var %%K%% = Object.getOwnPropertyNames(window); for (const n of %%K%%) { var u = n.lastIndexOf('_'); if (u > 3 && u < n.length - 1) { var suf = n.slice(u + 1); var hh = %%HF%%(suf); if (hh === %%H_ARRAY%% || hh === %%H_PROMISE%% || hh === %%H_SYMBOL%%) { %%B%% = true; break; } } } } catch {} }"
_BC_WRAP = r"let %%B%% = false;try {%%CHECKS%%} catch {%%B%% = true} if (%%B%%) {parent.postMessage({ type: 'cap:instr', nonce: %%ID%%, result: '', blocked: true }, '*');return;}"

# Environment checks (upstream `envChecks`, in source order; shuffled at build time).
_ENV_CHECKS = [
    r"try { const %%NK%%st = (new Error()).stack || ''; if (%%NK%%st.indexOf('node:internal') !== -1 || %%NK%%st.indexOf('moduleEvaluation') !== -1 || %%NK%%st.indexOf('loadAndEvaluateModule') !== -1 || %%NK%%st.indexOf('file:///') !== -1 || %%NK%%st.indexOf('[eval]') !== -1 || /\(native:/.test(%%NK%%st)) return null; } catch { return null }",
    r"if (typeof HTMLElement !== 'function' || typeof Window !== 'function' || typeof Document !== 'function' || typeof Navigator !== 'function' || typeof Node !== 'function') return null; if (!(navigator instanceof Navigator) || !(document instanceof Document) || !(window instanceof Window) || !(document.body instanceof HTMLElement)) return null; if (globalThis !== window || window.self !== window || document.defaultView !== window) return null;",
    r"try { const %%NK%%ots = Object.prototype.toString; if (%%HF%%(%%NK%%ots.call(navigator)) !== %%H_OBJ_NAV%% || %%HF%%(%%NK%%ots.call(window)) !== %%H_OBJ_WIN%% || %%HF%%(%%NK%%ots.call(document)) !== %%H_OBJ_DOC%%) return null; } catch { return null }",
    r"try { if (typeof EventTarget !== 'function' || !(document.body instanceof EventTarget) || !(window instanceof EventTarget)) return null; const %%NK%%probe = document.createElement('div'); let %%NK%%fired = 0; const %%NK%%ev = '_c' + (Date.now() & 0xffff).toString(36); const %%NK%%h = (e) => { if (e && e.detail === 0xc0de) %%NK%%fired++; }; %%NK%%probe.addEventListener(%%NK%%ev, %%NK%%h); %%NK%%probe.dispatchEvent(new CustomEvent(%%NK%%ev, { detail: 0xc0de })); %%NK%%probe.dispatchEvent(new CustomEvent(%%NK%%ev, { detail: 0xc0de })); %%NK%%probe.removeEventListener(%%NK%%ev, %%NK%%h); %%NK%%probe.dispatchEvent(new CustomEvent(%%NK%%ev, { detail: 0xc0de })); if (%%NK%%fired !== 2) return null; } catch { return null }",
    r"""try { const %%NK%%gf = new Function('return this'); const %%NK%%tg = %%NK%%gf(); if (%%NK%%tg !== globalThis) return null; const %%NK%%leakHashes = %%LEAK1%%; for (const %%NK%%k of Object.getOwnPropertyNames(%%NK%%tg)) { if (%%HSET%%(%%NK%%leakHashes, %%HF%%(%%NK%%k))) return null; } const %%NK%%fnArgs = new Function('a','b','c','return a+b+c'); if (%%NK%%fnArgs.length !== 3) return null; if (%%NK%%fnArgs(10,20,30) !== 60) return null; const %%NK%%src = Function.prototype.toString.call(%%NK%%fnArgs); if (%%NK%%src.indexOf('return a+b+c') === -1) return null; if (%%NK%%src.indexOf('apply') !== -1 || %%NK%%src.indexOf('callArgs') !== -1 || %%NK%%src.indexOf('Reflect.') !== -1) return null; let %%NK%%thrown = null; try { new Function('throw new Error("x")')(); } catch (%%NK%%e) { %%NK%%thrown = %%NK%%e; } if (!%%NK%%thrown || !%%NK%%thrown.stack) return null; const %%NK%%st2 = %%NK%%thrown.stack; if (%%NK%%st2.indexOf('node:internal') !== -1 || %%NK%%st2.indexOf('moduleEvaluation') !== -1 || %%NK%%st2.indexOf('file:///') !== -1 || %%NK%%st2.indexOf('[eval]') !== -1 || /\(native:/.test(%%NK%%st2)) return null; } catch { return null }""",
    r"try { const %%NK%%ie = (0, eval); const %%NK%%eg = %%NK%%ie('this'); if (%%NK%%eg !== globalThis) return null; const %%NK%%leak2 = %%LEAK2%%; for (const %%NK%%k of Object.getOwnPropertyNames(%%NK%%eg)) { if (%%HSET%%(%%NK%%leak2, %%HF%%(%%NK%%k))) return null; } } catch { return null }",
    r"try { var %%EL%% = %%ES%%; var %%EA%% = '%%EL2%%'; var %%EB%% = '%%ELREST%%'; var %%EC%% = %%EA%% + %%EB%%; var %%EL%%r1 = (0, eval)('typeof ' + %%EC%%); if (%%EL%%r1 !== 'undefined') return null; var %%EL%%r2 = eval(%%EC%%); if (%%EL%%r2 !== %%ES%%) return null; var %%EL%%r3 = eval(%%EA%% + %%EB%% + '+1'); if (%%EL%%r3 !== %%ES1%%) return null; var %%EL%%arr = ['(', '(', ')', '=', '>', 't', 'h', 'i', 's', ')', '(', ')']; var %%EL%%arrow = (0, eval)(%%EL%%arr.join('')); if (%%EL%%arrow !== globalThis) return null; var %%EL%%r4 = eval('(function(){return ' + %%EC%% + '*2;})()'); if (%%EL%%r4 !== %%ES2%%) return null; } catch { return null }",
]

_CLIENT_TEMPLATE = (
    r"(function(){window.onload=async function(){try {%%HELPERS%%const %%DV%%=await (async function(){%%ENVS%%%%BLOCK%%"
    "\n      var %%V0%%=%%I0%%;var %%V1%%=%%I1%%;var %%V2%%=%%I2%%;var %%V3%%=%%I3%%;%%EQS%%"
    '\n      var %%OUT%%={};%%OUT%%["%%V0%%"]=%%V0%%;%%OUT%%["%%V1%%"]=%%V1%%;%%OUT%%["%%V2%%"]=%%V2%%;%%OUT%%["%%V3%%"]=%%V3%%;return %%OUT%%;})();'
    r"if (!%%DV%% || typeof %%DV%% !== 'object') return;%%PROBE%%parent.postMessage({type: 'cap:instr',nonce:%%ID%%,result:{i:%%ID%%,state:%%DV%%,p:%%P%%,ts:Date.now()}},'*');} catch {}};})();"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fill(template: str, **values: str) -> str:
    """Replace each ``%%KEY%%`` token with its value (str.replace, no f-strings)."""
    for key, value in values.items():
        template = template.replace(f"%%{key}%%", value)
    return template


def json_compact(value: Any) -> str:
    """JS ``JSON.stringify`` equivalent for the values used here (ints, strings, lists)."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _random_bytes(n: int) -> bytes:
    return os.urandom(n)


def _r_hex(length: int) -> str:
    """Upstream ``rHex(len)``: ``randomBytes(len).hex().slice(0, len)``."""
    return _random_bytes(length).hex()[:length]


def _r_var(length: int | None = None) -> str:
    """Upstream ``rVar(len?)``: a JS identifier, first char a-z, rest a-z0-9."""
    if not length:
        length = _rng.randint(4, 10)  # upstream: int(Math.random()*7)+4
    s = VAR_LETTERS[_rng.randrange(0, 26)]
    for _ in range(1, length):
        s += VAR_CHARS[_rng.randrange(0, 36)]
    return s


def _fast_rnd(a: int, b: int) -> int:
    """Upstream ``fastRnd(a, b)``: inclusive on both ends."""
    return _rng.randint(a, b)


def shuffle(arr: list[_T]) -> list[_T]:
    """Upstream ``shuffle(arr)``: in-place Fisher-Yates."""
    _rng.shuffle(arr)
    return arr


def hash_with(seed: int) -> Callable[[str], int]:
    """Port of upstream ``hashWith(seed)``: a 32-bit string hash matching the browser code."""
    base = to_uint32(seed)

    def h(s: str) -> int:
        x = base
        for c in utf16_units(s):
            x = js_xor(x, c)
            x = to_uint32(
                x + js_shl(x, 1) + js_shl(x, 4) + js_shl(x, 7) + js_shl(x, 8) + js_shl(x, 24)
            )
        return x

    return h


def dom_sum_mock(x: int, y: int, z: int) -> int:
    """Port of upstream ``domSumMock(x, y, z)``: the DOM-walk arithmetic, without a DOM."""

    def build_chain(parent: _DomNode | None, val: int) -> _DomNode | None:
        cur, v = parent, val
        for _ in range(8):
            child = _DomNode(cur, str(v))  # (parentNode, innerText)
            if (v & 1) == 0:
                cur = child
            v = js_sar(v, 1)
        return cur

    node = build_chain(build_chain(build_chain(None, x), y), z)
    s = 0
    while node is not None:  # None is the document root
        s += int(node.text)  # parseInt(innerText, 10)
        node = node.parent
    return to_int32(js_rem(s, 256))


# ---------------------------------------------------------------------------
# Client script builders
# ---------------------------------------------------------------------------


def build_probe(p: str) -> str:
    """Port of upstream ``buildProbe(P)``: the fingerprint probe that posts ``p``."""
    sf = _r_var()
    nat = _r_var()
    fields = [
        _fill(
            f,
            SF=sf,
            NAT=nat,
            FONTS=json_compact(PROBE_FONT_STACKS),
        )
        for f in _PROBE_FIELDS
    ]
    shuffle(fields)
    head = _fill(_PROBE_HEAD, P=p, SF=sf, NAT=nat)
    return head + "".join(fields)


def build_block_checks(b: str, id_: str, hf: str, hset: str, h: Callable[[str], int]) -> str:
    """Port of upstream ``buildBlockChecks(b, id, hF, hSet, h)``."""
    win_hashes = [h(x) for x in WINDOW_PROP_MARKERS]
    doc_hashes = [h(x) for x in DOC_PROP_MARKERS]
    nav_own_hashes = [h(x) for x in NAV_OWN_PROP_MARKERS]
    attr_sub_hashes = [h(x) for x in ATTR_SUBSTRING_MARKERS]
    stack_sub_hashes = [h(x) for x in STACK_SUBSTRING_MARKERS]
    win_prefix_hashes = [h(x) for x in WINDOW_PREFIX_MARKERS]
    ua_tok_hashes = [h(x) for x in UA_TOKEN_MARKERS]
    webgl_vendor_hash = h(WEBGL_VENDOR_MARKER)
    webgl_renderer_hash = h(WEBGL_RENDERER_MARKER)
    productsub_gecko_hash = h(PRODUCTSUB_GECKO)
    sequentum_hash = h(SEQUENTUM_MARKER)

    common = {"B": b, "HF": hf, "HSET": hset}
    checks: list[str] = []

    checks.append(_fill(_BC_NAV_DESCRIPTORS, H_WEBDRIVER=str(h("webdriver")), **common))

    a = _r_var()
    checks.append(_fill(_BC_NAV_OWN, A=a, LIST=json_compact(nav_own_hashes), **common))

    a = _r_var()
    checks.append(_fill(_BC_WIN_PREFIX, A=a, LIST=json_compact(win_prefix_hashes), **common))

    a = _r_var()
    checks.append(_fill(_BC_WIN_PROPS, A=a, LIST=json_compact(win_hashes), **common))

    a = _r_var()
    checks.append(_fill(_BC_DOC_PROPS, A=a, LIST=json_compact(doc_hashes), **common))

    a = _r_var()
    checks.append(_fill(_BC_ATTR, A=a, LIST=json_compact(attr_sub_hashes), **common))

    a = _r_var()
    st = _r_var()
    checks.append(_fill(_BC_STACK, A=a, ST=st, LIST=json_compact(stack_sub_hashes), **common))

    checks.append(_fill(_BC_EXPOSED_FN, H_EXPOSE=str(h("exposeBindingHandle")), **common))

    checks.append(_fill(_BC_PROCESS, H_RENDERER=str(h("renderer")), **common))

    a = _r_var()
    checks.append(_fill(_BC_UA_TOKENS, A=a, LIST=json_compact(ua_tok_hashes), **common))

    checks.append(
        _fill(
            _BC_WEBGL,
            H_VENDOR=str(webgl_vendor_hash),
            H_RENDERER_GL=str(webgl_renderer_hash),
            **common,
        )
    )

    checks.append(_fill(_BC_FOCUS, **common))

    checks.append(_fill(_BC_EVAL_NATIVE, H_NATIVE=str(h("[native code]")), **common))

    checks.append(_fill(_BC_BIND, **common))

    checks.append(_fill(_BC_EXTERNAL, H_SEQUENTUM=str(sequentum_hash), **common))

    ok = _r_var()
    i = _r_var()
    checks.append(_fill(_BC_MIME, OK=ok, I=i, **common))

    ua = _r_var()
    ps = _r_var()
    checks.append(
        _fill(
            _BC_PRODUCTSUB,
            PS=ps,
            UA=ua,
            H_GECKO=str(productsub_gecko_hash),
            H_CHROME=str(h("chrome")),
            H_SAFARI=str(h("safari")),
            H_OPERA=str(h("opera")),
            **common,
        )
    )

    k = _r_var()
    checks.append(
        _fill(
            _BC_WIN_SUFFIX,
            K=k,
            H_ARRAY=str(h("Array")),
            H_PROMISE=str(h("Promise")),
            H_SYMBOL=str(h("Symbol")),
            **common,
        )
    )

    shuffle(checks)
    sampled = checks[: min(len(checks), 8)]
    return _fill(_BC_WRAP, B=b, CHECKS="".join(sampled), ID=json_compact(id_))


def build_client_script(
    *,
    id_: str,
    vars_: list[str],
    init_vals: list[int],
    client_eqs: str,
    block_automated_browsers: bool,
) -> str:
    """Port of upstream ``buildClientScript``: the JS the browser runs (before obfuscation)."""
    seed = _rng.randrange(1, 0x7FFFFFFF)  # upstream randomInt(1, 0x7fffffff)
    h = hash_with(seed)
    hf = _r_var()
    hset = _r_var()
    eval_local = _r_var()
    eval_secret = _rng.randrange(1_000_000, 0x7FFFFFFF)
    eval_a = _r_var()
    eval_b = _r_var()
    eval_c = _r_var()
    helpers = _fill(_HELPERS, HF=hf, HSET=hset, SEED=str(seed))

    block_checks = (
        build_block_checks(_r_var(), id_, hf, hset, h) if block_automated_browsers else ""
    )

    dv_key = _r_var()
    n_key = _r_var()
    out_key = _r_var()
    p_key = _r_var()

    leak1 = json_compact(
        [h(x) for x in ["Bun", "process", "module", "require", "global", "__dirname", "Deno"]]
    )
    leak2 = json_compact(
        [h(x) for x in ["Bun", "process", "require", "global", "__dirname", "Deno"]]
    )
    env = [
        _fill(
            tpl,
            NK=n_key,
            HF=hf,
            HSET=hset,
            LEAK1=leak1,
            LEAK2=leak2,
            H_OBJ_NAV=str(h("[object Navigator]")),
            H_OBJ_WIN=str(h("[object Window]")),
            H_OBJ_DOC=str(h("[object HTMLDocument]")),
            EL=eval_local,
            EA=eval_a,
            EB=eval_b,
            EC=eval_c,
            EL2=eval_local[:2],
            ELREST=eval_local[2:],
            ES=str(eval_secret),
            ES1=str(eval_secret + 1),
            ES2=str(eval_secret * 2),
        )
        for tpl in _ENV_CHECKS
    ]
    shuffle(env)

    probe = build_probe(p_key)

    return _fill(
        _CLIENT_TEMPLATE,
        HELPERS=helpers,
        DV=dv_key,
        ENVS="".join(env),
        BLOCK=block_checks,
        V0=vars_[0],
        V1=vars_[1],
        V2=vars_[2],
        V3=vars_[3],
        I0=str(init_vals[0]),
        I1=str(init_vals[1]),
        I2=str(init_vals[2]),
        I3=str(init_vals[3]),
        EQS=client_eqs,
        OUT=out_key,
        PROBE=probe,
        ID=json_compact(id_),
        P=p_key,
    )


# ---------------------------------------------------------------------------
# Public generator
# ---------------------------------------------------------------------------

_OPT_DEFAULT_LEVEL = 3


def _opt(opts: Any, name: str, default: Any) -> Any:
    if opts is None:
        return default
    if isinstance(opts, Mapping):
        mapping = cast("Mapping[str, Any]", opts)
        return mapping.get(name, default)
    return getattr(opts, name, default)


def generate_instrumentation(
    opts: Any = None, *, _return_client_eqs: bool = False
) -> dict[str, Any]:
    """Port of upstream ``generateInstrumentation(opts)``.

    ``opts`` may be a mapping or an object with ``block_automated_browsers``,
    ``obfuscation_level`` (default 3) and ``ttl_ms`` (default 5 min).

    Returns ``{"id", "expires", "expected_vals", "vars", "block_automated_browsers", "blob"}``.
    With ``_return_client_eqs=True`` (debug hook, used by tests) the result also carries
    ``"_debug": {"client_eqs", "init_vals", "script", "final_script"}``.
    """
    block = _opt(opts, "block_automated_browsers", False) is True
    level = max(1, min(10, int(_opt(opts, "obfuscation_level", _OPT_DEFAULT_LEVEL))))
    ttl_ms = int(_opt(opts, "ttl_ms", DEFAULT_TTL_MS))

    id_ = _r_hex(32)
    vars_ = [_r_var(12) for _ in range(4)]

    init_vals = [_fast_rnd(10, 250) for _ in range(4)]
    vals = list(init_vals)

    correct_key = _fast_rnd(1000, 9000)
    bad_key = _fast_rnd(1000, 9000)
    while bad_key == correct_key:
        bad_key = _fast_rnd(1000, 9000)

    vals[0] = js_xor(vals[0], correct_key)

    fn_helper = _r_var()
    dom_helper = _r_var()
    helper_decls = _fill(_HELPER_DECLS, FN=fn_helper, DOM=dom_helper)

    v0 = vars_[0]
    client_eqs = f"{helper_decls}{v0} = {v0} ^ (navigator.userAgent ? {correct_key} : {bad_key});"

    for _ in range(20):
        op = _fast_rnd(0, 5)
        dest = _fast_rnd(0, 3)
        src1 = _fast_rnd(0, 3)
        src2 = _fast_rnd(0, 3)
        src3 = _fast_rnd(0, 3)
        vd = vars_[dest]
        vs1 = vars_[src1]
        vs2 = vars_[src2]
        vs3 = vars_[src3]

        if op == 0:
            client_eqs += f"{vd} = ~({vd} & {vs1});"
            vals[dest] = js_not(js_and(vals[dest], vals[src1]))
        elif op == 1:
            client_eqs += f"{vd} = {vd} ^ {vs1};"
            vals[dest] = js_xor(vals[dest], vals[src1])
        elif op == 2:
            client_eqs += f"{vd} = {vd} | {vs1};"
            vals[dest] = js_or(vals[dest], vals[src1])
        elif op == 3:
            client_eqs += f"{vd} = {vd} & {vs1};"
            vals[dest] = js_and(vals[dest], vals[src1])
        elif op == 4:
            client_eqs += f"{vd} = {fn_helper}({vs1}, {vs2}, {vd});"
            vals[dest] = js_or(js_xor(vals[src2], vals[src1]), js_xor(vals[dest], vals[src2]))
        else:
            client_eqs += f"{vd} = {dom_helper}({vs1}, {vs2}, {vs3});"
            vals[dest] = dom_sum_mock(vals[src1], vals[src2], vals[src3])

    salts = [_fast_rnd(100_000, 999_999) for _ in range(4)]
    for i in range(4):
        vi = vars_[i]
        client_eqs += f"{vi}=(({vi}^{salts[i]})&0x7FFFFFFF)%900000+100000;"
        vals[i] = (js_and(js_xor(vals[i], salts[i]), 0x7FFFFFFF) % 900_000) + 100_000

    script = build_client_script(
        id_=id_,
        vars_=vars_,
        init_vals=init_vals,
        client_eqs=client_eqs,
        block_automated_browsers=block,
    )
    final_script = apply_obfuscation(script, level)
    blob = build_blob(final_script)

    result: dict[str, Any] = {
        "id": id_,
        "expires": int(time.time() * 1000) + ttl_ms,
        "expected_vals": vals,
        "vars": vars_,
        "block_automated_browsers": block,
        "blob": blob,
    }
    if _return_client_eqs:
        result["_debug"] = {
            "client_eqs": client_eqs,
            "init_vals": init_vals,
            "script": script,
            "final_script": final_script,
        }
    return result
