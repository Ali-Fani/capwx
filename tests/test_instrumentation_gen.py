"""Tests for the instrumentation generator and obfuscation (M6).

Node-based tests carry the ``node`` marker and are excluded by default; run them with
``uv run pytest -m node tests/test_instrumentation_gen.py``.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import shutil
import subprocess
import zlib
from pathlib import Path

import pytest

from capwx.protocols.instrumentation import obfuscate
from capwx.protocols.instrumentation.generator import (
    PROBE_FONT_STACKS,
    dom_sum_mock,
    generate_instrumentation,
    hash_with,
)

VECTORS = json.loads((Path(__file__).parent / "vectors" / "vectors.json").read_text("utf-8"))

HEX32 = re.compile(r"^[0-9a-f]{32}$")
VAR_NAME = re.compile(r"^[a-z][a-z0-9]{3,11}$")


def _inflate(blob: str) -> str:
    return zlib.decompress(base64.b64decode(blob), -15).decode("utf-8")


@pytest.fixture
def reset_clamp_warning(monkeypatch):
    monkeypatch.setattr(obfuscate, "_clamp_warned", False)


# ---------------------------------------------------------------------------
# Bit-exact helpers (vectors from tests/vectors/vectors.json, generated with Node)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("seed", "text", "expected"), VECTORS["hashWith"])
def test_hash_with_matches_node_vectors(seed, text, expected):
    assert hash_with(seed)(text) == expected


@pytest.mark.parametrize(("x", "y", "z", "expected"), VECTORS["domSum"])
def test_dom_sum_mock_matches_node_vectors(x, y, z, expected):
    assert dom_sum_mock(x, y, z) == expected


def test_probe_font_stacks_count_is_17():
    # fontWidths.length in the verify step depends on this count.
    assert len(PROBE_FONT_STACKS) == 17


# ---------------------------------------------------------------------------
# Generation shape and value pipeline
# ---------------------------------------------------------------------------


def test_output_shape():
    out = generate_instrumentation({"obfuscation_level": 1})
    assert set(out) == {
        "id",
        "expires",
        "expected_vals",
        "vars",
        "block_automated_browsers",
        "blob",
    }
    assert HEX32.match(out["id"])
    assert len(out["vars"]) == 4
    assert all(VAR_NAME.match(v) for v in out["vars"])
    assert len(set(out["vars"])) == 4
    assert isinstance(out["expires"], int) and out["expires"] > 0
    assert isinstance(out["blob"], str)
    assert out["block_automated_browsers"] is False


def test_expected_vals_are_four_ints_in_salt_range():
    for _ in range(200):
        vals = generate_instrumentation({"obfuscation_level": 1})["expected_vals"]
        assert len(vals) == 4
        for v in vals:
            assert type(v) is int
            assert 100_000 <= v <= 999_999


def test_block_flag_is_carried_through():
    out = generate_instrumentation({"block_automated_browsers": True, "obfuscation_level": 1})
    assert out["block_automated_browsers"] is True
    # The blocked-browser wrapper is only emitted when the flag is on (the individual checks
    # are sampled at random, so they are not a reliable marker).
    assert "blocked: true" in _inflate(out["blob"])
    plain = generate_instrumentation({"obfuscation_level": 1})
    assert "blocked: true" not in _inflate(plain["blob"])


_CE_DECL_RE = re.compile(r"var (\w+)=\(function\(\)\{try\{\(0,eval\)\('1'\);(.*?)\}\)\(\);")


def _ce_name_and_decl(script):
    match = _CE_DECL_RE.search(script)
    assert match, "the CSP eval probe is missing"
    return match.group(1), match.group(0)


def test_script_detects_csp_blocked_eval_and_reports_it():
    script = _inflate(generate_instrumentation({"obfuscation_level": 1})["blob"])
    name, decl = _ce_name_and_decl(script)
    assert "instanceof EvalError" in decl
    assert re.search(rf"ts:Date\.now\(\),ce:{name}\}}", script)


def test_eval_dependent_env_checks_are_guarded_by_the_csp_flag():
    script = _inflate(generate_instrumentation({"obfuscation_level": 1})["blob"])
    name, _ = _ce_name_and_decl(script)
    # new Function, (0, eval)('this') and the eval-secret check: exactly these three are guarded
    assert len(re.findall(rf"if \(!{name}\) \{{", script)) == 3


@pytest.mark.parametrize("level", [1, 4])
def test_csp_flag_token_is_filled_everywhere(level):
    script = _inflate(generate_instrumentation({"obfuscation_level": level})["blob"])
    assert "%%" not in script


def test_ttl_sets_expiry():
    before = _now_ms()
    out = generate_instrumentation({"obfuscation_level": 1, "ttl_ms": 1000})
    after = _now_ms()
    assert before + 1000 <= out["expires"] <= after + 1000


def _now_ms() -> int:
    import time

    return int(time.time() * 1000)


def test_blob_is_raw_deflate_of_utf8_script_level_1():
    script = _inflate(generate_instrumentation({"obfuscation_level": 1})["blob"])
    assert script.startswith("(function(){window.onload=")


def test_blob_is_standard_base64():
    blob = generate_instrumentation({"obfuscation_level": 2})["blob"]
    assert re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", blob)
    base64.b64decode(blob, validate=True)


def test_level_4_uses_string_table():
    script = _inflate(generate_instrumentation({"obfuscation_level": 4})["blob"])
    assert re.match(r"^var _T[0-9a-f]{6}=\[", script)
    assert "(function(){window.onload=" in script


@pytest.mark.parametrize("level", range(1, 11))
def test_every_level_generates(level, reset_clamp_warning):
    out = generate_instrumentation({"obfuscation_level": level})
    assert _inflate(out["blob"])


def test_level_8_warns_once_per_process(reset_clamp_warning, caplog):
    with caplog.at_level(logging.WARNING, logger="capwx"):
        generate_instrumentation({"obfuscation_level": 8})
        generate_instrumentation({"obfuscation_level": 8})
        generate_instrumentation({"obfuscation_level": 10})
    warnings = [r for r in caplog.records if r.name == "capwx" and r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "clamping to 7" in warnings[0].getMessage()


def test_level_8_is_clamped_to_level_7_output(reset_clamp_warning):
    # Level 7 output has a string table; level 8 must produce the same shape.
    script = _inflate(generate_instrumentation({"obfuscation_level": 8})["blob"])
    assert script.startswith("var _T")


def test_level_1_to_3_produce_no_string_table():
    for level in (1, 2, 3):
        script = _inflate(generate_instrumentation({"obfuscation_level": level})["blob"])
        assert script.startswith("(function(){window.onload=")


def test_debug_hook_returns_client_eqs():
    out = generate_instrumentation({"obfuscation_level": 1}, _return_client_eqs=True)
    dbg = out["_debug"]
    assert "client_eqs" in dbg and dbg["client_eqs"].endswith(";")
    assert len(dbg["init_vals"]) == 4
    assert "_debug" not in generate_instrumentation({"obfuscation_level": 1})


# ---------------------------------------------------------------------------
# Obfuscation helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("quote", "body", "value"),
    [
        ('"', "abc", "abc"),
        ("'", "it\\'s", "it's"),
        ("'", 'say \\"hi\\"', 'say "hi"'),
        ('"', "tab\\tnew\\nline", "tab\tnew\nline"),
        ("'", 'a"b', 'a"b'),
        ('"', "\\u0041", "A"),
    ],
)
def test_decode_js_string(quote, body, value):
    assert obfuscate.decode_js_string(quote, body) == value


def test_custom_obfuscate_strings_round_trip_semantics():
    src = "var a='x';var b=\"y\";var c='x';"
    out = obfuscate.custom_obfuscate_strings(src)
    table = re.match(r"^var (_T[0-9a-f]{6})=(\[.*?\]);", out)
    assert table is not None
    values = json.loads(table.group(2))
    assert sorted(values) == ["x", "y"]  # deduplicated
    body = out[table.end() :]
    refs = re.findall(re.escape(table.group(1)) + r"\[(\d+)\]", body)
    assert len(refs) == 3
    assert [values[int(i)] for i in refs] == ["x", "y", "x"]


def test_custom_obfuscate_strings_no_literals_is_identity():
    src = "var a=1+2;"
    assert obfuscate.custom_obfuscate_strings(src) == src


def test_strip_whitespace_matches_upstream_regexes():
    src = "a;\n    b;\n\t\tc\n\n  d"
    assert obfuscate.strip_whitespace(src) == "a;\nb;\nc\nd"


def test_build_blob_round_trip():
    text = "(function(){ 'héllo' })();"
    assert _inflate(obfuscate.build_blob(text)) == text


# ---------------------------------------------------------------------------
# Node: client equations evaluate to expected_vals; full script parses
# ---------------------------------------------------------------------------

_NODE_EQS_HARNESS = r"""
const fs = require("fs");
class El {
  constructor(tag) { this.tagName = tag; this.parentNode = null; this.children = []; this.style = {}; this._text = ""; }
  get lastElementChild() { return this.children.length ? this.children[this.children.length - 1] : null; }
  appendChild(c) { if (c.parentNode) c.parentNode.removeChild(c); c.parentNode = this; this.children.push(c); return c; }
  removeChild(c) { const i = this.children.indexOf(c); if (i < 0) throw new Error("NotFoundError"); this.children.splice(i, 1); c.parentNode = null; return c; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(""); }
  set textContent(v) { for (const c of this.children) c.parentNode = null; this.children = []; this._text = String(v); }
  get innerText() {
    // Only the non-rendered case (inside display:none) is modelled, as the DOM helper relies on it.
    for (let n = this; n; n = n.parentNode) if (n.style && n.style.display === "none") return this.textContent;
    throw new Error("layout-based innerText is not modelled");
  }
  set innerText(v) { this.textContent = v; }
}
const cases = JSON.parse(fs.readFileSync(0, "utf8"));
const navigator = { userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36" };
const out = cases.map((c) => {
  const document = { body: new El("body"), createElement: (t) => new El(t) };
  const body = c.inits.map((v, i) => `var ${c.vars[i]}=${v};`).join("") + c.eqs + `return [${c.vars.join(",")}];`;
  return new Function("navigator", "document", body)(navigator, document);
});
process.stdout.write(JSON.stringify(out));
"""

_NODE_CE_HARNESS = r"""
const fs = require("fs");
const decl = JSON.parse(fs.readFileSync(0, "utf8"));
const run = (evalImpl, fnImpl) =>
  new Function("eval", "Function", "EvalError", decl.code + "return " + decl.name + ";")(
    evalImpl, fnImpl, EvalError);
const thrower = (e) => function () { throw e; };
process.stdout.write(JSON.stringify({
  normal: run(eval, Function),
  evalBlocked: run(thrower(new EvalError("blocked")), Function),
  functionBlocked: run(eval, thrower(new EvalError("blocked"))),
  otherError: run(thrower(new TypeError("x")), Function),
}));
"""

_NODE_PARSE_HARNESS = r"""
const fs = require("fs");
const scripts = JSON.parse(fs.readFileSync(0, "utf8"));
const out = scripts.map((s) => {
  try { new Function(s); return null; } catch (e) { return String(e); }
});
process.stdout.write(JSON.stringify(out));
"""


def _require_node() -> str:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    return node


@pytest.mark.node
def test_client_equations_match_expected_vals_in_node():
    node = _require_node()
    cases, expected = [], []
    for _ in range(50):
        out = generate_instrumentation({"obfuscation_level": 1}, _return_client_eqs=True)
        dbg = out["_debug"]
        cases.append(
            {
                "vars": out["vars"],
                "inits": dbg["init_vals"],
                "eqs": dbg["client_eqs"],
            }
        )
        expected.append(out["expected_vals"])
    proc = subprocess.run(
        [node, "-e", _NODE_EQS_HARNESS],
        input=json.dumps(cases),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == expected


@pytest.mark.node
@pytest.mark.parametrize("level", [1, 4])
def test_full_script_parses_in_node(level):
    node = _require_node()
    scripts = [
        _inflate(generate_instrumentation({"obfuscation_level": level})["blob"]) for _ in range(3)
    ]
    scripts.append(
        _inflate(
            generate_instrumentation(
                {"obfuscation_level": level, "block_automated_browsers": True}
            )["blob"]
        )
    )
    proc = subprocess.run(
        [node, "-e", _NODE_PARSE_HARNESS],
        input=json.dumps(scripts),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == [None] * len(scripts)


@pytest.mark.node
def test_csp_probe_is_true_only_for_eval_error():
    node = _require_node()
    script = _inflate(generate_instrumentation({"obfuscation_level": 1})["blob"])
    name, decl = _ce_name_and_decl(script)
    proc = subprocess.run(
        [node, "-e", _NODE_CE_HARNESS],
        input=json.dumps({"name": name, "code": decl}),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == {
        "normal": False,
        "evalBlocked": True,
        "functionBlocked": True,
        "otherError": False,
    }
