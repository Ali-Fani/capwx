# Upstream pins and sync procedure

capwx is a Python port of the Cap server protocol (format 2) and vendors some
upstream binary and browser assets. Every pinned upstream item is listed here.

## Pins

| Thing | Version / commit |
|---|---|
| `tiagozip/cap` repo | commit `29bbe6fbe284786cdb0d4489e5040aee6042b2a4` |
| `capjs-core` (npm) | `0.1.5`, files `core/src/{index,crypto,hashwx,instrumentation,detect,prng}.js` |
| `cap-widget` (npm) | `0.1.58` |
| `@cap.js/wasm` (npm, browser solver wasm) | `0.0.8` (Apache-2.0) |
| `pako` (widget's inflate fallback) | `2.1.0` |
| `tevador/hashwx` | commit `74b567a31276a4c5d7cb232a5b7639467f49f961`, LGPL-3.0 |
| server `hashwx.wasm` | from `core/vendor/hashwx.wasm`, 12 541 bytes, sha256 `b1a0dbb3ef444d3c7069e0a5e0a0273ffa4cf8fef62cbbe43761c02f7cd6aff5` |
| `wasmtime` (PyPI) | `>=49,<50` (49.0.0 verified) |

Vendored files:

- `src/capwx/_vendor/hashwx/hashwx.wasm`, `LICENSE`, `COMMIT`, `SHA256`
  (server wasm, copied from `core/vendor/` at the pinned commit)
- `src/capwx/contrib/django/static/capwx/` (browser assets, written by
  `scripts/vendor_assets.py`, with `VERSIONS.json` holding sha256 of each file)
- `third_party/hashwx/` (the unmodified HashWX source tree at the pinned commit, copied with
  `git archive`, with `LICENSE` and `README.capwx.md`). This is the LGPL-3.0 Corresponding Source
  offered in `NOTICE`. It is in the sdist and not in the wheel. capwx never builds or imports it.

`scripts/check_dist.py` checks that a built wheel and sdist contain these files, and that each
vendored file matches its recorded hash. It also checks that the sdist has `third_party/hashwx/LICENSE`
and that the wheel has no `third_party` path.

## HashWX wasm provenance

`src/capwx/_vendor/hashwx/hashwx.wasm` (and its byte-identical browser copy) is taken from Cap, which
pins only the HashWX commit (`core/vendor/hashwx-COMMIT.txt`). Cap does not document the build steps.

- The exports are the 11 functions in tevador's `CMakeLists.txt` Emscripten target, plus Emscripten
  runtime helpers. `hashwx_seed` and the rest are upstream code in `third_party/hashwx/src/hashwx.c`.
  No Cap shim source exists.
- The binary is stripped (no `producers`, `name` or `target_features` section), so the compiler
  version cannot be recovered from it.
- The build recipe is **unknown**: the emsdk version, optimisation level and exact invocation are not
  recorded. The likely recipe is tevador's CMake Emscripten target, which is not verified.
- Nothing has been compiled or run. A rebuild would not be byte-identical, so verify behaviour instead.
- The exact recipe could be requested from the Cap author. That is a suggestion only; nobody has been
  contacted. Details are in `third_party/hashwx/README.capwx.md`.

## Deviations from upstream

These are the places where capwx does not match upstream output. Each one is deliberate.

- **Browser sha256 salt length: 16 bytes, not upstream's 32.** The widget's sha256 solver
  (`cap_wasm_bg.wasm`) only matches messages under 56 bytes. The message is the salt, which is
  `2 x sha256_size` hex characters, followed by the decimal nonce. At about 27 bytes of salt and up, the
  solver hangs in the widget. Upstream's 32-byte salt hangs for this reason. The default is set in
  `CapConfig.sha256_size`, and the reason is in `config.py`.
- **Instrumentation obfuscation levels.** Upstream minifies levels 4 to 7 with esbuild and obfuscates
  levels 8 to 10 with `javascript-obfuscator`, when those packages are installed. Neither is available
  in Python. capwx builds levels 4 to 7 with a string table plus whitespace stripping, so the script
  differs from upstream's output at those levels. Levels 8 to 10 are clamped to 7, with a warning
  logged once. The server verifies the probe results in the same way at every level.
- **Stricter verification bounds.** Upstream accepts any HashWX difficulty and any sha256 target
  length on verify. capwx refuses a HashWX `d` above 1 000 000 000 and a sha256 target that is not 1 to 16
  hex digits. Both bounds match the mint-time limits in `CapConfig`, and valid challenges from upstream
  are unaffected.
- **Instrumentation under a CSP without `'unsafe-eval'`.** Upstream's three eval-based environment
  checks (`new Function`, `(0, eval)('this')` and the eval-secret check) throw `EvalError` there, so
  the probe never posts and the widget times out after 20 s. capwx's script first tests once whether
  eval is blocked (`EvalError` from `(0, eval)('1')` or `new Function`), skips those three checks when
  it is, and adds `ce: true` to the result (`ce: false` otherwise). The server rejects `ce: true` with
  `instr_csp_eval_blocked` unless `instrMeta.allowCspEvalBlocked` is set (`allow_csp_eval_blocked`);
  then it accepts with the risk flag `csp_eval_blocked`. The meta key is capwx-only: meta minted by
  `capjs-core` lacks it and stays strict. All other checks are unchanged.
- **Replacement wasm is not hash-checked.** `hashwx_wasm_path` loads the file as given. The vendored
  wasm is checked against `SHA256` at load, and only when no path is set.
- **Django stores.** `DjangoCacheStore` consumes a token with an atomic `cache.add` of a marker
  (upstream Standalone has no such store). It is single use wherever `add` is atomic.

## Findings from the browser tests

- The sha256 salt limit above was found while testing the real widget. Keep `sha256_size` at 16 unless
  you have tested a larger value in a browser. The `e2e` suite drives the real widget end to end.

## Sync procedure

1. Bump the pins above (commit, npm versions) in `scripts/vendor_assets.py`,
   `UPSTREAM.md` and `NOTICE`.
2. Re-run `uv run python scripts/vendor_assets.py`. It checks each npm tarball's
   sha512 against the registry's `dist.integrity` and writes `VERSIONS.json`.
3. Re-vendor the server wasm and verify it: size, sha256 and `SHA256` file. Re-copy
   `third_party/hashwx/` from the new HashWX commit with `git archive` (no `.git`, no edits), then
   update `third_party/hashwx/README.capwx.md`, the HashWX commit in `NOTICE`, and the pins above.
4. Diff `core/src/*.js` between the old and new commit, then port any changes
   into `src/capwx/` (protocols, instrumentation, detect).
5. Regenerate vectors:
   `CAP_CHECKOUT=/path/to/cap node scripts/gen_vectors.mjs`.
6. Run the node interop suite (`pytest -m node`) and the browser e2e suite
   (`pytest -m e2e`). Both must pass before release.
7. Run `uv build` and `uv run python scripts/check_dist.py dist`.
